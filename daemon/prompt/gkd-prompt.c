/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gkd-prompt.h"
#include "gkd-prompt-marshal.h"

#include "egg/egg-cleanup.h"
#include "egg/egg-dh.h"
#include "egg/egg-hex.h"
#include "egg/egg-secure-memory.h"
#include "egg/egg-spawn.h"

#include <gcrypt.h>

enum {
	RESPONDED,
	COMPLETED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _GkdPromptPrivate {
	GKeyFile *input;
	GKeyFile *output;
	gchar *executable;
	gboolean completed;
	gboolean failure;

	/* Transport crypto */
	gcry_mpi_t secret;
	gcry_mpi_t prime;
	guchar *key;
	gsize n_key;

	/* Information about child */
	GPid pid;

	/* Input and output */
	gchar *in_data;
	gsize in_offset;
	gsize in_length;
	GString *out_data;
	GString *err_data;
	guint io_tag;
};

G_DEFINE_TYPE (GkdPrompt, gkd_prompt, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
kill_process (GkdPrompt *self)
{
	if (self->pv->pid)
		kill (self->pv->pid, SIGTERM);
}

static void
mark_completed (GkdPrompt *self)
{
	g_assert (!self->pv->completed);
	self->pv->completed = TRUE;
	g_signal_emit (self, signals[COMPLETED], 0);
}

static gboolean
on_standard_input (int fd, gpointer user_data)
{
	GkdPrompt *self = GKD_PROMPT (self);
	gssize ret;

	g_return_val_if_fail (GKD_IS_PROMPT (self), FALSE);

	if (self->pv->in_offset >= self->pv->in_length)
		return FALSE;

	g_assert (self->pv->in_data);
	ret = egg_spawn_write_input (fd, self->pv->in_data + self->pv->in_offset,
	                             self->pv->in_length - self->pv->in_offset);

	if (ret <= 0) {
		g_warning ("couldn't write all input to prompt process");
		self->pv->failure = TRUE;
		return FALSE;
	}

	self->pv->in_offset += ret;
	return TRUE;
}

static gboolean
on_standard_output (int fd, gpointer user_data)
{
	GkdPrompt *self = GKD_PROMPT (self);
	gchar buffer[1024];
	gssize ret;

	g_return_val_if_fail (GKD_IS_PROMPT (self), FALSE);

	ret = egg_spawn_read_output (fd, buffer, sizeof (buffer));
	if (ret < 0) {
		g_warning ("couldn't read output data from prompt process");
		self->pv->failure = TRUE;
		return FALSE;
	}

	if (!self->pv->out_data)
		self->pv->out_data = g_string_new_len (buffer, ret);
	else
		g_string_append_len (self->pv->out_data, buffer, ret);

	return (ret > 0);
}

static gboolean
on_standard_error (int fd, gpointer user_data)
{
	GkdPrompt *self = GKD_PROMPT (self);
	gchar buffer[1024];
	gssize ret;
	gchar *ptr;

	g_return_val_if_fail (GKD_IS_PROMPT (self), FALSE);

	ret = egg_spawn_read_output (fd, buffer, sizeof (buffer));
	if (ret < 0) {
		g_warning ("couldn't read error data from prompt process");
		self->pv->failure = TRUE;
		return FALSE;
	}

	if (!self->pv->err_data)
		self->pv->err_data = g_string_new_len (buffer, ret);
	else
		g_string_append_len (self->pv->err_data, buffer, ret);

	/* Print all stderr lines as messages */
	while ((ptr = strchr (self->pv->err_data->str, '\n')) != NULL) {
		*ptr = '\0';
		g_message ("%s", self->pv->err_data->str);
		g_string_erase (self->pv->err_data, 0,
		                ptr - self->pv->err_data->str);
	}

	return ret > 0;
}

static void
on_io_completed (gpointer user_data)
{
	GkdPrompt *self = GKD_PROMPT (self);
	GError *error = NULL;

	g_return_if_fail (GKD_IS_PROMPT (self));

	g_assert (!self->pv->output);
	g_assert (self->pv->io_tag != 0);
	g_assert (!self->pv->completed);

	/* Should be the last call we receive */
	self->pv->io_tag = 0;

	/* Print out any remaining errors */
	if (self->pv->err_data && self->pv->err_data->len)
		g_message ("%s", self->pv->err_data->str);

	/* Parse the output data properly */
	if (!self->pv->failure) {
		self->pv->output = g_key_file_new ();
		if (!g_key_file_load_from_data (self->pv->output, self->pv->out_data->str,
						self->pv->out_data->len, G_KEY_FILE_NONE, &error)) {
			g_key_file_free (self->pv->output);
			g_warning ("couldn't parse output from prompt: %s",
				   error && error->message ? error->message : "");
			g_clear_error (&error);
			self->pv->failure = TRUE;
		} else {
			g_signal_emit (self, signals[RESPONDED], 0);
		}
	}
}

static void
on_child_exited (GPid pid, gint status, gpointer user_data)
{
	GkdPrompt *self = GKD_PROMPT (self);
	gint code;

	if (pid == self->pv->pid) {
		self->pv->pid = 0;
		if (!self->pv->failure) {
			if (WIFEXITED (status)) {
				code = WEXITSTATUS (status);
				if (code != 0) {
					g_warning ("prompt process exited with failure code: %d", code);
					self->pv->failure = TRUE;
				}
			} else if (WIFSIGNALED (status)) {
				code = WTERMSIG (status);
				g_warning ("prompt process was killed with signal: %d", code);
				self->pv->failure = TRUE;
			}
		}
	}

	g_spawn_close_pid (pid);
}

static gboolean
encode_input_mpi (GkdPrompt *self, const gchar *section,
                  const gchar *field, gcry_mpi_t mpi)
{
	gcry_error_t gcry;
	guchar *data;
	gsize n_data;

	g_assert (self->pv->input);

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_HEX, NULL, 0, &n_data, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	data = g_malloc0 (n_data + 1);

	/* Write into buffer */
	gcry = gcry_mpi_print (GCRYMPI_FMT_HEX, data, n_data, &n_data, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	g_key_file_set_value (self->pv->input, section, field, (gchar*)data);
	g_free (data);

	return TRUE;
}

static void
prepare_transport_crypto (GkdPrompt *self)
{
	gcry_mpi_t pub, base;

	g_assert (!self->pv->prime);
	g_assert (!self->pv->secret);

	/* Figure out our prime, base, public and secret bits */
	if (!egg_dh_default_params (&self->pv->prime, &base) ||
	    !egg_dh_gen_secret (self->pv->prime, base, &pub, &self->pv->secret))
		g_return_if_reached ();

	/* Send over the prime, base, and public bits */
	if (!encode_input_mpi (self, "transport", "prime", self->pv->prime) ||
	    !encode_input_mpi (self, "transport", "base", base) ||
	    !encode_input_mpi (self, "transport", "public", pub))
		g_return_if_reached ();

	gcry_mpi_release (base);
	gcry_mpi_release (pub);
}

static gboolean
decode_output_mpi (GkdPrompt *self, const gchar *section,
                   const gchar *field, gcry_mpi_t *mpi)
{
	gcry_error_t gcry;
	gchar *data;

	g_assert (self->pv->output);

	data = g_key_file_get_value (self->pv->output, section, field, NULL);
	if (!data)
		return FALSE;

	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_HEX, data, 0, NULL);
	g_free (data);

	return (gcry == 0);
}

static guchar*
decode_output_hex (GkdPrompt *self, const gchar *section,
                   const gchar *field, gsize *n_result)
{
	guchar *result;
	gchar *data;

	g_assert (self->pv->output);

	data = g_key_file_get_value (self->pv->output, section, field, NULL);
	if (!data)
		return NULL;

	result = egg_hex_decode (data, -1, n_result);
	g_free (data);
	return result;
}

static gboolean
receive_transport_crypto (GkdPrompt *self)
{
	gcry_mpi_t key, peer;
	gcry_error_t gcry;
	guchar *buffer;
	gsize n_buffer;
	gboolean ret;

	g_assert (self->pv->output);

	if (!decode_output_mpi (self, "transport", "public", &peer))
		return FALSE;

	ret = egg_dh_gen_key (peer, self->pv->secret, self->pv->prime, &key);
	gcry_mpi_release (peer);
	if (!ret)
		return FALSE;

	/* Write the key out to raw data */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n_buffer, peer);
	g_return_val_if_fail (gcry == 0, FALSE);
	buffer = egg_secure_alloc (n_buffer);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, n_buffer, &n_buffer, peer);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Allocate memory for hashed key */
	egg_secure_free (self->pv->key);
	g_assert (16 == gcry_md_get_algo_dlen (GCRY_MD_MD5));
	self->pv->key = egg_secure_alloc (16);
	self->pv->n_key = 16;

	/* Use that as the input to derive a key for 128-bit AES */
	gcry_md_hash_buffer (GCRY_MD_MD5, self->pv->key, buffer, n_buffer);

	egg_secure_free (buffer);
	return TRUE;
}

static gchar*
decrypt_transport_crypto (GkdPrompt *self, guchar *data, gsize n_data,
                          guchar *iv, gsize n_iv)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	gchar *result;
	gsize pos;

	g_assert (self->pv->key);
	g_assert (self->pv->n_key == 16);

	if (n_iv != 16) {
		g_warning ("prompt response has iv of wrong length");
		return NULL;
	}

	if (n_data % 16 != 0) {
		g_warning ("prompt response encrypted password of wrong length");
		return NULL;
	}

	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		return NULL;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, self->pv->key, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Allocate memory for the result */
	result = egg_secure_alloc (n_data);

	for (pos = 0; pos < n_data; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, result + pos, 16, data + pos, 16);
		g_return_val_if_fail (gcry == 0, NULL);
	}

	gcry_cipher_close (cih);

	if (!g_utf8_validate (result, n_data, NULL)) {
		egg_secure_free (result);
		return NULL;
	}

	return result;
}


static gboolean
prepare_input_data (GkdPrompt *self)
{
	GError *error = NULL;

	g_assert (self->pv->input);

	prepare_transport_crypto (self);

	self->pv->in_data = g_key_file_to_data (self->pv->input, &self->pv->in_length, &error);
	if (!self->pv->in_data) {
		g_warning ("couldn't encode data for prompt: %s",
		           error && error->message ? error->message : "");
		g_clear_error (&error);
		self->pv->failure = TRUE;
		mark_completed (self);
		return FALSE;
	}

	/* No further modifications to input are possible */
	g_key_file_free (self->pv->input);
	self->pv->input = NULL;

	return TRUE;
}

static void
display_async_prompt (GkdPrompt *self)
{
	EggSpawnCallbacks callbacks;
	GError *error = NULL;
	gchar **names, **envp;
	int i, n;

	char *argv[] = {
		self->pv->executable,
		NULL,
	};

	g_assert (!self->pv->pid);

	/* Fires completed event when fails */
	if (!prepare_input_data (self))
		return;

	/* Any environment we have */
	names = g_listenv ();
	for (n = 0; names && names[n]; ++n);
	envp = g_new (char*, n + 2);
	for (i = 0; i < n; i++)
		envp[i] = g_strdup_printf ("%s=%s", names[i], g_getenv (names[i]));
	envp[i++] = NULL;
	g_strfreev (names);

	memset (&callbacks, 0, sizeof (callbacks));
	callbacks.standard_input = on_standard_input;
	callbacks.standard_output = on_standard_output;
	callbacks.standard_error = on_standard_error;
	callbacks.completed = on_io_completed;
	callbacks.finalize_func = g_object_unref;

	self->pv->io_tag = egg_spawn_async_with_callbacks (NULL, argv, envp, G_SPAWN_DO_NOT_REAP_CHILD,
	                                                   &self->pv->pid, &callbacks, g_object_ref (self),
	                                                   NULL, &error);
	if (!self->pv->io_tag) {
		g_warning ("couldn't spawn prompt tool: %s",
		           error && error->message ? error->message : "");
		g_clear_error (&error);
		self->pv->pid = 0;
		self->pv->failure = TRUE;
		mark_completed (self);
		return;
	}

	g_child_watch_add_full (G_PRIORITY_DEFAULT, self->pv->pid, on_child_exited,
	                        g_object_ref (self), g_object_unref);
}

static void
clear_prompt_data (GkdPrompt *self)
{
	if (self->pv->input)
		g_key_file_free (self->pv->input);
	self->pv->input = NULL;

	if (self->pv->output)
		g_key_file_free (self->pv->output);
	self->pv->output = NULL;

	self->pv->failure = FALSE;

	g_free (self->pv->in_data);
	self->pv->in_data = NULL;
	self->pv->in_length = 0;
	self->pv->in_offset = 0;

	if (self->pv->out_data)
		g_string_free (self->pv->out_data, TRUE);
	self->pv->out_data = NULL;

	if (self->pv->err_data)
		g_string_free (self->pv->err_data, TRUE);
	self->pv->err_data = NULL;

	if (self->pv->io_tag)
		g_source_remove (self->pv->io_tag);
	self->pv->io_tag = 0;

	if (self->pv->prime)
		gcry_mpi_release (self->pv->prime);
	self->pv->prime = NULL;

	if (self->pv->secret)
		gcry_mpi_release (self->pv->secret);
	self->pv->secret = NULL;

	if (self->pv->key) {
		egg_secure_clear (self->pv->key, self->pv->n_key);
		egg_secure_free (self->pv->key);
		self->pv->key = NULL;
		self->pv->n_key = 0;
	}
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_prompt_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdPrompt *self = GKD_PROMPT (G_OBJECT_CLASS (gkd_prompt_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	if (!self->pv->executable)
		self->pv->executable = g_strdup (LIBEXECDIR "/gnome-keyring-ask");

	return G_OBJECT (self);
}

static void
gkd_prompt_init (GkdPrompt *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GKD_TYPE_PROMPT, GkdPromptPrivate);
	gkd_prompt_reset (self);
}

static void
gkd_prompt_dispose (GObject *obj)
{
	GkdPrompt *self = GKD_PROMPT (obj);

	kill_process (self);
	clear_prompt_data (self);

	G_OBJECT_CLASS (gkd_prompt_parent_class)->dispose (obj);
}

static void
gkd_prompt_finalize (GObject *obj)
{
	GkdPrompt *self = GKD_PROMPT (obj);

	g_assert (self->pv->pid == 0);
	g_assert (!self->pv->in_data);
	g_assert (!self->pv->out_data);
	g_assert (!self->pv->err_data);
	g_assert (!self->pv->io_tag);
	g_assert (!self->pv->prime);
	g_assert (!self->pv->secret);
	g_assert (!self->pv->key);

	g_free (self->pv->executable);
	self->pv->executable = NULL;

	G_OBJECT_CLASS (gkd_prompt_parent_class)->finalize (obj);
}

static void
gkd_prompt_class_init (GkdPromptClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_prompt_constructor;
	gobject_class->dispose = gkd_prompt_dispose;
	gobject_class->finalize = gkd_prompt_finalize;

	g_type_class_add_private (klass, sizeof (GkdPromptPrivate));

	signals[COMPLETED] = g_signal_new ("signal", GKD_TYPE_PROMPT,
	                                   G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkdPromptClass, completed),
	                                   NULL, NULL, g_cclosure_marshal_VOID__VOID,
	                                   G_TYPE_NONE, 0);

	signals[RESPONDED] = g_signal_new ("signal", GKD_TYPE_PROMPT,
	                                   G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkdPromptClass, responded),
	                                   g_signal_accumulator_true_handled, NULL, gkd_prompt_marshal_BOOLEAN__VOID,
	                                   G_TYPE_BOOLEAN, 0);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

void
gkd_prompt_set_title (GkdPrompt *self, const gchar *title)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_value (self->pv->input, "prompt", "title", title);
}

void
gkd_prompt_set_primary_text (GkdPrompt *self, const gchar *primary)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_value (self->pv->input, "prompt", "primary", primary);
}

void
gkd_prompt_set_secondary_text (GkdPrompt *self, const gchar *secondary)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_value (self->pv->input, "prompt", "secondary", secondary);
}

void
gkd_prompt_show_widget (GkdPrompt *self, const gchar *widget)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_boolean (self->pv->input, "visibility", widget, TRUE);
}

void
gkd_prompt_hide_widget (GkdPrompt *self, const gchar *widget)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_boolean (self->pv->input, "visibility", widget, FALSE);
}

void
gkd_prompt_select_widget (GkdPrompt *self, const gchar *widget)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	g_key_file_set_boolean (self->pv->input, "selected", widget, TRUE);
}

gboolean
gkd_prompt_has_response (GkdPrompt *self)
{
	g_return_val_if_fail (GKD_IS_PROMPT (self), FALSE);
	return self->pv->output ? TRUE : FALSE;
}

gint
gkd_prompt_get_response (GkdPrompt *self)
{
	gchar *response;
	guint ret;

	g_return_val_if_fail (GKD_IS_PROMPT (self), GKD_RESPONSE_FAILURE);
	if (!self->pv->failure)
		return GKD_RESPONSE_FAILURE;

	g_return_val_if_fail (self->pv->output, GKD_RESPONSE_FAILURE);

	response = g_key_file_get_value (self->pv->output, "prompt", "response", NULL);
	if (!response) {
		ret = GKD_RESPONSE_NONE;
	} else if (g_str_equal (response, "ok")) {
		ret = GKD_RESPONSE_OK;
	} else if (g_str_equal (response, "no")) {
		ret =  GKD_RESPONSE_NO;
	} else if (g_str_equal (response, "other")) {
		ret = GKD_RESPONSE_OTHER;
	} else {
		g_warning ("invalid response field received from prompt: %s", response);
		ret = GKD_RESPONSE_NONE;
	}

	g_free (response);
	return ret;
}

gchar*
gkd_prompt_get_password (GkdPrompt *self, const gchar *password_type)
{
	gboolean encrypted;
	gchar *result;
	guchar *data;
	gsize n_data;
	guchar *iv;
	gsize n_iv;

	g_return_val_if_fail (GKD_IS_PROMPT (self), NULL);
	g_return_val_if_fail (self->pv->output, NULL);

	if (!self->pv->failure)
		return NULL;

	g_assert (self->pv->output);

	if (!password_type)
		password_type = "password";

	encrypted = g_key_file_get_boolean (self->pv->output, password_type, "encrypted", NULL);
	if (!encrypted)
		return g_key_file_get_string (self->pv->output, password_type, "value", NULL);

	/* Parse the encryption params and figure out a key */
	if (!self->pv->key && !receive_transport_crypto (self))
		g_return_val_if_reached (NULL);

	/* Parse out an IV */
	iv = decode_output_hex (self, password_type, "iv", &n_iv);
	if (iv == NULL) {
		g_warning ("prompt response has encrypted password, but no iv set");
		return NULL;
	}

	/* Parse out the password */
	data = decode_output_hex (self, password_type, "value", &n_data);
	if (data == NULL) {
		g_warning ("prompt response missing encrypted password value");
		g_free (iv);
		return NULL;
	}

	result = decrypt_transport_crypto (self, data, n_data, iv, n_iv);
	g_free (data);
	g_free (iv);

	return result;
}

gboolean
gkd_prompt_is_widget_selected (GkdPrompt *self, const gchar *widget)
{
	g_return_val_if_fail (GKD_IS_PROMPT (self), FALSE);
	g_return_val_if_fail (self->pv->output, FALSE);

	if (!self->pv->failure)
		return FALSE;

	g_assert (self->pv->output);
	return g_key_file_get_boolean (self->pv->output, "selected", widget, NULL);
}

void
gkd_prompt_set_window_id (GkdPrompt *self, const gchar *window_id)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	if (!window_id)
		g_key_file_remove_key (self->pv->input, "prompt", "window-id", NULL);
	else
		g_key_file_set_value (self->pv->input, "prompt", "window-id", window_id);
}

void
gkd_prompt_set_warning (GkdPrompt *self, const gchar *warning)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->input);
	if (!warning)
		g_key_file_remove_key (self->pv->input, "prompt", "warning", NULL);
	else
		g_key_file_set_value (self->pv->input, "prompt", "warning", warning);
}

void
gkd_prompt_reset (GkdPrompt *self)
{
	g_return_if_fail (GKD_IS_PROMPT (self));
	g_return_if_fail (self->pv->completed);

	kill_process (self);
	self->pv->pid = 0;

	clear_prompt_data (self);
	self->pv->input = g_key_file_new ();
}

/* ----------------------------------------------------------------------------------
 * ATTENTION QUEUES
 */

/* Forward declaration */
static void next_attention_req (const gchar *);

typedef struct _Attention {
	gchar *window_id;
	GkdPromptAttentionFunc callback;
	GDestroyNotify destroy;
	gpointer user_data;
	gulong completed_tag;
	GkdPrompt *prompt;
} AttentionReq;

static GHashTable *attention_reqs = NULL;

static void
clear_attention_reqs (gpointer unused)
{
	g_assert (attention_reqs);
	g_hash_table_destroy (attention_reqs);
}

static AttentionReq*
alloc_attention_req (const gchar *window_id)
{
	AttentionReq *att;

	g_assert (window_id);

	att = g_slice_new0 (AttentionReq);
	att->window_id = g_strdup (window_id);
	return att;
}

static void
free_attention_req (gpointer data)
{
	AttentionReq *att = data;

	if (att) {
		g_free (att->window_id);
		if (att->destroy)
			(att->destroy) (att->user_data);
		if (att->prompt)
			g_object_unref (att->prompt);
		g_slice_free (AttentionReq, att);
	}
}

static void
free_attention_queue (gpointer data)
{
	GQueue *queue = data;
	AttentionReq *att;

	if (queue) {
		while (!g_queue_is_empty (queue)) {
			att = g_queue_pop_head (queue);
			free_attention_req (att);
		}
		g_queue_free (queue);
	}
}

static GQueue*
alloc_attention_queue (void)
{
	return g_queue_new ();
}

static void
done_attention_req (gpointer user_data, GClosure *unused)
{
	AttentionReq *att = user_data;
	g_assert (att);
	g_signal_handler_disconnect (att->prompt, att->completed_tag);
	next_attention_req (att->window_id);
}

static void
next_attention_req (const gchar *window_id)
{
	AttentionReq *att;
	GQueue *queue;

	g_assert (window_id);
	g_assert (attention_reqs);

	queue = g_hash_table_lookup (attention_reqs, window_id);
	g_return_if_fail (queue);

	/* Nothing more to process for this window */
	if (g_queue_is_empty (queue)) {
		g_hash_table_remove (attention_reqs, window_id);
		return;
	}

	/* Get the next one out */
	att = g_queue_pop_head (queue);
	g_assert (att);
	g_assert (att->window_id);
	g_assert (g_str_equal (att->window_id, window_id));
	g_assert (!att->prompt);
	g_assert (att->callback);

	/* Callback populates the prompt */
	att->prompt = (att->callback) (att->user_data);

	/* Don't show the prompt */
	if (att->prompt == NULL) {
		free_attention_req (att);
		next_attention_req (window_id);
		return;
	}

	att->completed_tag = g_signal_connect_data (att->prompt, "completed",
	                                            G_CALLBACK (done_attention_req), att,
	                                            (GClosureNotify)free_attention_req,
	                                            G_CONNECT_AFTER);

	/* Actually display the prompt, "completed" signal will fire */
	gkd_prompt_set_window_id (att->prompt, window_id);
	display_async_prompt (att->prompt);
}

static gboolean
service_attention_req (gpointer user_data)
{
	AttentionReq *att = user_data;
	gboolean now = FALSE;
	GQueue *queue;

	g_assert (att);

	if (!attention_reqs) {
		attention_reqs = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                        g_free, free_attention_queue);
		egg_cleanup_register (clear_attention_reqs, NULL);
	}

	queue = g_hash_table_lookup (attention_reqs, att->window_id);
	if (queue == NULL) {
		queue = alloc_attention_queue ();
		g_hash_table_insert (attention_reqs, g_strdup (att->window_id), queue);
		now = TRUE;
	}

	g_queue_push_tail (queue, att);
	if (now == TRUE)
		next_attention_req (att->window_id);

	/* Remove this timeout handler after one call */
	return FALSE;
}

void
gkd_prompt_request_attention_async (const gchar *window_id, GkdPromptAttentionFunc callback,
                                    gpointer user_data, GDestroyNotify destroy_notify)
{
	AttentionReq *att;

	g_return_if_fail (callback);

	if (!window_id)
		window_id = "";
	att = alloc_attention_req (window_id);
	att->callback = callback;
	att->user_data = user_data;
	att->destroy = destroy_notify;

	g_timeout_add (0, service_attention_req, att);
}

