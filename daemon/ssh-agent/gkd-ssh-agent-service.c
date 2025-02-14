/*
 * gnome-keyring
 *
 * Copyright (C) 2007 Stefan Walter
 * Copyright (C) 2018 Red Hat, Inc.
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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno
 */

#include "config.h"

#include <gio/gunixsocketaddress.h>
#include <glib/gstdio.h>

#include <gcr/gcr-base.h>

#include "gkd-ssh-agent-service.h"
#include "gkd-ssh-agent-preload.h"
#include "gkd-ssh-agent-private.h"
#include "gkd-ssh-agent-process.h"
#include "gkd-ssh-agent-util.h"
#include "daemon/login/gkd-login-interaction.h"

#include "egg/egg-buffer.h"
#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include <glib/gi18n-lib.h>

EGG_SECURE_DECLARE (ssh_agent);

typedef gboolean (*GkdSshAgentOperation) (GkdSshAgentService *agent, GSocketConnection *connection, EggBuffer *req, EggBuffer *resp, GCancellable *cancellable, GError **error);
static const GkdSshAgentOperation operations[GKD_SSH_OP_MAX];

enum {
	PROP_0,
	PROP_PATH,
	PROP_INTERACTION,
	PROP_PRELOAD
};

struct _GkdSshAgentService
{
	GObject object;
	gchar *path;
	GTlsInteraction *interaction;
	GkdSshAgentPreload *preload;
	GkdSshAgentProcess *process;
	GSocketAddress *address;
	GSocketListener *listener;
	GHashTable *keys;
	GMutex lock;
	GCancellable *cancellable;
};

G_DEFINE_TYPE (GkdSshAgentService, gkd_ssh_agent_service, G_TYPE_OBJECT);

static void
gkd_ssh_agent_service_init (GkdSshAgentService *self)
{
	self->keys = g_hash_table_new_full (g_bytes_hash, g_bytes_equal,
					    (GDestroyNotify)g_bytes_unref, NULL);
	g_mutex_init (&self->lock);
}

static void
gkd_ssh_agent_service_constructed (GObject *object)
{
	GkdSshAgentService *self = GKD_SSH_AGENT_SERVICE (object);
	gchar *path;

	path = g_strdup_printf ("%s/.ssh", self->path);
	self->process = gkd_ssh_agent_process_new (path);
	g_free (path);

	self->listener = G_SOCKET_LISTENER (g_threaded_socket_service_new (-1));
	self->cancellable = g_cancellable_new ();

	G_OBJECT_CLASS (gkd_ssh_agent_service_parent_class)->constructed (object);
}

static void
gkd_ssh_agent_service_set_property (GObject *object,
                            guint prop_id,
                            const GValue *value,
                            GParamSpec *pspec)
{
	GkdSshAgentService *self = GKD_SSH_AGENT_SERVICE (object);

	switch (prop_id) {
	case PROP_PATH:
		self->path = g_value_dup_string (value);
		break;
	case PROP_INTERACTION:
		self->interaction = g_value_dup_object (value);
		break;
	case PROP_PRELOAD:
		self->preload = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_ssh_agent_service_finalize (GObject *object)
{
	GkdSshAgentService *self = GKD_SSH_AGENT_SERVICE (object);

	g_free (self->path);
	g_object_unref (self->interaction);
	g_object_unref (self->preload);

	g_object_unref (self->process);
	g_object_unref (self->listener);
	g_clear_object (&self->address);
	g_mutex_clear (&self->lock);
	g_hash_table_unref (self->keys);
	g_object_unref (self->cancellable);

	G_OBJECT_CLASS (gkd_ssh_agent_service_parent_class)->finalize (object);
}

static void
gkd_ssh_agent_service_class_init (GkdSshAgentServiceClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->constructed = gkd_ssh_agent_service_constructed;
	gobject_class->set_property = gkd_ssh_agent_service_set_property;
	gobject_class->finalize = gkd_ssh_agent_service_finalize;
	g_object_class_install_property (gobject_class, PROP_PATH,
		 g_param_spec_string ("path", "Path", "Path",
				      "",
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_INTERACTION,
		 g_param_spec_object ("interaction", "Interaction", "Interaction",
				      G_TYPE_TLS_INTERACTION,
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_PRELOAD,
		 g_param_spec_object ("preload", "Preload", "Preload",
				      GKD_TYPE_SSH_AGENT_PRELOAD,
				      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
}

static gboolean
relay_request (GkdSshAgentService *self,
	       GSocketConnection *connection,
	       EggBuffer *req,
	       EggBuffer *resp,
	       GCancellable *cancellable,
	       GError **error)
{
	return _gkd_ssh_agent_call (connection, req, resp, cancellable, error);
}

static gboolean
handle_request (GkdSshAgentService *self,
		GSocketConnection *connection,
		EggBuffer *req,
		EggBuffer *resp,
		GCancellable *cancellable,
		GError **error)
{
	GkdSshAgentOperation func;
	guchar op;

	egg_buffer_reset (resp);
	egg_buffer_add_uint32 (resp, 0);

	/* Decode the operation; on failure, just pass through */
	if (egg_buffer_get_byte (req, 4, NULL, &op) &&
	    op < GKD_SSH_OP_MAX && operations[op] != NULL)
		func = operations[op];
	else
		func = relay_request;

	return func (self, connection, req, resp, cancellable, error);
}

static void
add_key (GkdSshAgentService *self,
	 GBytes *key)
{
	g_mutex_lock (&self->lock);
	g_hash_table_add (self->keys, g_bytes_ref (key));
	g_mutex_unlock (&self->lock);
}

static void
remove_key (GkdSshAgentService *self,
	    GBytes *key)
{
	g_mutex_lock (&self->lock);
	g_hash_table_remove (self->keys, key);
	g_mutex_unlock (&self->lock);
}

static void
clear_keys (GkdSshAgentService *self)
{
	g_mutex_lock (&self->lock);
	g_hash_table_remove_all (self->keys);
	g_mutex_unlock (&self->lock);
}

static void
ensure_key (GkdSshAgentService *self,
			  GBytes *key)
{
	GcrSshAskpass *askpass;
	GError *error = NULL;
	gint status;
	GkdSshAgentKeyInfo *info;
	gchar *unique;
	const gchar *label;
	GHashTable *fields;
	GTlsInteraction *interaction;
	gchar *standard_error;

	gchar *argv[] = {
		SSH_ADD,
		NULL,
		NULL
	};

	if (gkd_ssh_agent_service_lookup_key (self, key))
		return;

	info = gkd_ssh_agent_preload_lookup_by_public_key (self->preload, key);
	if (!info)
		return;

	argv[1] = info->filename;

	fields = g_hash_table_new (g_str_hash, g_str_equal);
	unique = g_strdup_printf ("ssh-store:%s", info->filename);
	g_hash_table_insert (fields, "unique", unique);

	label = info->comment[0] != '\0' ? info->comment : _("Unnamed");

	interaction = gkd_login_interaction_new (self->interaction, NULL, label, fields);
	askpass = gcr_ssh_askpass_new (interaction);
	g_object_unref (interaction);

	if (!g_spawn_sync (NULL, argv, NULL,
			   G_SPAWN_STDOUT_TO_DEV_NULL,
	                   gcr_ssh_askpass_child_setup, askpass,
	                   NULL, &standard_error, &status, &error)) {
		g_warning ("couldn't run %s: %s", argv[0], error->message);
		g_error_free (error);
	} else if (!g_spawn_check_wait_status (status, &error)) {
		g_message ("the %s command failed: %s", argv[0], error->message);
		g_printerr ("%s", _gkd_ssh_agent_canon_error (standard_error));
		g_free (standard_error);
	} else {
		add_key (self, key);
	}

	g_hash_table_unref (fields);
	g_free (unique);
	gkd_ssh_agent_key_info_free (info);
	g_object_unref (askpass);
}

static gboolean
on_run (GThreadedSocketService *service,
	GSocketConnection *connection,
	GObject *source_object,
	gpointer user_data)
{
	GkdSshAgentService *self = g_object_ref (GKD_SSH_AGENT_SERVICE (user_data));
	EggBuffer req;
	EggBuffer resp;
	GError *error;
	GSocketConnection *agent_connection;
	gboolean ret;

	egg_buffer_init_full (&req, 128, egg_secure_realloc);
	egg_buffer_init_full (&resp, 128, (EggBufferAllocator)g_realloc);

	error = NULL;
	agent_connection = gkd_ssh_agent_process_connect (self->process, self->cancellable, &error);
	if (!agent_connection) {
		g_warning ("couldn't connect to ssh-agent: %s", error->message);
		g_error_free (error);
		goto out;
	}

	while (TRUE) {
		/* Read in the request */
		error = NULL;
		if (!_gkd_ssh_agent_read_packet (connection, &req, self->cancellable, &error)) {
			if (error->code != G_IO_ERROR_CANCELLED &&
			    error->code != G_IO_ERROR_CONNECTION_CLOSED)
				g_message ("couldn't read from client: %s", error->message);
			g_error_free (error);
			break;
		}

		/* Handle the request */
		error = NULL;
		while (!(ret = handle_request (self, agent_connection, &req, &resp, self->cancellable, &error))) {
			if (gkd_ssh_agent_process_get_pid (self->process) != 0) {
				if (error->code != G_IO_ERROR_CANCELLED)
					g_message ("couldn't handle client request: %s", error->message);
				g_error_free (error);
				goto out;
			}

			/* Reconnect to the ssh-agent */
			g_clear_object (&agent_connection);
			g_clear_error (&error);
			agent_connection = gkd_ssh_agent_process_connect (self->process, self->cancellable, &error);
			if (!agent_connection) {
				if (error->code != G_IO_ERROR_CANCELLED)
					g_message ("couldn't connect to ssh-agent: %s", error->message);
				g_error_free (error);
				goto out;
			}
		}

		/* Write the reply back out */
		error = NULL;
		if (!_gkd_ssh_agent_write_packet (connection, &resp, self->cancellable, &error)) {
			if (error->code != G_IO_ERROR_CANCELLED)
				g_message ("couldn't write to client: %s", error->message);
			g_error_free (error);
			break;
		}
	}

 out:
	egg_buffer_uninit (&req);
	egg_buffer_uninit (&resp);

	g_object_unref (agent_connection);
	g_object_unref (self);

	return TRUE;
}

static void
on_closed (GkdSshAgentProcess *process,
	   gpointer user_data)
{
	GkdSshAgentService *self = GKD_SSH_AGENT_SERVICE (user_data);
	clear_keys (self);
}

gboolean
gkd_ssh_agent_service_start (GkdSshAgentService *self)
{
	gchar *path;
	GError *error;

	path = g_strdup_printf ("%s/ssh", self->path);
	g_unlink (path);
	self->address = g_unix_socket_address_new (path);
	g_free (path);

	error = NULL;
	if (!g_socket_listener_add_address (self->listener,
					    self->address,
					    G_SOCKET_TYPE_STREAM,
					    G_SOCKET_PROTOCOL_DEFAULT,
					    NULL,
					    NULL,
					    &error)) {
		g_warning ("couldn't listen on %s: %s",
			   g_unix_socket_address_get_path (G_UNIX_SOCKET_ADDRESS (self->address)),
			   error->message);
		g_error_free (error);
		return FALSE;
	}

	g_signal_connect (self->listener, "run", G_CALLBACK (on_run), self);
	g_signal_connect (self->process, "closed", G_CALLBACK (on_closed), self);

	g_setenv ("SSH_AUTH_SOCK", g_unix_socket_address_get_path (G_UNIX_SOCKET_ADDRESS (self->address)), TRUE);

	g_socket_service_start (G_SOCKET_SERVICE (self->listener));

	return TRUE;
}

void
gkd_ssh_agent_service_stop (GkdSshAgentService *self)
{
	if (self->address)
		g_unlink (g_unix_socket_address_get_path (G_UNIX_SOCKET_ADDRESS (self->address)));

	g_cancellable_cancel (self->cancellable);
	g_socket_service_stop (G_SOCKET_SERVICE (self->listener));
}

GkdSshAgentService *
gkd_ssh_agent_service_new (const gchar *path,
		   GTlsInteraction *interaction,
		   GkdSshAgentPreload *preload)
{
	g_return_val_if_fail (path, NULL);
	g_return_val_if_fail (interaction, NULL);
	g_return_val_if_fail (preload, NULL);

	return g_object_new (GKD_TYPE_SSH_AGENT_SERVICE,
			     "path", path,
			     "interaction", interaction,
			     "preload", preload,
			     NULL);
}

GkdSshAgentPreload *
gkd_ssh_agent_service_get_preload (GkdSshAgentService *self)
{
	return self->preload;
}

GkdSshAgentProcess *
gkd_ssh_agent_service_get_process (GkdSshAgentService *self)
{
	return self->process;
}

gboolean
gkd_ssh_agent_service_lookup_key (GkdSshAgentService *self,
			  GBytes *key)
{
	gboolean ret;
	g_mutex_lock (&self->lock);
	ret = g_hash_table_contains (self->keys, key);
	g_mutex_unlock (&self->lock);
	return ret;
}

/* ---------------------------------------------------------------------------- */

static gboolean
op_add_identity (GkdSshAgentService *self,
		 GSocketConnection *connection,
		 EggBuffer *req,
		 EggBuffer *resp,
		 GCancellable *cancellable,
		 GError **error)
{
	const guchar *blob;
	gsize offset = 5;
	gsize length;
	GBytes *key = NULL;
	gboolean ret;

	/* If parsing the request fails, just pass through */
	ret = egg_buffer_get_byte_array (req, offset, &offset, &blob, &length);
	if (ret)
		key = g_bytes_new (blob, length);
	else
		g_message ("got unparseable add identity request for ssh-agent");

	ret = relay_request (self, connection, req, resp, cancellable, error);
	if (key) {
		if (ret)
			add_key (self, key);
		g_bytes_unref (key);
	}

	return ret;
}

static GHashTable *
parse_identities_answer (EggBuffer *resp)
{
	GHashTable *answer;
	const guchar *blob;
	gchar *comment;
	gsize length;
	gsize offset = 4;
	guint32 count;
	guchar op;
	guint32 i;

	if (!egg_buffer_get_byte (resp, offset, &offset, &op) ||
	    op != GKD_SSH_RES_IDENTITIES_ANSWER ||
	    !egg_buffer_get_uint32 (resp, offset, &offset, &count)) {
		g_message ("got unexpected response back from ssh-agent when requesting identities");
		return NULL;
	}

	answer = g_hash_table_new_full (g_bytes_hash, g_bytes_equal, (GDestroyNotify)g_bytes_unref, g_free);

	for (i = 0; i < count; i++) {
		if (!egg_buffer_get_byte_array (resp, offset, &offset, &blob, &length) ||
		    !egg_buffer_get_string (resp, offset, &offset, &comment, g_realloc)) {
			g_message ("got unparseable response back from ssh-agent when requesting identities");
			g_hash_table_unref (answer);
			return NULL;
		}
		g_hash_table_insert (answer, g_bytes_new (blob, length), comment);
	}

	return answer;
}


static gboolean
op_request_identities (GkdSshAgentService *self,
		       GSocketConnection *connection,
		       EggBuffer *req,
		       EggBuffer *resp,
		       GCancellable *cancellable,
		       GError **error)
{
	GHashTable *answer;
	GHashTableIter iter;
	gsize length;
	guint32 added;
	GBytes *key;
	GList *keys;
	GList *l;
	GkdSshAgentPreload *preload;

	if (!relay_request (self, connection, req, resp, cancellable, error))
		return FALSE;

	/* Parse all the keys, and if it fails, just fall through */
	answer = parse_identities_answer (resp);
	if (!answer)
		return TRUE;

	g_hash_table_iter_init (&iter, answer);
	while (g_hash_table_iter_next (&iter, (gpointer *)&key, NULL))
		add_key (self, key);

	added = 0;

	/* Add any preloaded keys not already in answer */
	preload = gkd_ssh_agent_service_get_preload (self);
	keys = gkd_ssh_agent_preload_get_keys (preload);
	for (l = keys; l != NULL; l = g_list_next (l)) {
		GkdSshAgentKeyInfo *info = l->data;
		if (!g_hash_table_contains (answer, info->public_key)) {
			const guchar *blob = g_bytes_get_data (info->public_key, &length);
			egg_buffer_add_byte_array (resp, blob, length);
			egg_buffer_add_string (resp, info->comment);
			added++;
		}
	}

	g_list_free_full (keys, (GDestroyNotify)gkd_ssh_agent_key_info_free);

	/* Set the correct amount of keys including the ones we added */
	egg_buffer_set_uint32 (resp, 5, added + g_hash_table_size (answer));
	g_hash_table_unref (answer);

	/* Set the correct total size of the payload */
	egg_buffer_set_uint32 (resp, 0, resp->len - 4);

	return TRUE;
}

static gboolean
op_sign_request (GkdSshAgentService *self,
		 GSocketConnection *connection,
		 EggBuffer *req,
		 EggBuffer *resp,
		 GCancellable *cancellable,
		 GError **error)
{
	const guchar *blob;
	gsize length;
	gsize offset = 5;
	GBytes *key;

	/* If parsing the request fails, just pass through */
	if (egg_buffer_get_byte_array (req, offset, &offset, &blob, &length)) {
		key = g_bytes_new (blob, length);
		ensure_key (self, key);
		g_bytes_unref (key);
	} else {
		g_message ("got unparseable sign request for ssh-agent");
	}

	return relay_request (self, connection, req, resp, cancellable, error);
}

static gboolean
op_remove_identity (GkdSshAgentService *self,
		    GSocketConnection *connection,
		    EggBuffer *req,
		    EggBuffer *resp,
		    GCancellable *cancellable,
		    GError **error)
{
	const guchar *blob;
	gsize length;
	gsize offset = 5;
	GBytes *key = NULL;
	gboolean ret;

	/* If parsing the request fails, just pass through */
	ret = egg_buffer_get_byte_array (req, offset, &offset, &blob, &length);
	if (ret)
		key = g_bytes_new (blob, length);
	else
		g_message ("got unparseable remove request for ssh-agent");

	/* Call out ssh-agent anyway to make sure that the key is removed */
	ret = relay_request (self, connection, req, resp, cancellable, error);
	if (key) {
		if (ret)
			remove_key (self, key);
		g_bytes_unref (key);
	}
	return ret;
}

static gboolean
op_remove_all_identities (GkdSshAgentService *self,
			  GSocketConnection *connection,
			  EggBuffer *req,
			  EggBuffer *resp,
			  GCancellable *cancellable,
			  GError **error)
{
	gboolean ret;

	ret = relay_request (self, connection, req, resp, cancellable, error);
	if (ret)
		clear_keys (self);

	return ret;
}

static const GkdSshAgentOperation operations[GKD_SSH_OP_MAX] = {
	NULL,                                 /* 0 */
	NULL,                                 /* GKR_SSH_OP_REQUEST_RSA_IDENTITIES */
	NULL,                                 /* 2 */
	NULL,                                 /* GKR_SSH_OP_RSA_CHALLENGE */
	NULL,                                 /* 4 */
	NULL,                                 /* 5 */
	NULL,                                 /* 6 */
	NULL,                                 /* GKR_SSH_OP_ADD_RSA_IDENTITY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_RSA_IDENTITY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_ALL_RSA_IDENTITIES */
	NULL,                                 /* 10 */
	op_request_identities,                /* GKR_SSH_OP_REQUEST_IDENTITIES */
	NULL,                                 /* 12 */
	op_sign_request,                      /* GKR_SSH_OP_SIGN_REQUEST */
	NULL,                                 /* 14 */
	NULL,                                 /* 15 */
	NULL,                                 /* 16 */
	op_add_identity,                      /* GKR_SSH_OP_ADD_IDENTITY */
	op_remove_identity,                   /* GKR_SSH_OP_REMOVE_IDENTITY */
	op_remove_all_identities,             /* GKR_SSH_OP_REMOVE_ALL_IDENTITIES */
	NULL,                                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY */
	NULL,                                 /* GKR_SSH_OP_REMOVE_SMARTCARD_KEY */
	NULL,                                 /* GKR_SSH_OP_LOCK */
	NULL,                                 /* GKR_SSH_OP_UNLOCK */
	NULL,                                 /* GKR_SSH_OP_ADD_RSA_ID_CONSTRAINED */
	op_add_identity,                      /* GKR_SSH_OP_ADD_ID_CONSTRAINED */
	NULL,                                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED */
};
