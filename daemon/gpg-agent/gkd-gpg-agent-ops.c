/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#include "gkd-gpg-agent.h"
#include "gkd-gpg-agent-private.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "pkcs11/pkcs11i.h"

#include <ctype.h>
#include <string.h>

#define GKD_GPG_AGENT_PASS_AS_DATA    0x00000001
#define GKD_GPG_AGENT_REPEAT          0x00000002

#define COLLECTION    "session"
#define N_COLLECTION  7

/* ----------------------------------------------------------------------------------
 * PASSWORD STUFF
 */

static void
keyid_to_field_attribute (const gchar *keyid, GP11Attributes *attrs)
{
	GString *fields = g_string_sized_new (128);

	/* Remember that attribute names are sorted */

	g_string_append (fields, "keyid");
	g_string_append_c (fields, '\0');
	g_string_append (fields, keyid);
	g_string_append_c (fields, '\0');

	g_string_append (fields, "source");
	g_string_append_c (fields, '\0');
	g_string_append (fields, "gnome-keyring:gpg-agent");
	g_string_append_c (fields, '\0');

	gp11_attributes_add_data (attrs, CKA_G_FIELDS, fields->str, fields->len);
	g_string_free (fields, TRUE);
}

static gboolean
do_clear_password (GP11Session *session, const gchar *keyid)
{
	GP11Attributes *attrs;
	GList *objects, *l;
	GError *error = NULL;

	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                              GP11_INVALID);
	keyid_to_field_attribute (keyid, attrs);

	objects = gp11_session_find_objects_full (session, attrs, NULL, &error);
	gp11_attributes_unref (attrs);

	if (error) {
		g_warning ("couldn't search for gpg agent passwords to clear: %s",
		           egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	if (!objects)
		return TRUE;

	/* Delete first item */
	for (l = objects; l; l = g_list_next (l)) {
		gp11_object_set_session (l->data, session);
		if (gp11_object_destroy (l->data, &error)) {
			break; /* Only delete the first item */
		} else {
			g_warning ("couldn't clear gpg agent password: %s",
			           egg_error_message (error));
			g_clear_error (&error);
		}
	}

	gp11_list_unref_free (objects);
	return TRUE;
}

static gchar*
do_lookup_password (GP11Session *session, const gchar *keyid)
{
	GP11Attributes *attrs;
	GList *objects, *l;
	GError *error = NULL;
	gpointer data = NULL;
	gsize n_data;

	attrs = gp11_attributes_newv (CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                              GP11_INVALID);
	keyid_to_field_attribute (keyid, attrs);

	objects = gp11_session_find_objects_full (session, attrs, NULL, &error);
	gp11_attributes_unref (attrs);

	if (error) {
		g_warning ("couldn't search for gpg agent passwords to clear: %s",
		           egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	if (!objects)
		return NULL;

	/* Return first password */
	for (l = objects; l; l = g_list_next (l)) {
		gp11_object_set_session (l->data, session);
		data = gp11_object_get_data_full (l->data, CKA_VALUE, egg_secure_realloc, NULL, &n_data, &error);
		if (error) {
			g_warning ("couldn't lookup gpg agent password: %s", egg_error_message (error));
			g_clear_error (&error);
			data = NULL;
		} else {
			break;
		}
	}

	gp11_list_unref_free (objects);

	/* Data is null terminated */
	return data;
}

static gchar*
do_get_password (GP11Session *session, const gchar *keyid, const gchar *errmsg,
                 const gchar *prompt, const gchar *description, gboolean confirm)
{
	gchar *password;

	password = do_lookup_password (session, keyid);
	if (password != NULL)
		return password;

	/*
	 * Need the following to continue:
	 * - Ability to detect or use default keyring.
	 * - Ability to prompt to unlock keyring.
	 */
	g_assert (FALSE && "Not yet impelmented");
	return NULL;
}

/* ----------------------------------------------------------------------------------
 * PARSING and UTIL
 */

/* Is the argument a assuan null parameter? */
static gboolean
is_null_argument (gchar *arg)
{
	return (strcmp (arg, "X") == 0);
}

static const gchar HEX_CHARS[] = "0123456789ABCDEF";

/* Decode an assuan parameter */
static void
decode_assuan_arg (gchar *arg)
{
	gchar *t;
	gint len;

	for (len = strlen (arg); len > 0; arg++, len--) {
		switch (*arg) {
		/* + becomes a space */
		case '+':
			*arg = ' ';
			break;

		/* hex encoded as in URIs */
		case '%':
			*arg = '?';
			t = strchr (HEX_CHARS, arg[1]);
			if (t != NULL) {
				*arg = ((t - HEX_CHARS) & 0xf) << 4;
				t = strchr (HEX_CHARS, arg[2]);
				if (t != NULL)
					*arg |= (t - HEX_CHARS) & 0xf;
			}
			len -= 2;
			if (len < 1) /* last char, null terminate */
				arg[1] = 0;
			else /* collapse rest */
				memmove (arg + 1, arg + 3, len);
			break;
		};
	}
}

/* Parse an assuan argument that we recognize */
static guint32
parse_assuan_flag (gchar *flag)
{
	g_assert (flag);
	if (g_str_equal (flag, GPG_AGENT_FLAG_DATA))
		return GKD_GPG_AGENT_PASS_AS_DATA;
	else if (g_str_has_prefix (flag, GPG_AGENT_FLAG_REPEAT)) {
		gint count = 1;

		flag += strlen(GPG_AGENT_FLAG_REPEAT);
		if (*flag == '=') {
			count = atoi (++flag);
			if (!(count == 0 || count == 1))
				g_warning ("--repeat=%d treated as --repeat=1", count);
		}

		if (count)
			return GKD_GPG_AGENT_REPEAT;
	}
	return 0;
}

/* Split a line into each of it's arguments. This modifies line */
static void
split_arguments (gchar *line, guint32 *flags, ...)
{
	gchar **cur;
	gchar *flag;
	va_list ap;

	va_start (ap, flags);

	/* Initial white space */
	while (*line && isspace (*line))
		line++;

	/* The flags */
	if (flags) {
		*flags = 0;

		while (*line) {
			/* Options start with a double dash */
			if(!(line[0] == '-' && line[1] == '-'))
				break;
			line +=2;
			flag = line;

			/* All non-whitespace */
			while (*line && !isspace (*line))
				line++;

			/* Skip and null any whitespace */
			while (*line && isspace (*line)) {
				*line = 0;
				line++;
			}

			*flags |= parse_assuan_flag (flag);
		}
	}

	/* The arguments */
	while ((cur = va_arg (ap, gchar **)) != NULL) {
		if (*line) {
			*cur = line;

			/* All non-whitespace */
			while (*line && !isspace (*line))
				line++;

			/* Skip and null any whitespace */
			while (*line && isspace (*line)) {
				*line = 0;
				line++;
			}

			decode_assuan_arg (*cur);
		} else {
			*cur = NULL;
		}
	}

	va_end (ap);
}

static guint
x11_display_dot_offset (const gchar *d)
{
	const gchar *p;
	guint l = strlen (d);

	for (p = d + l; *p != '.'; --p) {
		if (p <= d)
			break;
		if (*p == ':')
			break;
	}
	if (*p == '.')
		l = p - d;

	return l;
}

/*
 * Displays are of the form: hostname:displaynumber.screennumber, where
 * hostname can be empty (to indicate a local connection).
 * Two displays are equivalent if their hostnames and displaynumbers match.
 */
static gboolean
x11_displays_eq (const gchar *d1, const gchar *d2)
{
	guint l1, l2;
	l1 = x11_display_dot_offset (d1);
	l2 = x11_display_dot_offset (d2);
	return (g_ascii_strncasecmp (d1, d2, l1 > l2 ? l1 : l2) == 0);
}

/* Does command have option? */
static gboolean
command_has_option (gchar *command, gchar *option)
{
	gboolean has_option = FALSE;

	if (!strcmp (command, GPG_AGENT_GETPASS)) {
		has_option = (!strcmp (option, GPG_AGENT_FLAG_DATA) ||
		              !strcmp (option, GPG_AGENT_FLAG_REPEAT));
	}
	/* else if (other commands) */

	return has_option;
}

/* Encode a password in hex */
static gchar*
encode_password (const gchar *pass)
{
	static const char HEXC[] = "0123456789abcdef";
	int j, c;
	gchar *enc, *k;

	/* Encode the password */
	c = sizeof (gchar *) * ((strlen (pass) * 2) + 1);
	k = enc = egg_secure_alloc (c);

	/* Simple hex encoding */
	while (*pass) {
		j = *(pass) >> 4 & 0xf;
		*(k++) = HEXC[j];

		j = *(pass++) & 0xf;
		*(k++) = HEXC[j];
	}

	return enc;
}

/* ----------------------------------------------------------------------------------
 * OPERATIONS
 */

gboolean
gkd_gpg_agent_ops_options (GkdGpgAgentCall *call, gchar *args)
{
	gchar *option;
	gsize len;

	split_arguments (args, NULL, &option, NULL);
	if (!option) {
		g_message ("received invalid option argument");
		return gkd_gpg_agent_send_reply (call, FALSE, "105 parameter error");
	}

	/*
	 * If the option is a display option we make sure it's
	 * the same as our display. Otherwise we don't answer.
	 */
	len = strlen (GPG_AGENT_OPT_DISPLAY);
	if (g_ascii_strncasecmp (option, GPG_AGENT_OPT_DISPLAY, len) == 0) {
		option += len;

		if (x11_displays_eq (option, g_getenv ("DISPLAY"))) {
			call->terminal_ok = TRUE;
		} else {
			g_message ("received request different display: %s", option);
			return gkd_gpg_agent_send_reply (call, FALSE, "105 parameter conflict");
		}
	}

	/* We don't do anything with the other options right now */
	return gkd_gpg_agent_send_reply (call, TRUE, NULL);
}

gboolean
gkd_gpg_agent_ops_getpass (GkdGpgAgentCall *call, gchar *args)
{
	gchar *id;
	gchar *errmsg;
	gchar *prompt;
	gchar *description;
	GP11Session *session;
	gchar *password;
	gchar *encoded;
	guint32 flags;

	/* We don't answer this unless it's from the right terminal */
	if (!call->terminal_ok) {
		g_message ("received passphrase request from wrong terminal");
		return gkd_gpg_agent_send_reply (call, FALSE, "113 Server Resource Problem");
	}

	split_arguments (args, &flags, &id, &errmsg, &prompt, &description, NULL);

	if (!id || !errmsg || !prompt || !description) {
		g_message ("received invalid passphrase request");
		return gkd_gpg_agent_send_reply (call, FALSE, "105 parameter error");
	}

	if (is_null_argument (id))
		id = NULL;
	if (is_null_argument (errmsg))
		errmsg = NULL;
	if (is_null_argument (prompt))
		prompt = NULL;
	if (is_null_argument (description))
		description = NULL;

	session = gkd_gpg_agent_checkout_main_session ();
	g_return_val_if_fail (session, FALSE);

	password = do_get_password (session, id, errmsg, prompt, description,
	                            flags & GKD_GPG_AGENT_REPEAT);

	gkd_gpg_agent_checkin_main_session (session);

	if (password == NULL) {
		gkd_gpg_agent_send_reply (call, FALSE, "111 cancelled");
	} else if (flags & GKD_GPG_AGENT_PASS_AS_DATA) {
		gkd_gpg_agent_send_data (call, password);
		gkd_gpg_agent_send_reply (call, TRUE, NULL);
	} else {
		encoded = encode_password (password);
		gkd_gpg_agent_send_reply (call, TRUE, encoded);
		egg_secure_strfree (encoded);
	}

	egg_secure_strfree (password);
	return TRUE;
}

gboolean
gkd_gpg_agent_ops_clrpass (GkdGpgAgentCall *call, gchar *args)
{
	GP11Session *session;
	gchar *id;

	/* We don't answer this unless it's from the right terminal */
	if (!call->terminal_ok) {
		g_message ("received passphrase request from wrong terminal");
		return gkd_gpg_agent_send_reply (call, FALSE, "113 Server Resource Problem");
	}

	split_arguments (args, NULL, &id, NULL);

	if (!id) {
		gkd_gpg_agent_send_reply (call, FALSE, "105 parameter error");
		g_warning ("received invalid clear pass request: %s", args);
	}

	session = gkd_gpg_agent_checkout_main_session ();
	g_return_val_if_fail (session, FALSE);

	/* Ignore the result, always return success */
	do_clear_password (session, id);

	gkd_gpg_agent_checkin_main_session (session);

	gkd_gpg_agent_send_reply (call, TRUE, NULL);
	return TRUE;
}

gboolean
gkd_gpg_agent_ops_getinfo (GkdGpgAgentCall *call, gchar *request)
{
	gchar *args;
	gboolean implemented = FALSE;

	args = strchr (request, ' ');
	if (args) {
		*args = 0;
		args++;
		while (isspace (*args))
			args++;
	}

	if (!strcmp (request, "cmd_has_option")) {
		gchar *command = args;
		gchar *option;

		if (!command || !*command)
			return gkd_gpg_agent_send_reply (call, FALSE, "105 parameter error");

		option = strchr(args, ' ');

		if (option) {
			*option = 0;
			option++;
			while (isspace (*option))
				option++;
		} else {
			return gkd_gpg_agent_send_reply (call, FALSE, "105 parameter error");
		}

		implemented = command_has_option (command, option);
	}

	/* else if (other info request) */

	if (implemented)
		return gkd_gpg_agent_send_reply (call, TRUE, NULL);
	else
		return gkd_gpg_agent_send_reply (call, FALSE, "100 not implemented");
}

gboolean
gkd_gpg_agent_ops_nop (GkdGpgAgentCall *call, gchar *args)
{
	return gkd_gpg_agent_send_reply (call, TRUE, NULL);
}

gboolean
gkd_gpg_agent_ops_bye (GkdGpgAgentCall *call, gchar *args)
{
	gkd_gpg_agent_send_reply (call, TRUE, "closing connection");
	return FALSE;
}

gboolean
gkd_gpg_agent_ops_reset (GkdGpgAgentCall *call, gchar *args)
{
	/* We keep no state :) */
	return gkd_gpg_agent_send_reply (call, TRUE, NULL);
}

gboolean
gkd_gpg_agent_ops_id (GkdGpgAgentCall *call, gchar *args)
{
	return gkd_gpg_agent_send_reply (call, TRUE, "gnome-keyring-daemon");
}
