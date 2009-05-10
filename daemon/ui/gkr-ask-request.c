/*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ask-request.c - represents a prompt for the user

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-ask-request.h"
#include "gkr-ask-marshal.h"
#include "gkr-ask-daemon.h"

#include "daemon/util/gkr-daemon-async.h"

#include "egg/egg-secure-memory.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include "util/gkr-location.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <glib.h>

#include <gcrypt.h>

#define DEBUG_COMMUNICATION 0

/* -----------------------------------------------------------------------------
 * DECLARATIONS 
 */

extern char **environ;

enum {
	CHECK_REQUEST,
	COMPLETED,
	LAST_SIGNAL
};

struct _GkrAskRequestPrivate;
typedef struct _GkrAskRequestPrivate GkrAskRequestPrivate;

struct _GkrAskRequestPrivate {
	GObject* object;
	GQuark location;
	
	gchar *title;
	gchar *primary;
	gchar *secondary;
	gchar *checktext;
	gboolean location_selector;
	
	gboolean completed;
	guint flags;
	
	gint ask_pid;
	gint in_fd;
	gint out_fd;
	EggBuffer buffer;
};

#define GKR_ASK_REQUEST_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_ASK_REQUEST, GkrAskRequestPrivate))

G_DEFINE_TYPE (GkrAskRequest, gkr_ask_request, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 }; 

/* -----------------------------------------------------------------------------
 * OBJECT MARKUP
 */
 
typedef struct _ObjectMarkupCtx {
	GString *res;
	GObject *object;
} ObjectMarkupCtx;
 
static void
insert_object_property (GString *res, GObject *object, const gchar *property)
{
	GParamSpec *spec;
	GValue value;
	GValue svalue;
	gchar *str;

	g_return_if_fail (property && property[0]);

	memset (&value, 0, sizeof (value));
	memset (&svalue, 0, sizeof (value));
    
	spec = g_object_class_find_property (G_OBJECT_GET_CLASS (object), property);
	if (!spec) 
		return;

	g_value_init (&value, spec->value_type);
	g_object_get_property (object, property, &value);
	g_value_init (&svalue, G_TYPE_STRING);
	
	if (g_value_transform (&value, &svalue)) {
		str = g_markup_escape_text (g_value_get_string (&svalue), -1);
		g_string_append (res, str);
		g_free (str);
        }
        
        g_value_unset (&svalue);
        g_value_unset (&value);
}

static void
format_start_element (GMarkupParseContext *ctx, const gchar *element_name,
                      const gchar **attribute_names, const gchar **attribute_values,
                      gpointer user_data, GError **error)
{
	ObjectMarkupCtx *omc = (ObjectMarkupCtx*)user_data;
	gchar *t;
    
	if (strcmp (element_name, "outer") == 0) 
		return;

	if (strcmp (element_name, "object") == 0) {
        
		const gchar *property = NULL;
        
		for (; *attribute_names && *attribute_values; attribute_names++, attribute_values++) {
			if (strcmp (*attribute_names, "prop") == 0)
				property = *attribute_values;
		}
        
		if (!property)
			g_warning ("key text <object> element requires the following attributes\n"
			           "     <object prop=\"xxxxx\"/>");
		else 
			insert_object_property (omc->res, omc->object, property);
        
		return;
	}

	/* Just pass through any other elements */
	g_string_append_printf (omc->res, "<%s", element_name);
	for (; *attribute_names && *attribute_values; attribute_names++, attribute_values++) {
		t = g_markup_printf_escaped ("%s", *attribute_values);
		g_string_append_printf (omc->res, " %s=\"%s\"", *attribute_names, t);
		g_free (t);
	}
	g_string_append (omc->res, ">");
}

static void 
format_end_element (GMarkupParseContext *ctx, const gchar *element_name, 
                    gpointer user_data, GError **error)
{
	ObjectMarkupCtx *omc = (ObjectMarkupCtx*)user_data;

	if (strcmp (element_name, "outer") == 0 || 
	    strcmp (element_name, "object") == 0)
		return;
    
	/* Just pass through any other elements */;
	g_string_append_printf (omc->res, "</%s>", element_name);
}

static void 
format_text (GMarkupParseContext *ctx, const gchar *text, gsize text_len,
             gpointer user_data, GError **error)
{
	ObjectMarkupCtx *omc = (ObjectMarkupCtx*)user_data;
	g_string_append_len (omc->res, text, text_len);
}

static gchar*
format_object_markup (GObject *object, const gchar *str1, const gchar *str2)
{
	ObjectMarkupCtx omc;
	GError *err = NULL;
	GMarkupParseContext *ctx;
	GMarkupParser parser;
	gboolean ret;
    
	memset (&parser, 0, sizeof (parser));
	parser.start_element = format_start_element;
	parser.end_element = format_end_element;
	parser.text = format_text;
	parser.passthrough = format_text;
    
	omc.res = g_string_new (NULL);
	omc.object = object;
    
	/* We need an outer tag in order to parse */
	ctx = g_markup_parse_context_new (&parser, 0, &omc, NULL);
	ret = g_markup_parse_context_parse (ctx, "<outer>", strlen ("<outer>"), &err) && 
	      (!str1 || g_markup_parse_context_parse (ctx, str1, strlen (str1), &err)) && 
	      (!str2 || g_markup_parse_context_parse (ctx, str2, strlen (str2), &err)) && 
	      g_markup_parse_context_parse (ctx, "</outer>", strlen ("</outer>"), &err); 

	g_markup_parse_context_free (ctx);

	if (!ret) {
		g_warning ("couldn't parse markup: %s%s: %s", str1 ? str1 : "",
		           str2 ? str2 : "", err && err->message ? err->message : "");
		g_string_free (omc.res, TRUE);
		return NULL;
	}
	
	return g_string_free (omc.res, FALSE);
}

/* -----------------------------------------------------------------------------
 * HELPERS 
 */

static void 
mark_completed (GkrAskRequest *ask, GkrAskResponse resp)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	if (!pv->completed) {
		if (resp)
			ask->response = resp;
		pv->completed = TRUE;
	}
}

static void
kill_ask_process (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	if (pv->ask_pid != 0) {
		kill (pv->ask_pid, SIGKILL);
		pv->ask_pid = 0;
	}
}

static void 
kill_ask_if_active (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	if (pv->ask_pid) {
		g_assert (!pv->completed);
		kill_ask_process (ask);
		g_assert (pv->ask_pid == 0);
	}
}

static void
finish_ask_io (GkrAskRequest *ask, gboolean success)
{
	GkrAskRequestPrivate *pv;
	gchar *line, *next, *value;
	GError *error = NULL;
	GKeyFile *key_file;
	int i;

	pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	pv->ask_pid = 0;

	/* Cleanup for response processing */
	egg_secure_strfree (ask->typed_password);
	ask->typed_password = NULL;
	egg_secure_strfree (ask->original_password);
	ask->original_password = NULL;
	
	/* A failed request */
	if (!success) {
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
		return;
	}
	
	/* 
	 * Parse each of the lines. Try to keep memory allocations
	 * to a minimum, for security reasons.
	 */
	for (i = 0, line = (gchar*)pv->buffer.buf; line && i < 2; ++i) {
		
		/* Break out the line */
		next = strchr (line, '\n');
		if (next) {
			*next = 0;
			++next;
		}
		
		/* First line is the password */
		if (i == 0)
			ask->typed_password = egg_secure_strdup (line);
		
		/* Second line is the original password (if any)*/
		else if (i == 1)
			ask->original_password = egg_secure_strdup (line);
			
		line = next;
	}
	
	if (!line) {
		g_warning ("missing dialog response from ask tool");
		if (!g_getenv ("DISPLAY"))
			g_warning ("the gnome-keyring-daemon process may not have been "
			           "initialized properly, as its environment is missing "
			           "the 'DISPLAY' variable.");
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
		return;
	}
	
	/* The remainder is a GKeyFile */
	key_file = g_key_file_new ();
	if (!g_key_file_load_from_data (key_file, line, strlen (line), G_KEY_FILE_NONE, &error)) {
		g_warning ("couldn't parse dialog response from ask tool: %s", error->message);
		g_error_free (error);
		g_key_file_free (key_file);
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
		return;
	}
	
	/* Pull out some values */
	ask->checked = g_key_file_get_boolean (key_file, "check", "check-active", NULL);
	ask->response = g_key_file_get_integer (key_file, "general", "response", NULL);
	value = g_key_file_get_value (key_file, "location", "location-selected", NULL);
	if (value)
		ask->location_selected = gkr_location_from_string (value);
	g_free (value);
	g_key_file_free (key_file);
		
	/* An invalid result from the ask tool */
	if (!ask->response) {
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
		return;
	}
	
	/* Ref around these callbacks */
	g_object_ref (ask);
	
	/* Check it and see if it really is completed */
	gkr_ask_request_check (ask);
	
	/* And ask again if not finished */
	if (!pv->completed)
		gkr_ask_request_prompt (ask);
		
	/* Ref from eaclier up */
	g_object_unref (ask);
}

static void
close_fd (gpointer data)
{
	int *fd = (int*)data;
	g_assert (fd);
	close (*fd);
	*fd = -1;
}

static gchar*
prep_dialog_data (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	GkrLocationManager *locmgr;
	gboolean need_locations = FALSE;
	GKeyFile *key_file;
	gchar *value, *data;
	GArray *array;
	GSList *locations, *l;
	GParamSpec *spec;
	GQuark loc, loc_volume;
	const gchar *t;
	
	key_file = g_key_file_new ();
	
	value = format_object_markup (pv->object, pv->title, NULL);
	g_key_file_set_value (key_file, "general", "title", value);
	g_free (value);
	
	value = format_object_markup (pv->object, pv->primary, NULL);
	g_key_file_set_value (key_file, "general", "primary", value);
	g_free (value);
	
	value = format_object_markup (pv->object, pv->secondary, NULL);
	g_key_file_set_value (key_file, "general", "secondary", value);
	g_free (value);
	
	g_key_file_set_integer (key_file, "general", "flags", pv->flags);

	if (pv->checktext) {
		g_key_file_set_boolean (key_file, "check", "check-enable", TRUE);
		g_key_file_set_value (key_file, "check", "check-text", pv->checktext);
	}
	
	/* Display the location drop down selector */	
	if (pv->location_selector) {
		g_key_file_set_boolean (key_file, "location", "location-selector", TRUE);
		need_locations = TRUE;
	}

	if (!pv->location && pv->object) {
		spec = g_object_class_find_property (G_OBJECT_GET_CLASS (pv->object), "location");
		if (spec)
			g_object_get (pv->object, "location", &pv->location, NULL);
	}

	/* See if we should send a location to display */
	loc_volume = 0;
	if (pv->location) {
		loc_volume = gkr_location_get_volume (pv->location);
		
		/* Suppress local stuff unless displying the selector */ 
		if (!need_locations && loc_volume) {
			if(loc_volume == GKR_LOCATION_VOLUME_LOCAL)
				loc_volume = 0;
			else if(loc_volume == GKR_LOCATION_VOLUME_HOME)
				loc_volume = 0;
		}
			
		if (loc_volume) {
			g_key_file_set_value (key_file, "location", "location", 
			                      gkr_location_to_string (loc_volume));
			need_locations = TRUE;
		}
	}
	
	if (need_locations) {
		locmgr = gkr_location_manager_get ();
		array = g_array_new (TRUE, TRUE, sizeof (gchar*));
		locations = gkr_location_manager_get_volumes (locmgr);
			
		/* Send all the locations and all the display names */
		for (l = locations; l; l = g_slist_next (l)) {
			loc = GPOINTER_TO_UINT (l->data);
		 	t = gkr_location_to_string (loc); 
			g_array_append_val (array, t);
			
			/* Did we see the location of the item? */
			if (loc == loc_volume)
				loc_volume = 0;
		}
		
		/* If we didn't see the location of the item, include it in the list */
		if (loc_volume) {
			locations = g_slist_append (locations, GUINT_TO_POINTER (loc_volume));
			t = gkr_location_to_string (loc_volume);
			g_array_append_val (array, t); 
		}
		
		g_key_file_set_string_list (key_file, "location", "names", (const gchar**)array->data, array->len);
		
		g_array_set_size (array, 0);
		for (l = locations; l; l = g_slist_next (l)) {
			t = gkr_location_manager_get_volume_display (locmgr, GPOINTER_TO_UINT (l->data));
			if (!t)
				t = "";
			g_array_append_val (array, t);
		}
		g_key_file_set_string_list (key_file, "location", "display-names", (const gchar**)array->data, array->len);

		g_array_free (array, TRUE);
		g_slist_free (locations);
	}

	data = g_key_file_to_data (key_file, NULL, NULL);
	g_return_val_if_fail (data, NULL);
	
	return data;
}

static gboolean
read_until_end (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	gboolean ret = FALSE;
	guchar *buf;
	int res;
	
	g_return_val_if_fail (pv->out_fd >= 0, FALSE);
	
	/* Passwords come through this buffer */
	buf = egg_secure_alloc (128);

	gkr_daemon_async_register_cancel (close_fd, &pv->out_fd);

	for (;;) {

		if (gkr_daemon_async_is_stopping ())
			break;

		gkr_daemon_async_begin_concurrent ();
			res = read (pv->out_fd, buf, 128);
		gkr_daemon_async_end_concurrent ();

		/* Got an error */
		if (res < 0) {
			if (errno == EINTR || errno == EAGAIN) 
				continue;
			g_warning ("couldn't read from ask tool: %s", g_strerror (errno));
			break;
			
		/* Got some data */
		} else if (res > 0) {
			egg_buffer_append (&pv->buffer, buf, res);
			
		/* End of data */
		} else if (res == 0) {
			ret = TRUE;
			break;
		}
	}
	
	/* Always null terminate */
	egg_buffer_add_byte (&pv->buffer, 0);

	egg_secure_free (buf);
	gkr_daemon_async_unregister_cancel (close_fd, &pv->out_fd);
	
	close_fd (&pv->out_fd);

	return ret;
}

static gboolean
launch_ask_helper (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	gchar **names, **envp;
	int i, n;
	GError *error = NULL;
	gboolean ret;
	
	char *argv[] = {
		LIBEXECDIR "/gnome-keyring-ask",
		NULL,
	};

	/* Calculate us some environment */
	names = g_listenv ();
	g_return_val_if_fail (names, FALSE);
	i = 0; 
	while (names[i])
		++i;
	n = i;
	
	/* Any environment we have */
	envp = g_new (char*, n + 2);
	for (i = 0; i < n; i++)
		envp[i] = g_strdup_printf ("%s=%s", names[i], g_getenv (names[i]));
	envp[i++] = NULL;
	g_strfreev (names);

	egg_buffer_resize (&pv->buffer, 0);
	
	ret = g_spawn_async_with_pipes (NULL, argv, envp, 0, NULL, NULL, &pv->ask_pid, 
	                                &pv->in_fd, &pv->out_fd, NULL, &error);
	g_strfreev (envp);
	
	if (!ret) {
		g_warning ("couldn't spawn gnome-keyring-ask tool: %s", 
		           error && error->message ? error->message : "unknown error");
		pv->out_fd = -1;
		pv->in_fd = -1;
		return FALSE;
	} 
	
	return TRUE;
}

static gboolean
send_all_data (GkrAskRequest *ask, const gchar *buf, gsize len)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	gboolean ret = FALSE;
	int res;
	
	g_return_val_if_fail (pv->in_fd >= 0, FALSE);
	
	gkr_daemon_async_register_cancel (close_fd, &pv->in_fd);

	while (len > 0) {

		if (gkr_daemon_async_is_stopping ())
			break;

		gkr_daemon_async_begin_concurrent ();
			res = write (pv->in_fd, buf, len);
		gkr_daemon_async_end_concurrent ();

		/* Got an error */
		if (res < 0) {
			if (errno == EINTR || errno == EAGAIN) 
				continue;
			g_warning ("couldn't write data to ask tool: %s", g_strerror (errno));
			break;
			
		/* Got some data */
		} else if (res > 0) {
			len -= res;
			buf += res;
			
		/* Eh? */
		} else if (res == 0) {
			g_warning ("couldn't write data to ask tool");
			break;
		}
	}
	
	if (len == 0)
		ret = TRUE;
	
	gkr_daemon_async_unregister_cancel (close_fd, &pv->in_fd);
	
	close_fd (&pv->in_fd);
	return ret;
}

static void 
tracked_object_destroyed (gpointer data, GObject *where_the_object_was)
{
	GkrAskRequest *ask = GKR_ASK_REQUEST (data);
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (pv->object == where_the_object_was);
	pv->object = NULL;
	
	/* Cancel any goings on */
	kill_ask_if_active (ask);
	mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
}

static gboolean
accumulate_checks (GSignalInvocationHint *ihint, GValue *return_accu,
                   const GValue *handler_return, gpointer data)
{
	guint val;
	
	g_assert (ihint->signal_id == signals[CHECK_REQUEST]);
	
	g_assert (G_VALUE_TYPE (handler_return) == G_TYPE_UINT);
	g_assert (G_VALUE_TYPE (return_accu) == G_TYPE_UINT);
	
	/* If the signal handler cares about the result */
	val = g_value_get_uint (handler_return);
	if (val) {
		g_value_set_uint (return_accu, val);
		return FALSE;
	}
	
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gkr_ask_request_init (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	pv->title = g_strdup ("");
	pv->primary = g_strdup ("");
	pv->secondary = g_strdup ("");
	pv->checktext = NULL;
	
	pv->out_fd = -1;
	pv->in_fd = -1;
	
	/* Use a secure memory buffer */
	egg_buffer_init_full (&pv->buffer, 128, egg_secure_realloc);
}

static guint
gkr_ask_request_check_request (GkrAskRequest *ask)
{
	return GKR_ASK_DONT_CARE;
}

static void
gkr_ask_request_dispose (GObject *obj)
{
	GkrAskRequest *ask = GKR_ASK_REQUEST (obj);
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	kill_ask_if_active (ask);
	mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
	g_assert (pv->ask_pid == 0);
	
	egg_secure_strfree (ask->original_password);
	ask->original_password = NULL;
	
	egg_secure_strfree (ask->typed_password);
	ask->typed_password = NULL;
	
	if (pv->in_fd >= 0)
		close_fd (&pv->in_fd);
	if (pv->out_fd >= 0)
		close_fd (&pv->out_fd);
	
	G_OBJECT_CLASS(gkr_ask_request_parent_class)->dispose (obj);
}

static void
gkr_ask_request_finalize (GObject *obj)
{
	GkrAskRequest *ask = GKR_ASK_REQUEST (obj);
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	gkr_ask_request_set_object (ask, NULL);
	g_assert (pv->object == NULL);
	
	g_free (pv->title);
	g_free (pv->primary);
	g_free (pv->secondary);
	g_free (pv->checktext);
	pv->title = pv->primary = pv->secondary = pv->checktext = NULL;
	
	g_assert (pv->ask_pid == 0);
	g_assert (pv->in_fd < 0);
	g_assert (pv->out_fd < 0);
	
	egg_buffer_uninit (&pv->buffer);

	G_OBJECT_CLASS(gkr_ask_request_parent_class)->finalize (obj);
}

static void
gkr_ask_request_class_init (GkrAskRequestClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gkr_ask_request_parent_class = g_type_class_peek_parent (klass);
	
	klass->check_request = gkr_ask_request_check_request;
	
	gobject_class->dispose = gkr_ask_request_dispose;
	gobject_class->finalize = gkr_ask_request_finalize;

	g_type_class_add_private (gobject_class, sizeof (GkrAskRequestPrivate));

	signals[CHECK_REQUEST] = g_signal_new ("check-request", GKR_TYPE_ASK_REQUEST, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GkrAskRequestClass, check_request),
			accumulate_checks, NULL, gkr_ask_marshal_UINT__VOID, 
			G_TYPE_UINT, 0);
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GkrAskRequest*
gkr_ask_request_new (const gchar *title, const gchar *primary, guint flags)
{
	GkrAskRequest *ask;
	GkrAskRequestPrivate *pv;
	
	/* TODO: This should be done via properties */
	
	ask = g_object_new (GKR_TYPE_ASK_REQUEST, NULL);
	pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_free (pv->title);
	pv->title = g_strdup (title ? title : "");
	
	g_free (pv->primary);
	pv->primary = g_strdup (primary ? primary : "");
	pv->flags = flags;
	
	return ask;
}

void
gkr_ask_request_set_secondary (GkrAskRequest *ask, const gchar *secondary)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	g_free (pv->secondary);
	pv->secondary = g_strdup (secondary);
}

void
gkr_ask_request_set_check_option (GkrAskRequest *ask, const gchar *check_text)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	g_free (pv->checktext);
	pv->checktext = g_strdup (check_text);
}

GObject*
gkr_ask_request_get_object (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	return pv->object;
}

void
gkr_ask_request_set_object (GkrAskRequest *ask, GObject *object)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	if (pv->object) {
		g_object_weak_unref (pv->object, tracked_object_destroyed, ask);
		pv->object = NULL;
	}
	
	if (object) {
		pv->object = object;
		g_object_weak_ref (pv->object, tracked_object_destroyed, ask);
	}
}

gboolean
gkr_ask_request_check (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	guint ret;
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	/* Already completed due to object going away or some other? */
	if (pv->completed) 
		return TRUE;
	
	/* Ask all the handlers to prep */
	g_signal_emit (ask, signals[CHECK_REQUEST], 0, &ret);
	
	/* A handler completed it */
	switch (ret) {
	case GKR_ASK_DONT_CARE:
		if (ask->response) {
			mark_completed (ask, ask->response);
			return TRUE;
		}
		break;
	case GKR_ASK_STOP_REQUEST:
		g_assert (ask->response && "check-request signal handler didn't fill in response");
		mark_completed (ask, ask->response);
		return TRUE;
	case GKR_ASK_CONTINUE_REQUEST:
		break;
	default:
		g_assert (FALSE && "invalid return value from a check-request signal handler");
		break;
	}
	
	return FALSE;
}

void
gkr_ask_request_prompt (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	gboolean ret;
	gchar *data;
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	/* Already completed due to object going away or some other? */
	if (pv->completed) 
		return;
	
	ret = launch_ask_helper (ask);
	if (ret) {
		data = prep_dialog_data (ask);
		g_return_if_fail (data);
#if DEBUG_COMMUNICATION
		g_printerr ("TO DIALOG:\n%s\n", data);
#endif
		ret = send_all_data (ask, data, strlen (data));
		g_free (data);
	}
	if (ret) {
		ret = read_until_end (ask);
#if DEBUG_COMMUNICATION
		if (ret)
			g_printerr ("FROM DIALOG:\n%s\n", pv->buffer.buf);
#endif
	}		
	finish_ask_io (ask, ret);
}

void
gkr_ask_request_deny (GkrAskRequest *ask)
{
	g_assert (GKR_IS_ASK_REQUEST (ask));
	kill_ask_if_active (ask);
	mark_completed (ask, GKR_ASK_RESPONSE_DENY);
}

void
gkr_ask_request_cancel (GkrAskRequest *ask)
{
	g_assert (GKR_IS_ASK_REQUEST (ask));
	kill_ask_if_active (ask);
	mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
}

gboolean
gkr_ask_request_is_complete (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	return pv->completed;
}

void
gkr_ask_request_set_location_selector (GkrAskRequest *ask, gboolean have)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	pv->location_selector = have;
}
                                                          
void
gkr_ask_request_set_location (GkrAskRequest *ask, GQuark loc)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	pv->location = loc;
}

gchar*
gkr_ask_request_make_unique (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));

	/* 
	 * This string is used to uniquely identify another
	 * prompt with the same text as this one. Usually used
	 * so we can be intelligent about prompting the user.
	 */
	
	return g_strconcat (pv->title ? pv->title : "", "|", 
	                    pv->primary ? pv->primary : "", "|",
	                    pv->secondary ? pv->secondary : "", "|",
	                    NULL);
}
