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

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-memory.h"
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include "common/gkr-async.h"

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
	
	gchar *title;
	gchar *primary;
	gchar *secondary;
	gchar *checktext;
	
	gboolean completed;
	guint flags;
	
	gint ask_pid;
	GkrBuffer buffer;
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
cancel_ask_if_active (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	if (pv->ask_pid) {
		g_assert (!pv->completed);
		kill_ask_process (ask);
		g_assert (pv->ask_pid == 0);
	}
	
	mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
}

static void
finish_ask_io (GkrAskRequest *ask, gboolean success)
{
	GkrAskRequestPrivate *pv;
	gchar *line, *next;
	int i;

	pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	pv->ask_pid = 0;

	/* Cleanup for response processing */
	gnome_keyring_free_password (ask->typed_password);
	ask->typed_password = NULL;
	gnome_keyring_free_password (ask->original_password);
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
	gkr_buffer_add_byte (&pv->buffer, 0);
	for (i = 0, line = (gchar*)pv->buffer.buf; i < 4; ++i) {
		
		/* Break out the line */
		next = strchr (line, '\n');
		if (next) 
			*next = 0;
		
		/* First line is the response */
		if (i == 0) {
			if (pv->checktext) 
				ask->checked = g_strrstr (line, "checked") ? TRUE : FALSE;
			ask->response = atol (line);
			if (ask->response < GKR_ASK_RESPONSE_ALLOW)
				break;
				
		/* Next line is the typed password (if any) */
		} else if (i == 1) {
			ask->typed_password = gnome_keyring_memory_strdup (line);
			
		/* Last line is the original password (if any) */
		} else if (i == 2) {
			ask->original_password = gnome_keyring_memory_strdup (line);
		}
		
		/* No more lines? */
		if (!next)
			break;
		line = next + 1;
	}
	
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

static gboolean
read_until_end (GkrAskRequest *ask, int fd)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	gboolean ret = FALSE;
	guchar *buf;
	int res;
	
	/* Passwords come through this buffer */
	buf = gnome_keyring_memory_alloc (128);

	gkr_async_register_cancel (close_fd, &fd);

	for (;;) {

		if (gkr_async_is_stopping ())
			break;

		gkr_async_begin_concurrent ();
			res = read (fd, buf, 128);
		gkr_async_end_concurrent ();

		/* Got an error */
		if (res < 0) {
			if (errno == EINTR && errno == EAGAIN) 
				continue;
			g_warning ("couldn't read from ask tool: %s", g_strerror (errno));
			break;
			
		/* Got some data */
		} else if (res > 0) {
			gkr_buffer_append (&pv->buffer, buf, res);
			
		/* End of data */
		} else if (res == 0) {
			ret = TRUE;
			break;
		}
	}
	
	gnome_keyring_memory_free (buf);
	gkr_async_unregister_cancel (close_fd, &fd);

	return ret;
}

static int
launch_ask_helper (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	const gchar* display;
	char **envp;
	int i, n;
	int stdout_fd;
	GError *error = NULL;
	char *argv[] = {
		LIBEXECDIR "/gnome-keyring-ask",
		NULL,
	};

	/* Calculate us some environment */
	i = 0;
	while (environ[i])
		++i;
	n = i;
	
	/* Any environment we have */
	envp = g_new (char*, n + 1 + 6);
	for (i = 0; i < n; i++)
		envp[i] = g_strdup (environ[i]);
	
	/* And add in the stuff we need */
	display = gkr_ask_daemon_get_display ();
	if (display && display[0])
		envp[i++] = g_strdup_printf ("DISPLAY=%s", display);
	envp[i++] = format_object_markup (pv->object, "ASK_TITLE=", pv->title);
	envp[i++] = format_object_markup (pv->object, "ASK_PRIMARY=", pv->primary);
	envp[i++] = format_object_markup (pv->object, "ASK_SECONDARY=", pv->secondary);
	if (pv->checktext)
		envp[i++] = g_strdup_printf ("ASK_CHECK=%s", pv->checktext);
	envp[i++] = g_strdup_printf ("ASK_FLAGS=%d", pv->flags);
	envp[i++] = NULL;

	gkr_buffer_resize (&pv->buffer, 0);
	
	if (!g_spawn_async_with_pipes (NULL, argv, envp, 0, NULL, NULL, &pv->ask_pid, 
	                               NULL, &stdout_fd, NULL, &error)) {
		g_warning ("couldn't spawn gnome-keyring-ask tool: %s", 
		           error && error->message ? error->message : "unknown error");
		stdout_fd = -1;
	} 
	
	g_strfreev (envp);
	return stdout_fd;
}

static void 
tracked_object_destroyed (gpointer data, GObject *where_the_object_was)
{
	GkrAskRequest *ask = GKR_ASK_REQUEST (data);
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	g_assert (pv->object == where_the_object_was);
	pv->object = NULL;
	
	/* Cancel any goings on */
	cancel_ask_if_active (ask);
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
	
	/* Use a secure memory buffer */
	gkr_buffer_init_full (&pv->buffer, 128, gnome_keyring_memory_realloc);
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
	
	cancel_ask_if_active (ask);
	g_assert (pv->ask_pid == 0);
	
	gnome_keyring_free_password (ask->original_password);
	ask->original_password = NULL;
	
	gnome_keyring_free_password (ask->typed_password);
	ask->typed_password = NULL;
	
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
	
	gkr_buffer_uninit (&pv->buffer);

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
	int outfd;
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	/* Already completed due to object going away or some other? */
	if (pv->completed) 
		return;
	
	outfd = launch_ask_helper (ask);
	
	ret = read_until_end (ask, outfd);
	
	finish_ask_io (ask, ret);
}

void
gkr_ask_request_cancel (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	cancel_ask_if_active (ask);
	if (!pv->completed)
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
}

gboolean
gkr_ask_request_is_complete (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	return pv->completed;
}
