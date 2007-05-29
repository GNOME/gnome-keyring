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
#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

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
	
	gchar* title;
	gchar* primary;
	gchar* secondary;
	
	gboolean completed;
	guint flags;
	
	gint ask_pid;
	GString *buffer;
	guint input_watch;
};

#define GKR_ASK_REQUEST_GET_PRIVATE(o)  \
	(G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_ASK_REQUEST, GkrAskRequestPrivate))

G_DEFINE_TYPE (GkrAskRequest, gkr_ask_request, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 }; 

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
		g_signal_emit (ask, signals[COMPLETED], 0);
	}
}

static void
kill_ask_process (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	if (pv->input_watch != 0) {

		g_source_remove (pv->input_watch);
		pv->input_watch = 0;
	}
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
finish_ask_io (GkrAskRequest *ask, gboolean failed)
{
	GkrAskRequestPrivate *pv;
	gchar **lines;

	pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	
	pv->input_watch = 0;
	pv->ask_pid = 0;

	/* Cleanup for response processing */
	g_free (ask->typed_password);
	ask->typed_password = NULL;
	g_free (ask->original_password);
	ask->original_password = NULL;
	
	/* A failed request */
	if (failed) {
		mark_completed (ask, GKR_ASK_RESPONSE_FAILURE);
		return;
	}
	
	/* Parse out all the information we have */
	lines = g_strsplit (pv->buffer->str, "\n", 4);
	if (lines[0]) {
		/* First line is the response */
		ask->response = atol (lines[0]);
		
		/* Only use passwords if confirming */
		if (ask->response >= GKR_ASK_RESPONSE_ALLOW) {
			if (lines[1]) {
				/* Next line is the typed password (if any) */
				ask->typed_password = g_strdup (lines[1]);
				if (lines[2]) {
					/* Last line is the original password (if any) */
					ask->original_password = g_strdup (lines[2]);
				}
			}
		} 
	}
	g_strfreev (lines);
	
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

static gboolean
ask_io (GIOChannel *channel, GIOCondition cond, gpointer data)
{
	GkrAskRequest *ask;
	GkrAskRequestPrivate *pv;
	char buffer[1024];
	int res;
	int fd;

	ask = GKR_ASK_REQUEST (data);
	pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);

	if (cond & G_IO_IN) {
		do 
		{
			fd = g_io_channel_unix_get_fd (channel);
			res = read (fd, buffer, sizeof (buffer));
			if (res < 0) {
				if (errno != EINTR && errno != EAGAIN) {
					finish_ask_io (ask, TRUE);
					return FALSE;
				}
			} else if (res > 0) {
				g_string_append_len (pv->buffer, buffer, res);
			}
		} while (res > 0);
	}

	if (cond & G_IO_HUP) {	
		finish_ask_io (ask, FALSE);
		return FALSE;
	}
	
	return TRUE;
}

static gboolean
launch_ask_helper (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	GIOChannel *channel;
	const gchar* display;
	char **envp;
	int i, n;
	int stdout_fd;
	GError *error;
	char *argv[] = {
		LIBEXECDIR "/gnome-keyring-ask",
		NULL,
	};
	gboolean res;

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
	envp[i++] = g_strdup_printf ("ASK_TITLE=%s", pv->title);
	envp[i++] = g_strdup_printf ("ASK_PRIMARY=%s", pv->primary);
	envp[i++] = g_strdup_printf ("ASK_SECONDARY=%s", pv->secondary);
	envp[i++] = g_strdup_printf ("ASK_FLAGS=%d", pv->flags);
	envp[i++] = NULL;

	g_string_truncate (pv->buffer, 0);
	
	if (!g_spawn_async_with_pipes (NULL, argv, envp, 0, NULL, NULL, &pv->ask_pid, 
	                               NULL, &stdout_fd, NULL, &error)) {
		g_warning ("couldn't spawn gnome-keyring-ask tool: %s", 
		           error && error->message ? error->message : "unknown error");
		res = FALSE;
	} else {
		channel = g_io_channel_unix_new (stdout_fd);
		pv->input_watch = g_io_add_watch (channel, G_IO_IN | G_IO_HUP, ask_io, ask);
		g_io_channel_unref (channel);
		res = TRUE;
	}
	
	g_strfreev (envp);
	return res;
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
	pv->buffer = g_string_new ("");
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
	pv->title = pv->primary = pv->secondary = NULL;
	
	g_assert (pv->ask_pid == 0);
	
	if (pv->buffer)
		g_string_free (pv->buffer, TRUE);
	pv->buffer = NULL;
	
	if (pv->input_watch) 
		g_source_remove (pv->input_watch);
	pv->input_watch = 0;

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

	signals[COMPLETED] = g_signal_new ("completed", GKR_TYPE_ASK_REQUEST, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrAskRequestClass, completed),
			NULL, NULL, g_cclosure_marshal_VOID__VOID, 
			G_TYPE_NONE, 0);
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
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	/* Already completed due to object going away or some other? */
	if (pv->completed) 
		return;
	
	launch_ask_helper (ask);
}

void
gkr_ask_request_cancel (GkrAskRequest *ask)
{
	g_assert (GKR_IS_ASK_REQUEST (ask));
	
	cancel_ask_if_active (ask);
}

gboolean
gkr_ask_request_is_complete (GkrAskRequest *ask)
{
	GkrAskRequestPrivate *pv = GKR_ASK_REQUEST_GET_PRIVATE (ask);
	g_assert (GKR_IS_ASK_REQUEST (ask));
	return pv->completed;
}
