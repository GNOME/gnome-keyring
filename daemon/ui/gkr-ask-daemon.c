/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ask-daemon.c: Global ask functionality

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-ask-daemon.h"
#include "gkr-ask-request.h"

#include "daemon/util/gkr-daemon-async.h"
#include "daemon/util/gkr-daemon-util.h"

#include "egg/egg-cleanup.h"

#include <glib.h>

static gboolean ask_daemon_inited = FALSE;

static GkrDaemonAsyncWait *wait_condition = NULL;
static GkrAskRequest *current_ask = NULL;

static GkrAskHook ask_daemon_hook = NULL;
static gpointer ask_daemon_hook_data = NULL;

static void 
ask_daemon_cleanup (gpointer unused)
{
	g_assert (ask_daemon_inited);

	if (current_ask)
		gkr_ask_request_cancel (current_ask);
	
	g_assert (wait_condition);
	gkr_daemon_async_wait_free (wait_condition);
	wait_condition = NULL;
	
	ask_daemon_inited = FALSE;
}

static void
ask_daemon_init (void)
{
	if (ask_daemon_inited)
		return;
	ask_daemon_inited = TRUE;
	
	wait_condition = gkr_daemon_async_wait_new ();
	
	egg_cleanup_register (ask_daemon_cleanup, NULL);
}

static gboolean
check_previously_denied (GkrAskRequest *ask)
{
	GkrDaemonClient *client;
	GHashTable *denied;
	gchar *unique;
	gboolean ret;
	
	client = gkr_daemon_client_get_current ();
	if (client == NULL)
		return FALSE;
	
	denied = g_object_get_data (G_OBJECT (client), "gkr-ask-daemon.denied");
	if (!denied)
		return FALSE;
	
	unique = gkr_ask_request_make_unique (ask);
	g_return_val_if_fail (unique, FALSE);
	ret = g_hash_table_lookup (denied, unique) ? TRUE : FALSE;
	g_free (unique);
	return ret;
}

static void
note_previously_denied (GkrAskRequest *ask)
{
	GkrDaemonClient *client;
	GHashTable *denied;
	gchar *unique;

	unique = gkr_ask_request_make_unique (ask);
	g_return_if_fail (unique);
	
	client = gkr_daemon_client_get_current ();
	if (!client)
		return;

	/* Associate the denied table with the current client */
	denied = g_object_get_data (G_OBJECT (client), "gkr-ask-daemon.denied");
	if (!denied) {
		denied = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
		g_object_set_data_full (G_OBJECT (client), "gkr-ask-daemon.denied", 
		                        denied, (GDestroyNotify)g_hash_table_unref);
	}
	
	g_hash_table_insert (denied, unique, unique);
}

void
gkr_ask_daemon_process (GkrAskRequest* ask)
{
	ask_daemon_init ();
	
	g_assert (GKR_IS_ASK_REQUEST (ask));
	g_assert (!gkr_ask_request_is_complete (ask));

	g_object_ref (ask);

	/* 
	 * Hand it off to the hook. This is used in the test harnesses
	 * to verify that a prompt or no prompt was run.
	 */
	if (ask_daemon_hook)
		(ask_daemon_hook) (ask, ask_daemon_hook_data);
	
	/* See if it'll complete without a prompt */
	if (gkr_ask_request_check (ask))
		goto done;
	
	if (gkr_daemon_async_is_stopping ()) {
		gkr_ask_request_cancel (ask);
		goto done;
	}
	
	/* Wait until no other asks are prompting */
	while (current_ask)
		gkr_daemon_async_wait (wait_condition);

	/* 
	 * See if the user already denied this request.
	 * 
	 * The logic here is, that if the user denied the request, 
	 * then we won't prompt them again for the same string. 
	 * They'll probably deny it again. 
	 * 
	 * We only keep this cache for the current client connection. 
	 */
	if (check_previously_denied (ask)) {
		g_message ("user denied this prompt previously, skipping prompt and automatically denying");
		gkr_ask_request_deny (ask);
		goto done;
	}
	
	g_assert (ask_daemon_inited);
	current_ask = ask;
	
	if (!gkr_ask_request_check (ask)) {
		gkr_ask_request_prompt (ask);
		
		/* 
		 * Note that this prompt was explicitly denied, so we 
		 * can prevent prompting again on the same client
		 * connection. See above.
		 */ 
		if (ask->response == GKR_ASK_RESPONSE_DENY)
			note_previously_denied (ask);
	}

	current_ask = NULL;
	
	g_assert (wait_condition);
	gkr_daemon_async_notify (wait_condition);
	
done:
	g_assert (gkr_ask_request_is_complete (ask));
	g_object_unref (ask);
}

void
gkr_ask_daemon_set_hook (GkrAskHook hook, gpointer data)
{
	ask_daemon_hook = hook;
	ask_daemon_hook_data = data;
}
