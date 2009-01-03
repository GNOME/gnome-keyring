/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-ssh-agent-standalone.c - Test standalone SSH agent

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include <glib.h>

#include "gck-ssh-agent.h"

#include "common/gkr-secure-memory.h"

G_LOCK_DEFINE_STATIC (memory_mutex);

void gkr_memory_lock (void)
	{ G_LOCK (memory_mutex); }

void gkr_memory_unlock (void)
	{ G_UNLOCK (memory_mutex); }

void* gkr_memory_fallback (void *p, unsigned long sz)
	{ return g_realloc (p, sz); }

static gboolean
accept_client (GIOChannel *channel, GIOCondition cond, gpointer unused)
{
	gck_ssh_agent_accept ();
	return TRUE;
}

static gboolean 
authenticate_token (GP11Slot *self, gchar *label, gchar **password, gpointer unused)
{
	gchar *prompt = g_strdup_printf ("Enter token password (%s): ", label);
	char *result = getpass (prompt);
	g_free (prompt);
	*password = g_strdup (result);
	memset (result, 0, strlen (result));
	return TRUE;
}

static gboolean 
authenticate_object (GP11Slot *self, GP11Object *object, gchar *label, gchar **password)
{
	gchar *prompt = g_strdup_printf ("Enter object password (%s): ", label);
	char *result = getpass (prompt);
	g_free (prompt);
	*password = g_strdup (result);
	memset (result, 0, strlen (result));
	return TRUE;
}

int 
main(int argc, char *argv[])
{
	GP11Module *module;
	GList *slots;
	GP11Slot *slot;
	GError *error = NULL;
	GIOChannel *channel;
	GMainLoop *loop;
	
	g_type_init ();
	
	if (!g_thread_supported ())
		g_thread_init (NULL);
	
	module = gp11_module_initialize (argv[1], argc > 2 ? argv[2] : NULL, &error);
	if (!module) {
		g_message ("couldn't load pkcs11 module: %s", error->message);
		g_clear_error (&error);
		return 1;
	}
	
	/* This is currently brittle because it's just used for development */
	slots = gp11_module_get_slots (module, TRUE);
	if (!slots) {
		g_message ("no slots present in pkcs11 module");
		return 1;
	}

	slot = g_object_ref (slots->data);
	gp11_list_unref_free (slots);
	
	g_signal_connect (slot, "authenticate-token", G_CALLBACK (authenticate_token), NULL);
	g_signal_connect (slot, "authenticate-object", G_CALLBACK (authenticate_object), NULL);
	gp11_slot_set_auto_login (slot, TRUE);

	if (!gck_ssh_agent_initialize ("/tmp/test-gck-ssh-agent", slot))
		return 1;
	
	channel = g_io_channel_unix_new (gck_ssh_agent_get_socket_fd ());
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, accept_client, NULL);
	g_io_channel_unref (channel);

	g_print ("SSH_AUTH_SOCK=%s\n", gck_ssh_agent_get_socket_path ());
	
	/* Run a main loop */
	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
	
	gck_ssh_agent_uninitialize ();
	g_object_unref (slot);
	
	return 0;
}
