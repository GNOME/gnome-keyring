/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gkr-pkcs11-auth.h"
#include "gkr-pkcs11-daemon.h"

#include "pkcs11/plex-layer/gck-plex-layer.h"
#include "pkcs11/roots-store/gck-roots-store.h"
#include "pkcs11/rpc-layer/gck-rpc-layer.h"
#include "pkcs11/ssh-agent/gck-ssh-agent.h"
#include "pkcs11/ssh-store/gck-ssh-store.h"
#include "pkcs11/user-store/gck-user-store.h"

#include "daemon/util/gkr-daemon-async.h"
#include "daemon/util/gkr-daemon-util.h"

#include "egg/egg-cleanup.h"

/*
 * ALL calls into PKCS#11 and anything starting with 'gck'
 * must be concurrent. That is must UNLOCK the demon lock, 
 * perform the call and then relock. 
 * 
 * 	gkr_daemon_async_begin_concurrent ();
 *	
 *		gck_call_xxxx (xxx);
 *	
 *	gkr_daemon_async_end_concurrent ();
 */

/* The top level of our internal PKCS#11 module stack */
static CK_FUNCTION_LIST_PTR pkcs11_roof = NULL;

static void
pkcs11_daemon_cleanup (gpointer unused)
{
	CK_RV rv;
	
	g_assert (pkcs11_roof);

	gkr_daemon_async_begin_concurrent ();

		gck_ssh_agent_uninitialize ();
		gck_rpc_layer_uninitialize ();
		rv = (pkcs11_roof->C_Finalize) (NULL);
	
	gkr_daemon_async_end_concurrent ();
	
	if (rv != CKR_OK)
		g_warning ("couldn't finalize internal PKCS#11 stack (code: %d)", (gint)rv);

	pkcs11_roof = NULL;
}

gboolean
gkr_pkcs11_daemon_initialize (void)
{
	CK_FUNCTION_LIST_PTR plex_layer;
	CK_FUNCTION_LIST_PTR roots_store; 
	CK_FUNCTION_LIST_PTR ssh_store;
	CK_FUNCTION_LIST_PTR user_store;
	gboolean ret;
	CK_RV rv;

	/* Now initialize them all */
	gkr_daemon_async_begin_concurrent ();

		/* SSH storage */
		ssh_store = gck_ssh_store_get_functions ();
		
		/* Root certificates */
		roots_store = gck_roots_store_get_functions ();
		
		/* User certificates */
		user_store = gck_user_store_get_functions ();
		
		/* Add all of those into the multiplexing layer */
		gck_plex_layer_add_module (ssh_store);
#ifdef ROOT_CERTIFICATES
		gck_plex_layer_add_module (roots_store);
#endif
		gck_plex_layer_add_module (user_store);
		
		plex_layer = gck_plex_layer_get_functions (); 
		
		/* The auth component is the top component */
		gkr_pkcs11_auth_chain_functions (plex_layer);
		pkcs11_roof = gkr_pkcs11_auth_get_functions ();
	
		/* Initialize the whole caboodle */
		rv = (pkcs11_roof->C_Initialize) (NULL);

	gkr_daemon_async_end_concurrent ();

	if (rv != CKR_OK) {
		g_warning ("couldn't initialize internal PKCS#11 stack (code: %d)", (gint)rv);
		return FALSE;
	}		
	
	egg_cleanup_register (pkcs11_daemon_cleanup, NULL);

	gkr_daemon_async_begin_concurrent ();

		ret = gck_ssh_agent_initialize (pkcs11_roof) &&
		      gck_rpc_layer_initialize (pkcs11_roof);

	gkr_daemon_async_end_concurrent ();

	return ret;
}

static void
pkcs11_rpc_cleanup (gpointer unused)
{
	gkr_daemon_async_begin_concurrent ();

		gck_rpc_layer_shutdown ();

	gkr_daemon_async_end_concurrent ();
}

static gboolean
accept_rpc_client (GIOChannel *channel, GIOCondition cond, gpointer unused)
{
	gkr_daemon_async_begin_concurrent ();

		if (cond == G_IO_IN)
			gck_rpc_layer_accept ();
		
	gkr_daemon_async_end_concurrent ();
	
	return TRUE;
}

gboolean
gkr_pkcs11_daemon_startup_pkcs11 (void)
{
	GIOChannel *channel;
	const gchar *base_dir;
	int sock;

	base_dir = gkr_daemon_util_get_master_directory ();
	g_return_val_if_fail (base_dir, FALSE);

	gkr_daemon_async_begin_concurrent ();

		sock = gck_rpc_layer_startup (base_dir);

	gkr_daemon_async_end_concurrent ();
	
	if (sock == -1)
		return FALSE;
	
	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, accept_rpc_client, NULL);
	g_io_channel_unref (channel);

	egg_cleanup_register (pkcs11_rpc_cleanup, NULL);

	return TRUE;
}

static void
pkcs11_ssh_cleanup (gpointer unused)
{
	gkr_daemon_async_begin_concurrent ();

		gck_ssh_agent_shutdown ();

	gkr_daemon_async_end_concurrent ();
}

static gboolean
accept_ssh_client (GIOChannel *channel, GIOCondition cond, gpointer unused)
{
	gkr_daemon_async_begin_concurrent ();

		if (cond == G_IO_IN)
			gck_ssh_agent_accept ();
		
	gkr_daemon_async_end_concurrent ();
				
	return TRUE;
}

gboolean
gkr_pkcs11_daemon_startup_ssh (void)
{
	GIOChannel *channel;
	const gchar *base_dir;
	int sock;

	base_dir = gkr_daemon_util_get_master_directory ();
	g_return_val_if_fail (base_dir, FALSE);

	gkr_daemon_async_begin_concurrent ();

		sock = gck_ssh_agent_startup (base_dir);

	gkr_daemon_async_end_concurrent ();
	
	if (sock == -1)
		return FALSE;
	
	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, accept_ssh_client, NULL);
	g_io_channel_unref (channel);
	
	/* gck-ssh-agent sets the environment variable */
	gkr_daemon_util_push_environment ("SSH_AUTH_SOCK", g_getenv ("SSH_AUTH_SOCK"));

	egg_cleanup_register (pkcs11_ssh_cleanup, NULL);

	return TRUE;
}
