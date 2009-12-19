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

#include "gkd-util.h"
#include "gkd-pkcs11-auth.h"
#include "gkd-pkcs11.h"

#include "pkcs11/plex-layer/gck-plex-layer.h"
#include "pkcs11/roots-store/gck-roots-store.h"
#include "pkcs11/rpc-layer/gck-rpc-layer.h"
#include "pkcs11/secret-store/gck-secret-store.h"
#include "pkcs11/ssh-agent/gck-ssh-agent.h"
#include "pkcs11/ssh-store/gck-ssh-store.h"
#include "pkcs11/user-store/gck-user-store.h"

#include "egg/egg-cleanup.h"

/* The top level of our internal PKCS#11 module stack */
static CK_FUNCTION_LIST_PTR pkcs11_roof = NULL;
static CK_FUNCTION_LIST_PTR pkcs11_base = NULL;

static void
pkcs11_daemon_cleanup (gpointer unused)
{
	CK_RV rv;

	g_assert (pkcs11_roof);

	gck_ssh_agent_uninitialize ();
	gck_rpc_layer_uninitialize ();
	rv = (pkcs11_roof->C_Finalize) (NULL);

	if (rv != CKR_OK)
		g_warning ("couldn't finalize internal PKCS#11 stack (code: %d)", (gint)rv);

	pkcs11_roof = NULL;
}

gboolean
gkd_pkcs11_initialize (void)
{
	CK_FUNCTION_LIST_PTR roots_store;
	CK_FUNCTION_LIST_PTR secret_store;
	CK_FUNCTION_LIST_PTR ssh_store;
	CK_FUNCTION_LIST_PTR user_store;
	gboolean ret;
	CK_RV rv;

	/* Secrets */
	secret_store = gck_secret_store_get_functions ();

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
	gck_plex_layer_add_module (secret_store);
	gck_plex_layer_add_module (user_store);

	pkcs11_base = gck_plex_layer_get_functions ();

	/* The auth component is the top component */
	gkd_pkcs11_auth_chain_functions (pkcs11_base);
	pkcs11_roof = gkd_pkcs11_auth_get_functions ();

	/* Initialize the whole caboodle */
	rv = (pkcs11_roof->C_Initialize) (NULL);

	if (rv != CKR_OK) {
		g_warning ("couldn't initialize internal PKCS#11 stack (code: %d)", (gint)rv);
		return FALSE;
	}

	egg_cleanup_register (pkcs11_daemon_cleanup, NULL);

	ret = gck_ssh_agent_initialize (pkcs11_roof) &&
	      gck_rpc_layer_initialize (pkcs11_roof);

	return ret;
}

static void
pkcs11_rpc_cleanup (gpointer unused)
{
	gck_rpc_layer_shutdown ();
}

static gboolean
accept_rpc_client (GIOChannel *channel, GIOCondition cond, gpointer unused)
{
	if (cond == G_IO_IN)
		gck_rpc_layer_accept ();

	return TRUE;
}

gboolean
gkd_pkcs11_startup_pkcs11 (void)
{
	GIOChannel *channel;
	const gchar *base_dir;
	int sock;

	base_dir = gkd_util_get_master_directory ();
	g_return_val_if_fail (base_dir, FALSE);

	sock = gck_rpc_layer_startup (base_dir);
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
	gck_ssh_agent_shutdown ();
}

static gboolean
accept_ssh_client (GIOChannel *channel, GIOCondition cond, gpointer unused)
{
	if (cond == G_IO_IN)
		gck_ssh_agent_accept ();
	return TRUE;
}

gboolean
gkd_pkcs11_startup_ssh (void)
{
	GIOChannel *channel;
	const gchar *base_dir;
	int sock;

	base_dir = gkd_util_get_master_directory ();
	g_return_val_if_fail (base_dir, FALSE);

	sock = gck_ssh_agent_startup (base_dir);
	if (sock == -1)
		return FALSE;

	channel = g_io_channel_unix_new (sock);
	g_io_add_watch (channel, G_IO_IN | G_IO_HUP, accept_ssh_client, NULL);
	g_io_channel_unref (channel);

	/* gck-ssh-agent sets the environment variable */
	gkd_util_push_environment ("SSH_AUTH_SOCK", g_getenv ("SSH_AUTH_SOCK"));

	egg_cleanup_register (pkcs11_ssh_cleanup, NULL);

	return TRUE;
}

CK_FUNCTION_LIST_PTR
gkd_pkcs11_get_functions (void)
{
	return pkcs11_roof;
}

CK_FUNCTION_LIST_PTR
gkd_pkcs11_get_base_functions (void)
{
	return pkcs11_base;
}
