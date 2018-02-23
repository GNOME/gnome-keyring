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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-glue.h"
#include "gkd-util.h"

#include "ssh-agent/gkd-ssh-agent-service.h"
#include "ssh-agent/gkd-ssh-agent-interaction.h"

#include "egg/egg-cleanup.h"

static void
pkcs11_ssh_cleanup (gpointer data)
{
	GkdSshAgentService *service = GKD_SSH_AGENT_SERVICE (data);
	gkd_ssh_agent_service_stop (service);
	g_object_unref (service);
}

gboolean
gkd_daemon_startup_ssh (void)
{
	const gchar *base_dir;
	GTlsInteraction *interaction;
	GkdSshAgentPreload *preload;
	GkdSshAgentService *service;

	base_dir = gkd_util_get_master_directory ();
	g_return_val_if_fail (base_dir, FALSE);

	interaction = gkd_ssh_agent_interaction_new (NULL);
	preload = gkd_ssh_agent_preload_new ("~/.ssh");

	service = gkd_ssh_agent_service_new (base_dir, interaction, preload);
	g_object_unref (interaction);
	g_object_unref (preload);

	if (!gkd_ssh_agent_service_start (service))
		return FALSE;

	/* ssh-agent sets the environment variable */
	gkd_util_push_environment ("SSH_AUTH_SOCK", g_getenv ("SSH_AUTH_SOCK"));

	egg_cleanup_register (pkcs11_ssh_cleanup, service);

	return TRUE;
}
