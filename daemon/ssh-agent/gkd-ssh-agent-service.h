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

#ifndef __GKD_SSH_AGENT_SERVICE_H__
#define __GKD_SSH_AGENT_SERVICE_H__

#include <gio/gio.h>
#include "gkd-ssh-agent-preload.h"
#include "gkd-ssh-agent-process.h"
#include "egg/egg-buffer.h"

#define GKD_TYPE_SSH_AGENT_SERVICE gkd_ssh_agent_service_get_type ()
G_DECLARE_FINAL_TYPE (GkdSshAgentService, gkd_ssh_agent_service, GKD, SSH_AGENT_SERVICE, GObject);

GkdSshAgentService *gkd_ssh_agent_service_new  (const gchar        *path,
                                                GTlsInteraction    *interaction,
                                                GkdSshAgentPreload *preload);

gboolean            gkd_ssh_agent_service_start
                                               (GkdSshAgentService *self);

void                gkd_ssh_agent_service_stop (GkdSshAgentService *self);

GkdSshAgentPreload *gkd_ssh_agent_service_get_preload
                                               (GkdSshAgentService *self);

GkdSshAgentProcess *gkd_ssh_agent_service_get_process
                                               (GkdSshAgentService *self);

gboolean            gkd_ssh_agent_service_lookup_key
                                               (GkdSshAgentService *self,
                                                GBytes             *key);

#endif /* __GKD_SSH_AGENT_SERVICE_H__ */
