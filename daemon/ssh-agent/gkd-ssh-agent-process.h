/*
 * gnome-keyring
 *
 * Copyright (C) 2014 Stef Walter
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
 *
 * Author: Stef Walter <stef@thewalter.net>
 */

#ifndef __GKD_SSH_AGENT_PROCESS_H__
#define __GKD_SSH_AGENT_PROCESS_H__

#include <glib-object.h>

#include "egg/egg-buffer.h"

#define GKD_TYPE_SSH_AGENT_PROCESS gkd_ssh_agent_process_get_type ()
G_DECLARE_FINAL_TYPE(GkdSshAgentProcess, gkd_ssh_agent_process, GKD, SSH_AGENT_PROCESS, GObject)

GkdSshAgentProcess *gkd_ssh_agent_process_new         (const gchar        *path);
gboolean            gkd_ssh_agent_process_connect     (GkdSshAgentProcess *self);
gboolean            gkd_ssh_agent_process_call        (GkdSshAgentProcess *self,
                                                       EggBuffer          *req,
                                                       EggBuffer          *resp);
gboolean            gkd_ssh_agent_process_lookup_key  (GkdSshAgentProcess *self,
                                                       GBytes             *key);
void                gkd_ssh_agent_process_add_key     (GkdSshAgentProcess *self,
                                                       GBytes             *key);
void                gkd_ssh_agent_process_remove_key  (GkdSshAgentProcess *self,
                                                       GBytes             *key);
void                gkd_ssh_agent_process_clear_keys  (GkdSshAgentProcess *self);

#endif /* __GKD_SSH_AGENT_PROCESS_H__ */
