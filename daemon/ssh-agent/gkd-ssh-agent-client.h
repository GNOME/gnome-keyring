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

#ifndef __GKD_SSH_AGENT_CLIENT_H__
#define __GKD_SSH_AGENT_CLIENT_H__

#include <glib-object.h>

#include "egg/egg-buffer.h"

#define GKD_TYPE_SSH_AGENT_CLIENT               (gkm_ssh_agent_client_get_type ())
#define GKD_SSH_AGENT_CLIENT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_TYPE_SSH_AGENT_CLIENT, GkdSshAgentClient))
#define GKD_SSH_AGENT_CLIENT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_TYPE_SSH_AGENT_CLIENT, GkdSshAgentClientClass))
#define GKD_IS_SSH_AGENT_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_TYPE_SSH_AGENT_CLIENT))
#define GKD_IS_SSH_AGENT_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_TYPE_SSH_AGENT_CLIENT))
#define GKD_SSH_AGENT_CLIENT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_TYPE_SSH_AGENT_CLIENT, GkdSshAgentClientClass))

typedef struct _GkdSshAgentClient GkdSshAgentClient;
typedef struct _GkdSshAgentClientClass GkdSshAgentClientClass;

GType                gkd_ssh_agent_client_get_type            (void);

GkdSshAgentClient *  gkd_ssh_agent_client_connect             (void);

gboolean             gkd_ssh_agent_client_transact            (GkdSshAgentClient *self,
							       EggBuffer *req,
							       EggBuffer *resp);

GList *              gkd_ssh_agent_client_preload_keys        (GkdSshAgentClient *self);

gchar *              gkd_ssh_agent_client_preload_comment     (GkdSshAgentClient *self,
                                                               GBytes *key);

GBytes *             gkd_ssh_agent_client_preload_unlock      (GkdSshAgentClient *self,
							       GBytes *key);

void                 gkd_ssh_agent_client_preload_clear       (GkdSshAgentClient *self,
                                                               GBytes *key);

void                 gkd_ssh_agent_client_preload_clear_all   (GkdSshAgentClient *self);

void                 gkd_ssh_agent_client_cleanup             (void);

#endif /* __GKD_SSH_AGENT_CLIENT_H__ */
