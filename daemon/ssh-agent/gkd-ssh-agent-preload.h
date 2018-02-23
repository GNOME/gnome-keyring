/*
 * gnome-keyring
 *
 * Copyright (C) 2014 Stef Walter
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

#ifndef __GKD_SSH_AGENT_PRELOAD_H__
#define __GKD_SSH_AGENT_PRELOAD_H__

#include <glib-object.h>

typedef struct {
	gchar *filename;
	GBytes *public_key;
	gchar *comment;
} GkdSshAgentKeyInfo;

void                gkd_ssh_agent_key_info_free    (gpointer boxed);
gpointer            gkd_ssh_agent_key_info_copy    (gpointer boxed);

#define GKD_TYPE_SSH_AGENT_PRELOAD gkd_ssh_agent_preload_get_type ()
G_DECLARE_FINAL_TYPE (GkdSshAgentPreload, gkd_ssh_agent_preload, GKD, SSH_AGENT_PRELOAD, GObject)

GkdSshAgentPreload *gkd_ssh_agent_preload_new      (const gchar *path);

GList              *gkd_ssh_agent_preload_get_keys (GkdSshAgentPreload *self);

GkdSshAgentKeyInfo *gkd_ssh_agent_preload_lookup_by_public_key
                                                   (GkdSshAgentPreload *self,
                                                    GBytes *public_key);

#endif /* __GKD_SSH_AGENT_PRELOAD_H__ */

