/*
 * gnome-keyring
 *
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
 * Author: Daiki Ueno
 */

#include <gio/gio.h>
#include "egg/egg-buffer.h"

#ifndef __GKD_SSH_AGENT_UTIL_H__
#define __GKD_SSH_AGENT_UTIL_H__ 1

gboolean _gkd_ssh_agent_read_packet      (GSocketConnection  *connection,
                                          EggBuffer          *buffer,
                                          GCancellable       *cancellable,
                                          GError            **error);

gboolean _gkd_ssh_agent_write_packet     (GSocketConnection  *connection,
                                          EggBuffer          *buffer,
                                          GCancellable       *cancellable,
                                          GError            **error);

gboolean _gkd_ssh_agent_call             (GSocketConnection  *connection,
                                          EggBuffer          *req,
                                          EggBuffer          *resp,
                                          GCancellable       *cancellable,
                                          GError            **error);

GBytes  *_gkd_ssh_agent_parse_public_key (GBytes             *input,
                                          gchar             **comment);

gchar   *_gkd_ssh_agent_canon_error      (gchar *str);

#endif /* __GKD_SSH_AGENT_UTIL_H__ */
