/*
 * Copyright (C) 2014 Stef Walter
 *
 * Gnome keyring is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * Gnome keyring is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: Stef Walter <stef@thewalter.net>
 */

#ifndef GKD_SSH_OPENSSH_H_
#define GKD_SSH_OPENSSH_H_

#include <glib.h>

GBytes *         gkd_ssh_openssh_parse_public_key      (GBytes *data,
                                                        gchar **comment);

#endif /* GKD_SSH_OPENSSH_H_ */
