/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-interaction.h

   Copyright (C) 2014 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   see <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stefw@redhat.com>
*/

#ifndef GKD_SSH_INTERACTION_H
#define GKD_SSH_INTERACTION_H

#include <gio/gio.h>

G_BEGIN_DECLS

#define GKD_TYPE_SSH_INTERACTION    (gkd_ssh_interaction_get_type ())
#define GKD_SSH_INTERACTION(obj)    (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_TYPE_SSH_INTERACTION, GkdSshInteraction))
#define GKD_SSH_IS_INTERACTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_TYPE_SSH_INTERACTION))

typedef struct _GkdSshInteraction GkdSshInteraction;

GType               gkd_ssh_interaction_get_type               (void) G_GNUC_CONST;

GTlsInteraction *   gkd_ssh_interaction_new                    (GBytes *key);

G_END_DECLS

#endif /* GKD_SSH_INTERACTION_H */
