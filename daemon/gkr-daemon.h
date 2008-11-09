/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon.h - common includes for the keyring daemon code

   Copyright (C) 2003 Red Hat, Inc

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

#ifndef GNOME_KEYRING_DAEMON_H
#define GNOME_KEYRING_DAEMON_H

#include <time.h>
#include <sys/types.h>
#include <glib.h>

#include "common/gkr-buffer.h"

#include "keyrings/gkr-keyring.h"
#include "keyrings/gkr-keyring-item.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"


typedef struct {
	GnomeKeyringApplicationRef *app_ref;
} GkrKeyringRequest;	

typedef gboolean (*GkrDaemonOperation) (GkrBuffer *packet, GkrBuffer *result,
                                        GkrKeyringRequest *req);

extern GkrDaemonOperation keyring_ops[];

void           gkr_daemon_quit (void);

gboolean       gkr_daemon_io_create_master_socket (void);
const gchar*   gkr_daemon_io_get_socket_path      (void);

/* Dbus Initialization/Cleanup */
void gkr_daemon_dbus_setup (void);

#endif /* GNOME_KEYRING_DAEMON_H */
