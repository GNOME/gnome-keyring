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
	GList *ask_requests;
	gpointer data;
} GkrKeyringRequest;	

typedef struct {
	gboolean (*collect_info) (GkrBuffer *packet,
				  GkrKeyringRequest *req);
	gboolean (*execute_op) (GkrBuffer *packet,
				GkrBuffer *result,
				GkrKeyringRequest *req);
} GnomeKeyringOperationImplementation;

extern GnomeKeyringOperationImplementation keyring_ops[];
GList *                     gnome_keyring_acl_copy (GList *list);


GnomeKeyringApplicationRef *gnome_keyring_application_ref_new_from_pid (pid_t                             pid);
GnomeKeyringApplicationRef *gnome_keyring_application_ref_copy         (const GnomeKeyringApplicationRef *app);
void                        gnome_keyring_application_ref_free         (GnomeKeyringApplicationRef       *app);

void gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac);
void                        gnome_keyring_acl_free                     (GList                            *acl);


void     cleanup_socket_dir   (void);
gboolean create_master_socket (const char **path);

GnomeKeyringAttributeList *gnome_keyring_attributes_hash    (GnomeKeyringAttributeList        *attributes);
GnomeKeyringAccessControl *gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
							     GnomeKeyringAccessType            types_allowed);

void gnome_keyring_client_fixup_for_removed (gpointer keyring, gpointer item);

/* Dbus Initialization/Cleanup */
#ifdef WITH_DBUS
void gnome_keyring_daemon_dbus_setup (GMainLoop *loop, const gchar* socket);
void gnome_keyring_daemon_dbus_cleanup (void);
#endif 

#endif /* GNOME_KEYRING_DAEMON_H */
