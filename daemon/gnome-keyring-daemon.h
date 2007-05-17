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

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-private.h"

#include "keyrings/gkr-keyring.h"
#include "keyrings/gkr-keyring-item.h"

typedef enum {
	/* Access a keyring at all */
	GNOME_KEYRING_ACCESS_REQUEST_KEYRING,

	/* Access basic info about an item, without secret (always read access) */
	GNOME_KEYRING_ACCESS_REQUEST_ITEM,

	/* Access, change or delete, all info for item, including a secret */
	GNOME_KEYRING_ACCESS_REQUEST_ITEM_SECRET,

	/* Set various passwords for keyrings */
	GNOME_KEYRING_ACCESS_REQUEST_NEW_KEYRING_PASSWORD,
	GNOME_KEYRING_ACCESS_REQUEST_ORIGINAL_CHANGE_KEYRING_PASSWORD,
	GNOME_KEYRING_ACCESS_REQUEST_CHANGE_KEYRING_PASSWORD,

	/* Access to change the default keyring */
	GNOME_KEYRING_ACCESS_REQUEST_DEFAULT_KEYRING
} GnomeKeyringAccessRequestType;

typedef struct {
	GnomeKeyringAccessRequestType request_type;
	
	GnomeKeyringAccessType access_type;

	/* Only one is non-NULL */
	GkrKeyring *keyring;
	GkrKeyringItem *item;
	
	char *new_keyring;
	/* filled out for password requests */
	char *original;
	char *password;
	
	gboolean granted;
} GnomeKeyringAccessRequest;

typedef struct {
	gboolean (*collect_info) (GString *packet,
				  GList **access_requests);
	gboolean (*execute_op) (GString *packet,
				GString *result,
				GnomeKeyringApplicationRef *app_ref,
				GList *access_requests);
} GnomeKeyringOperationImplementation;

extern GnomeKeyringOperationImplementation keyring_ops[];

typedef void (*GnomeKeyringRequestAccessCallback) (GList *access_requests,
						   gpointer data);

gpointer gnome_keyring_ask      (GList                             *access_requests,
				 GnomeKeyringApplicationRef        *app_ref,
				 GnomeKeyringRequestAccessCallback  callback,
				 gpointer                           data);
void     gnome_keyring_cancel_ask (gpointer                           request);

GList *                    gnome_keyring_access_request_list_copy (GList                     *list);
void                       gnome_keyring_access_request_list_free (GList                     *list);
void                       gnome_keyring_access_request_free      (GnomeKeyringAccessRequest *access_request);
GnomeKeyringAccessRequest *gnome_keyring_access_request_copy      (GnomeKeyringAccessRequest *access_request);

GList *                     gnome_keyring_acl_copy (GList *list);


GnomeKeyringApplicationRef *gnome_keyring_application_ref_new_from_pid (pid_t                             pid);
GnomeKeyringApplicationRef *gnome_keyring_application_ref_copy         (const GnomeKeyringApplicationRef *app);
void                        gnome_keyring_application_ref_free         (GnomeKeyringApplicationRef       *app);

void gnome_keyring_access_control_free (GnomeKeyringAccessControl *ac);
void                        gnome_keyring_acl_free                     (GList                            *acl);


void     cleanup_socket_dir   (void);
gboolean create_master_socket (const char **path);

void     set_default_keyring       (GkrKeyring *keyring);
void     update_keyrings_from_disk (void);

GnomeKeyringAttributeList *gnome_keyring_attributes_hash    (GnomeKeyringAttributeList        *attributes);
GnomeKeyringAccessControl *gnome_keyring_access_control_new (const GnomeKeyringApplicationRef *application,
							     GnomeKeyringAccessType            types_allowed);

GkrKeyring*    find_keyring            (const char           *name);

char *get_default_keyring_file_for_name (const char *keyring_name);
void gnome_keyring_client_fixup_for_removed (gpointer keyring, gpointer item);

void gkr_daemon_add_keyring (GkrKeyring *keyring);
void gkr_daemon_remove_keyring (GkrKeyring *keyring);

extern GList *keyrings;
extern GkrKeyring *session_keyring;
extern GkrKeyring *default_keyring;

/* Dbus Initialization/Cleanup */
#ifdef WITH_DBUS
void gnome_keyring_daemon_dbus_setup (GMainLoop *loop, const gchar* socket);
void gnome_keyring_daemon_dbus_cleanup (void);
#endif 

#endif /* GNOME_KEYRING_DAEMON_H */
