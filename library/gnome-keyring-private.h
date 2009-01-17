/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-private.h - private header for keyring

   Copyright (C) 2003 Red Hat, Inc

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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Alexander Larsson <alexl@redhat.com>
*/

#ifndef GNOME_KEYRING_PRIVATE_H
#define GNOME_KEYRING_PRIVATE_H

#include "gnome-keyring.h"
#include "gnome-keyring-proto.h"

struct GnomeKeyringApplicationRef {
	char *display_name;
	char *pathname;
};

struct GnomeKeyringAccessControl {
	GnomeKeyringApplicationRef *application; /* null for all */
	GnomeKeyringAccessType types_allowed;
};

struct GnomeKeyringInfo {
	gboolean lock_on_idle;
	guint32 lock_timeout;
	time_t mtime;
	time_t ctime;
	gboolean is_locked;
};

struct GnomeKeyringItemInfo {
	GnomeKeyringItemType type;
	char *display_name;
	char *secret;
	time_t mtime;
	time_t ctime;
};

#define GNOME_KEYRING_DAEMON_SERVICE    "org.gnome.keyring"
#define GNOME_KEYRING_DAEMON_PATH       "/org/gnome/keyring/daemon"
#define GNOME_KEYRING_DAEMON_INTERFACE  "org.gnome.keyring.Daemon"

int gnome_keyring_socket_connect_daemon (gboolean non_blocking, gboolean only_running);
int gnome_keyring_socket_read_all (int fd, guchar *buf, size_t len);
int gnome_keyring_socket_write_all (int fd, const guchar *buf, size_t len);
gboolean gnome_keyring_socket_read_buffer (int fd, EggBuffer *buffer);
gboolean gnome_keyring_socket_write_buffer (int fd, EggBuffer *buffer);

extern const gchar *GNOME_KEYRING_OUT_ENVIRONMENT[];
extern const gchar *GNOME_KEYRING_IN_ENVIRONMENT[];

gchar** gnome_keyring_build_environment (const gchar **names);
void gnome_keyring_apply_environment (gchar **envp);

void 	_gnome_keyring_memory_dump (void);
extern  gboolean gnome_keyring_memory_warning;
 
#endif /* GNOME_KEYRING_PRIVATE_H */

