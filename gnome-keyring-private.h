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

struct GnomeKeyringApplicationRef {
	char *display_name;
	char *pathname;
};

typedef enum {
	GNOME_KEYRING_ACCESS_READ = 1<<0,
	GNOME_KEYRING_ACCESS_WRITE = 1<<1,
	GNOME_KEYRING_ACCESS_REMOVE = 1<<2
} GnomeKeyringAccessType;

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

typedef enum {
	GNOME_KEYRING_ASK_RESPONSE_FAILURE,
	GNOME_KEYRING_ASK_RESPONSE_DENY,
	GNOME_KEYRING_ASK_RESPONSE_ALLOW_ONCE,
	GNOME_KEYRING_ASK_RESPONSE_ALLOW_FOREVER,
} GnomeKeyringAskResponse;


#endif /* GNOME_KEYRING_PRIVATE_H */
