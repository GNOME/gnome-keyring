/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyrings-login.h - get secrets to automatically unlock keyrings or keys

   Copyright (C) 2007 Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRKEYRINGSAUTOUNLOCK_H_
#define GKRKEYRINGSAUTOUNLOCK_H_

#include "library/gnome-keyring.h"

gboolean        gkr_keyring_login_is_unlocked    (void);

gboolean        gkr_keyring_login_is_usable      (void);

gboolean        gkr_keyring_login_unlock         (const gchar *secret);

void            gkr_keyring_login_lock           (void);

const gchar*    gkr_keyring_login_master         (void);

void            gkr_keyring_login_attach_secret  (GnomeKeyringItemType type, 
                                                  const gchar *display_name, 
                                                  const gchar *secret,
                                                  ...);

const gchar*    gkr_keyring_login_lookup_secret  (GnomeKeyringItemType type,
                                                  ...);
                                                 
void            gkr_keyring_login_remove_secret  (GnomeKeyringItemType type,
                                                  ...);

#endif /*GKRKEYRINGSAUTOUNLOCK_H_*/
