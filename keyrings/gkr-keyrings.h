/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyrings.h - the global list of keyrings

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

#ifndef __GKR_KEYRINGS_H__
#define __GKR_KEYRINGS_H__

#include "gkr-keyring.h"

void            gkr_keyrings_update        (void);

GkrKeyring*     gkr_keyrings_get_default   (void);

void            gkr_keyrings_set_default   (GkrKeyring *keyring);

GkrKeyring*     gkr_keyrings_get_login     (void);

void            gkr_keyrings_add           (GkrKeyring *keyring);

void            gkr_keyrings_remove        (GkrKeyring *keyring);

GkrKeyring*     gkr_keyrings_find          (const gchar *name);

GkrKeyring*     gkr_keyrings_for_location  (GQuark location);

GkrKeyring*     gkr_keyrings_get_session   (void);

guint           gkr_keyrings_get_count     (void);

typedef gboolean (*GkrKeyringEnumFunc)     (GkrKeyring* keyring, gpointer data);
gboolean        gkr_keyrings_foreach       (GkrKeyringEnumFunc func, gpointer data);

#endif /* __GKR_KEYRINGS_H__ */

