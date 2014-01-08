/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-armor.h - Armor routines

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef EGG_ARMOR_H_
#define EGG_ARMOR_H_

#include <glib.h>

typedef void (*EggArmorCallback) (GQuark type,
                                  GBytes *data,
                                  GBytes *outer,
                                  GHashTable *headers,
                                  gpointer user_data);

GHashTable*      egg_armor_headers_new   (void);

guint            egg_armor_parse         (GBytes *data,
                                          EggArmorCallback callback,
                                          gpointer user_data);

guchar*          egg_armor_write         (const guchar *data,
                                          gsize n_data,
                                          GQuark type,
                                          GHashTable *headers,
                                          gsize *n_result);

#endif /* EGG_ARMOR_H_ */
