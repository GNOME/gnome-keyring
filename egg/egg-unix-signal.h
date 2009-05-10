/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-unix-signal.h - integrate unix signals into the main loop

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

#ifndef EGGUNIXSIGNAL_H_
#define EGGUNIXSIGNAL_H_

#include <glib.h>

typedef gboolean (*EggUnixSignalHandler)     (guint sig, gpointer user_data);

guint    egg_unix_signal_connect             (GMainContext *ctx, guint sig,
                                              EggUnixSignalHandler handler, gpointer user_data);

#endif /* EGGUNIXSIGNAL_H_ */
