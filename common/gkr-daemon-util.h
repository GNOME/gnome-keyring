/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-daemon-util.h - Helper utilities for the daemon

   Copyright (C) 2007, Stefan Walter

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

#ifndef GKRMASTERDIRECTORY_H_
#define GKRMASTERDIRECTORY_H_

#include <glib.h>

const gchar*    gkr_daemon_util_get_master_directory    (void);

void            gkr_daemon_util_push_environment        (const gchar *name, const gchar *value);

const gchar**   gkr_daemon_util_get_environment         (void);

#endif /*GKRMASTERDIRECTORY_H_*/
