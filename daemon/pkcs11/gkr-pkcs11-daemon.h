/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-daemon.h - entry points for daemon PKCS#11 functionality

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#ifndef __GKR_PKCS11_DAEMON_H__
#define __GKR_PKCS11_DAEMON_H__

/* -----------------------------------------------------------------------------
 * GENERAL FUNCTIONS 
 */
 
gboolean        gkr_pkcs11_daemon_setup               (void);

/* -----------------------------------------------------------------------------
 * Used by gkr-pkcs11-daemon.c and gkr-pkcs11-daemon-session.c 
 */

gpointer        gkr_pkcs11_daemon_session_thread      (gpointer user_data);

#endif /* __GKR_PKCS11_DAEMON_H__ */
