/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* pkcs11g.h - GNOME extensions to PKCS#11

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

#ifndef PKCS11G_H
#define PKCS11G_H

#include "pkcs11.h"

#define GKR_VENDOR_GNOME 0x474E4D45 /* GNME */

#define CKA_GNOME (CKA_VENDOR_DEFINED | GKR_VENDOR_GNOME)

/* A key or certificate can be used for SSH authentication (CK_BBOOL) */
#define CKA_PURPOSE_SSH_AUTHENTICATION     (CKA_GNOME + 10)

#endif /* PKCS11G_H */
