/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* pkcs11g.h - GNOME extensions to PKCS#11

   Copyright (C) 2008, Stef Walter

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

#ifndef PKCS11G_H
#define PKCS11G_H

#include "pkcs11.h"

#define CKA_GNOME   (CKA_VENDOR_DEFINED | 0x474E4D45UL /* GNME */ )
#define CKO_GNOME   (CKO_VENDOR_DEFINED | 0x474E4D45UL /* GNME */ )
#define CKR_GNOME   (CKR_VENDOR_DEFINED | 0x474E4D45UL /* GNME */ )
#define CKM_GNOME   (CKR_VENDOR_DEFINED | 0x474E4D45UL /* GNME */ )
#define CKK_GNOME   (CKR_VENDOR_DEFINED | 0x474E4D45UL /* GNME */ )

/* -------------------------------------------------------------------
 * OBJECT UNIQUE IDENTIFIER
 */

/* A string unique among all objects on a given machine */
#define CKA_GNOME_UNIQUE                            (CKA_GNOME + 350)

/* -------------------------------------------------------------------
 */

#define CKA_GNOME_TRANSIENT                      (CKA_GNOME + 201)

#endif /* PKCS11G_H */
