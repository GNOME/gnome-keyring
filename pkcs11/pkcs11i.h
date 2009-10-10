/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* pkcs11g.h - GNOME internal definitions to PKCS#11

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

#ifndef PKCS11I_H
#define PKCS11I_H

#include "pkcs11.h"
#include "pkcs11g.h"

/* Signifies that nobody is logged in */
#define CKU_NONE G_MAXULONG

#define CK_GNOME_MAX_SLOT                           (0x000000FFUL)
#define CK_GNOME_MAX_HANDLE                         (((CK_ULONG)-1UL) >> 10)

/* -------------------------------------------------------------------
 * OBJECT HASH
 */

#define CKA_GNOME_INTERNAL_SHA1                      (CKA_GNOME + 1000)


/* -------------------------------------------------------------------
 * APPLICATION
 */

/* Flag for CK_INFO when applications are supported */
#define CKF_G_APPLICATIONS                       0x40000000UL

/* Call C_OpenSession with this when passing CK_G_APPLICATION */
#define CKF_G_APPLICATION_SESSION                0x40000000UL

typedef CK_ULONG CK_G_APPLICATION_ID;

typedef struct CK_G_APPLICATION {
	CK_UTF8CHAR applicationName;
	CK_VOID_PTR applicationData;
	CK_FLAGS flags;
	CK_G_APPLICATION_ID applicationId;
} CK_G_APPLICATION;

typedef CK_G_APPLICATION* CK_G_APPLICATION_PTR;

#define CKR_G_APPLICATION_ID_INVALID             (CKR_GNOME + 10)

#endif /* PKCS11I_H */
