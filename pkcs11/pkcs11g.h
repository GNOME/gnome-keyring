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

#define CKA_GNOME (CKA_VENDOR_DEFINED | 0x474E4D45 /* GNME */ ) 

#define CKT_GNOME_UNKNOWN   0
#define CKT_GNOME_UNTRUSTED 1
#define CKT_GNOME_TRUSTED   2

/*
 * 
 * CK_ULONG
 * 
 *  - CKT_GNOME_TRUSTED 
 *  - CKT_GNOME_UNTRUSTED
 *  - CKT_GNOME_UNKNOWN
 */
#define CKA_GNOME_USER_TRUST                     (CKA_GNOME + 10)

/*
 * Whether the key or certificate is restricted to a set of 
 * purposes (ie: enhanced usages). 
 * 
 * CK_BBOOL
 * 
 *  - When CK_TRUE see CKA_PURPOSE_OIDS for the set of purposes.
 *  - When CK_FALSE then is not restricted to any specific purpose. 
 */
#define CKA_GNOME_PURPOSE_RESTRICTED             (CKA_GNOME + 12)

/*
 * The available purposes that a certificate or key can be 
 * used for. 
 * 
 * CK_STRING 
 * 
 *  - This is only relevant if CKA_PURPOSE_RESTRICTED is CK_TRUE.
 *  - Use CKA_TRUSTED and CKA_CERTIFICATE_CATEGORY to validate whether
 *    usage of the certificate for these purposes is directly or 
 *    indirectly trusted by the user.
 *  - The returned string is a space delemited set of OIDs. 
 *  - When an empty string is returned then no purposes are valid.
 */
#define CKA_GNOME_PURPOSE_OIDS                   (CKA_GNOME + 11) 

/* 
 * The key or certificate can be used for the purpose 
 * indicated
 * 
 * CK_BBOOL 
 * 
 *  - These are shortcuts to using CKA_PURPOSE_OIDS
 *  - Use CKA_TRUSTED and CKA_CERTIFICATE_CATEGORY to validate whether
 *    the certificate is directly or indirectly trusted by the user.
 */
#define CKA_GNOME_PURPOSE_SSH_AUTH               (CKA_GNOME + 101)
#define CKA_GNOME_PURPOSE_SERVER_AUTH            (CKA_GNOME + 102)
#define CKA_GNOME_PURPOSE_CLIENT_AUTH            (CKA_GNOME + 103)
#define CKA_GNOME_PURPOSE_CODE_SIGNING           (CKA_GNOME + 104)
#define CKA_GNOME_PURPOSE_EMAIL_PROTECTION       (CKA_GNOME + 105)
#define CKA_GNOME_PURPOSE_IPSEC_END_SYSTEM       (CKA_GNOME + 106)
#define CKA_GNOME_PURPOSE_IPSEC_TUNNEL           (CKA_GNOME + 107)
#define CKA_GNOME_PURPOSE_IPSEC_USER             (CKA_GNOME + 108)
#define CKA_GNOME_PURPOSE_TIME_STAMPING          (CKA_GNOME + 109)

#endif /* PKCS11G_H */
