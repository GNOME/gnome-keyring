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

#define CKA_GNOME (CKA_VENDOR_DEFINED | 0x474E4D45 /* GNME */ ) 
#define CKO_GNOME (CKO_VENDOR_DEFINED | 0x474E4D45 /* GNME */ ) 


/* ----------------------------------------------------------------------
 * APARTMENT SLOTS
 * 
 * The lower 10 bits of the CK_SLOT_ID are used as the actual slot identifier, 
 * and the remainder are used as application identifiers.
 * 
 * This enables a single loaded module to serve multiple applications
 * concurrently. The caller of a module should check the 
 * CKF_GNOME_VIRTUAL_SLOTS flag before using this functionality.
 */

/* Flag for CK_INFO when virtual slots are supported */
#define CKF_GNOME_APPARTMENTS                       0x40000000

/* Get an actual slot id from a virtual slot */
#define CK_GNOME_APPARTMENT_SLOT(virt)              ((virt) & 0x000003FF)

/* Get an app id from a virtual slot */
#define CK_GNOME_APPARTMENT_APP(virt)               ((virt) >> 10)

/* Is the app id valid for use in a virtual slot? */
#define CK_GNOME_APPARTMENT_IS_APP(app)             ((app) < (((CK_ULONG)-1) >> 10))

/* Build a virtual slot from an actual slot id, and an app id */
#define CK_GNOME_MAKE_APPARTMENT(slot, app)         (((slot) & 0x000003FF) | ((app) << 10))


/* -------------------------------------------------------------------
 * LIMITED HANDLES
 * 
 * The upper 10 bits of a CK_SESSION_HANDLE and CK_OBJECT_HANDLE are 
 * never used by Gnome Keyring PKCS#11 modules. These bits are used 
 * for tracking purposes when combining modules into a single module.
 */ 

#define CK_GNOME_MAX_SLOT                           (0x000003FF)
#define CK_GNOME_MAX_APP                            (((CK_ULONG)-1) >> 10)
#define CK_GNOME_MAX_HANDLE                         (((CK_ULONG)-1) >> 10)


/* -------------------------------------------------------------------
 * OBJECT AUTHENTICATION 
 */

#define CKA_GNOME_AUTH_CACHE                        (CKA_GNOME + 300)
#define CKV_GNOME_AUTH_CACHE_NEVER                  ((CK_ULONG)-1)
#define CKV_GNOME_AUTH_CACHE_SESSION                0x40000000
#define CKV_GNOME_AUTH_CACHE_UNLIMITED              0x80000000

#define CKA_GNOME_AUTH_CACHED                       (CKA_GNOME + 301)

/* -------------------------------------------------------------------
 * OBJECT UNIQUE IDENTIFIER
 */

/* A string unique among all objects on a given machine */
#define CKA_GNOME_UNIQUE                            (CKA_GNOME + 350)


/* ----------------------------------------------------------------------
 * TODO: EXTENSIONS BELOW NEED TO BE INDIVIDUALLY CONSIDERED CAREFULLY
 */

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

/*
 * An import object used to, well, import data and create objects 
 * out of the imported data.
 * 
 * Attributes:
 *  - CKA_VALUE: The raw data to import
 *  - CKA_GNOME_IMPORT_TOKEN: Whether to import to token or session.
 *  - CKA_GNOME_IMPORT_OBJECTS: the objects that were imported
 *  - CKA_GNOME_IMPORT_LABEL: Label to be used in prompts, and set on the objects
 *    imported if they have no label.
 */
#define CKO_GNOME_IMPORT                         (CKO_GNOME + 200)

/* 
 * Whether to import to token or session.
 * 
 * CK_BBOOL
 */
#define CKA_GNOME_IMPORT_TOKEN                   (CKA_GNOME + 200)

/*
 * The objects that were imported. 
 * 
 * An array of CK_OBJECT_HANDLE. 
 * 
 * - The number of objects in the array is ulValueLen / sizeof (CK_OBJECT_HANDLE) 
 */
#define CKA_GNOME_IMPORT_OBJECTS                 (CKA_GNOME + 201)

/*
 * The label to be used in prompts and set on objects imported if they
 * have no label.
 * 
 * String
 */
#define CKA_GNOME_IMPORT_LABEL                   (CKA_GNOME + 202)

#endif /* PKCS11G_H */
