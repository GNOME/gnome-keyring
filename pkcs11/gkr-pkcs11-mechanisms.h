/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-mechanisms.h - the PKCS#11 mechanisms we support

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

   Author: Stef Walter <nielsen@memberwebs.com>
*/

#ifndef GKR_PKCS11_MECHANISMS_H
#define GKR_PKCS11_MECHANISMS_H

/* 
 * IMPORTANT: Keep these two arrays in sync.
 */
 
const static CK_MECHANISM_TYPE gkr_pkcs11_mechanisms[] = {
	CKM_RSA_PKCS,
	CKM_RSA_X_509,
	CKM_DSA
};

const static CK_MECHANISM_INFO gkr_pkcs11_mechanism_info[] = {
	/* 
	 * CKM_RSA_PKCS
	 * For RSA, min and max are the minimum and maximum modulus in bits
	 * TODO: CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER 
	 */
	{ 256, 32768, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_HW },

	/* 
	 * CKM_RSA_X509
	 * For RSA, min and max are the minimum and maximum modulus in bits
	 * TODO: CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER 
	 */
	{ 256, 32768, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_HW },
	
	/*
	 * CKM_DSA
	 * For DSA, min and max are the minimum and maximum modulus in bits
	 */
	{ 512, 1024, CKF_SIGN | CKF_VERIFY | CKF_HW }
};

#endif /* GKR_PKCS11_MECHANISMS_H */
