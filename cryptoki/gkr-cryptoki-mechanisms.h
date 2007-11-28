/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-mechanisms.h - the PKCS#11 mechanisms we support

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

#ifndef CRYPTOKI_MECHANISMS_H
#define CRYPTOKI_MECHANISMS_H

/* 
 * IMPORTANT: Keep these two arrays in sync.
 */
 
const static CK_MECHANISM_TYPE gkr_cryptoki_mechanisms[] = {
	/* TODO: CKM_RSA_PKCS_KEY_PAIR_GEN, */
	CKM_RSA_PKCS
};

const static CK_MECHANISM_INFO gkr_cryptoki_mechanism_info[] = {
	/* TODO: CKM_RSA_PKCS_KEY_PAIR_GEN, */
	/* 
	 * CKM_RSA_PKCS
	 * For RSA, min and max are the minimum and maximum modulus in bits 
	 */
	/* TODO: Vet the numbers min/max key leng below.  */
	{256, 32768, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP}
};

#endif /* CRYPTOKI_MECHANISMS_H */
