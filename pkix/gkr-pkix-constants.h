/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-constants.h - Constants from PK standards

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

#ifndef GKRPKIXCONSTANTS_H_
#define GKRPKIXCONSTANTS_H_

#define PKIX_KEY_USAGE_DIGITAL_SIGNATURE 0x80
#define PKIX_KEY_USAGE_NON_REPUDIATION 0x40
#define PKIX_KEY_USAGE_KEY_ENCIPHERMENT 0x20
#define PKIX_KEY_USAGE_DATA_ENCIPHERMENT 0x10
#define PKIX_KEY_USAGE_KEY_AGREEMENT 0x08
#define PKIX_KEY_USAGE_KEY_CERT_SIGN 0x04
#define PKIX_KEY_USAGE_CRL_SIGN 0x02
#define PKIX_KEY_USAGE_ENCIPHER_ONLY 0x01

#define PKIX_USAGE_SERVER_AUTH		"1.3.6.1.5.5.7.3.1"
#define PKIX_USAGE_CLIENT_AUTH		"1.3.6.1.5.5.7.3.2"	
#define PKIX_USAGE_CODE_SIGNING		"1.3.6.1.5.5.7.3.3"	
#define PKIX_USAGE_EMAIL		"1.3.6.1.5.5.7.3.4"	
#define PKIX_USAGE_TIME_STAMPING	"1.3.6.1.5.5.7.3.8"	
#define PKIX_USAGE_IPSEC_ENDPOINT	"1.3.6.1.5.5.7.3.5"	
#define PKIX_USAGE_IPSEC_TUNNEL		"1.3.6.1.5.5.7.3.6"	
#define PKIX_USAGE_IPSEC_USER		"1.3.6.1.5.5.7.3.7"	
#define PKIX_USAGE_IKE_INTERMEDIATE	"1.3.6.1.5.5.8.2.2"	

#endif /*GKRPKIXCONSTANTS_H_*/
