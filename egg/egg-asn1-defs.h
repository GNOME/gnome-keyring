/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-asn1-defs.h - ASN.1 definitions

   Copyright (C) 2010 Stefan Walter

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef EGG_ASN1_DEFS_H_
#define EGG_ASN1_DEFS_H_

struct _EggAsn1xDef {
	const char *name;
	unsigned int type;
	const void *value;
};

extern const struct _EggAsn1xDef pkix_asn1_tab[];
extern const struct _EggAsn1xDef pk_asn1_tab[];

#endif /* EGG_ASN1_DEFS_H_ */
