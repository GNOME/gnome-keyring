/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef GCK_NULL_MECHANISM_H_
#define GCK_NULL_MECHANISM_H_

#include "gck-types.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11i.h"

#include <glib.h>

#define GCK_NULL_MECHANISM_MIN_LENGTH     0
#define GCK_NULL_MECHANISM_MAX_LENGTH     0

static const CK_MECHANISM_TYPE GCK_NULL_MECHANISMS[] = {
	CKM_G_NULL
};

CK_RV                   gck_null_mechanism_wrap                (GckSession *session,
                                                                CK_MECHANISM_PTR mech,
                                                                GckObject *wrapper,
                                                                GckObject *wrapped,
                                                                CK_BYTE_PTR output,
                                                                CK_ULONG_PTR n_output);

CK_RV                   gck_null_mechanism_unwrap              (GckSession *session,
                                                                CK_MECHANISM_PTR mech,
                                                                GckObject *wrapper,
                                                                CK_VOID_PTR input,
                                                                CK_ULONG n_input,
                                                                CK_ATTRIBUTE_PTR attrs,
                                                                CK_ULONG n_attrs,
                                                                GckObject **unwrapped);

#endif /* GCK_NULL_MECHANISM_H_ */
