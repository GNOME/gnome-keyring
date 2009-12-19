/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#ifndef GKD_PKCS11_AUTH_H_
#define GKD_PKCS11_AUTH_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

void                            gkd_pkcs11_auth_chain_functions          (CK_FUNCTION_LIST_PTR funcs);

CK_FUNCTION_LIST_PTR            gkd_pkcs11_auth_get_functions            (void);

#endif /* GKD_PKCS11_AUTH_H_ */
