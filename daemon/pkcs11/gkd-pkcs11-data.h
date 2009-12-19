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

#ifndef GKD_PKCS11_DATA_H_
#define GKD_PKCS11_DATA_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

void                            gkd_pkcs11_data_initialized              (void);

void                            gkd_pkcs11_data_session_opened           (CK_SLOT_ID slot_id,
                                                                          CK_SESSION_HANDLE handle);

void                            gkd_pkcs11_data_session_closed           (CK_SLOT_ID slot_id,
                                                                          CK_SESSION_HANDLE handle);

void                            gkd_pkcs11_data_session_closed_all       (CK_SLOT_ID slot);

void                            gkd_pkcs11_data_finalized                (void);

void                            gkd_pkcs11_data_session_store            (CK_SLOT_ID slot_id,
                                                                          CK_SESSION_HANDLE handle,
                                                                          gpointer data,
                                                                          GDestroyNotify destroy_func);

gpointer                        gkd_pkcs11_data_session_lookup            (CK_SLOT_ID slot_id,
                                                                           CK_SESSION_HANDLE handle);

void                            gkd_pkcs11_data_session_remove            (CK_SLOT_ID slot_id,
                                                                           CK_SESSION_HANDLE handle);

#endif /* GKD_PKCS11_DATA_H_ */
