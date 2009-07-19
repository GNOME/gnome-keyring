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

#ifndef GKR_PKCS11_AUTH_H_
#define GKR_PKCS11_AUTH_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

typedef struct _GkrPkcs11AuthObject {
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS klass;
	CK_SLOT_ID slot;
	CK_BBOOL token;
	gchar *label;
	gchar *unique;
	gchar *digest;
} GkrPkcs11AuthObject;

void                            gkr_pkcs11_auth_chain_functions          (CK_FUNCTION_LIST_PTR funcs); 

CK_FUNCTION_LIST_PTR            gkr_pkcs11_auth_get_functions            (void);

gboolean                        gkr_pkcs11_auth_login_user_prompt        (CK_SESSION_HANDLE handle,
                                                                          CK_TOKEN_INFO *info,
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len);

void                            gkr_pkcs11_auth_login_user_done          (CK_SESSION_HANDLE handle, 
                                                                          CK_TOKEN_INFO *info,
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len,
                                                                          CK_RV rv);

void                            gkr_pkcs11_auth_login_specific_prepare   (CK_SESSION_HANDLE handle,
                                                                          GkrPkcs11AuthObject *object);

CK_OBJECT_HANDLE                gkr_pkcs11_auth_login_specific_object    (CK_SESSION_HANDLE handle,
                                                                          CK_SESSION_INFO *info);

gboolean                        gkr_pkcs11_auth_login_specific_prompt    (CK_SESSION_HANDLE handle, 
                                                                          CK_SESSION_INFO *info,
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len);

void                            gkr_pkcs11_auth_login_specific_done      (CK_SESSION_HANDLE handle, 
                                                                          CK_SESSION_INFO *info,
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len,
                                                                          CK_RV rv);

gboolean                        gkr_pkcs11_auth_init_user_prompt         (CK_SESSION_HANDLE handle, 
                                                                          CK_TOKEN_INFO *token_info, 
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len);

void                            gkr_pkcs11_auth_init_user_done           (CK_SESSION_HANDLE handle, 
                                                                          CK_TOKEN_INFO *token_info, 
                                                                          CK_UTF8CHAR_PTR *pin, 
                                                                          CK_ULONG *pin_len,
                                                                          CK_RV rv);

void                            gkr_pkcs11_auth_initialized              (void);

void                            gkr_pkcs11_auth_session_opened           (CK_SESSION_HANDLE handle,
                                                                          CK_SESSION_INFO *info);

void                            gkr_pkcs11_auth_session_closed           (CK_SESSION_HANDLE handle,
                                                                          CK_SESSION_INFO *info);

void                            gkr_pkcs11_auth_session_closed_all       (CK_SLOT_ID slot);

void                            gkr_pkcs11_auth_finalized                (void);

void                            gkr_pkcs11_auth_free_object              (GkrPkcs11AuthObject *info);

#endif /* GKR_PKCS11_AUTH_H_ */
