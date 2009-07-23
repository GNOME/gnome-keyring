/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *  
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef __GCK_SESSION_H__
#define __GCK_SESSION_H__

#include <glib-object.h>

#include "gck-module.h"
#include "gck-manager.h"

#define GCK_TYPE_SESSION               (gck_session_get_type ())
#define GCK_SESSION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCK_TYPE_SESSION, GckSession))
#define GCK_SESSION_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCK_TYPE_SESSION, GckSessionClass))
#define GCK_IS_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCK_TYPE_SESSION))
#define GCK_IS_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCK_TYPE_SESSION))
#define GCK_SESSION_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCK_TYPE_SESSION, GckSessionClass))

typedef struct _GckSessionClass GckSessionClass;
typedef struct _GckSessionPrivate GckSessionPrivate;
    
struct _GckSession {
	GObject parent;
	GckSessionPrivate *pv;
};

struct _GckSessionClass {
	GObjectClass parent_class;
    
#if 0
	/* signals --------------------------------------------------------- */
    
	void (*signal) (GckSession *session);
#endif
};

typedef gboolean         (*GckAuthenticatorFunc)                        (GckAuthenticator *auth,
                                                                         GckObject *object,
                                                                         gpointer user_data);

GType                    gck_session_get_type                           (void);

GckSession*              gck_session_for_session_object                 (GckObject *obj);

CK_SESSION_HANDLE        gck_session_get_handle                         (GckSession *self);

CK_SLOT_ID               gck_session_get_slot_id                        (GckSession *self);

CK_ULONG                 gck_session_get_apartment                      (GckSession *self);

GckModule*               gck_session_get_module                         (GckSession *self);

GckManager*              gck_session_get_manager                        (GckSession *self);

gboolean                 gck_session_get_read_only                      (GckSession *self);

gulong                   gck_session_get_logged_in                      (GckSession *self);

void                     gck_session_set_logged_in                      (GckSession *self,
                                                                         gulong logged_in);

CK_RV                    gck_session_lookup_readable_object             (GckSession *self, 
                                                                         CK_OBJECT_HANDLE handle, 
                                                                         GckObject **result);

CK_RV                    gck_session_lookup_writable_object             (GckSession *self, 
                                                                         CK_OBJECT_HANDLE handle, 
                                                                         GckObject **result);

CK_RV                    gck_session_login_context_specific             (GckSession *self,
                                                                         CK_UTF8CHAR_PTR pin,
                                                                         CK_ULONG n_pin);

void                     gck_session_destroy_session_object             (GckSession *self,
                                                                         GckTransaction *transaction,
                                                                         GckObject *obj);

gboolean                 gck_session_for_each_authenticator             (GckSession *self,
                                                                         GckObject *object,
                                                                         GckAuthenticatorFunc func,
                                                                         gpointer user_data);



CK_RV                    gck_session_C_GetFunctionStatus                (GckSession *self);

CK_RV                    gck_session_C_CancelFunction                   (GckSession *self);

CK_RV                    gck_session_C_GetSessionInfo                   (GckSession* self, 
                                                                         CK_SESSION_INFO_PTR info);

CK_RV                    gck_session_C_GetOperationState                (GckSession* self, 
                                                                         CK_BYTE_PTR operation_state,
                                                                         CK_ULONG_PTR operation_state_len);

CK_RV                    gck_session_C_SetOperationState                (GckSession* self, 
                                                                         CK_BYTE_PTR operation_state,
                                                                         CK_ULONG operation_state_len, 
                                                                         CK_OBJECT_HANDLE encryption_key,
                                                                         CK_OBJECT_HANDLE authentication_key);

CK_RV                    gck_session_C_CreateObject                     (GckSession* self, 
                                                                         CK_ATTRIBUTE_PTR template,
                                                                         CK_ULONG count, 
                                                                         CK_OBJECT_HANDLE_PTR new_object);

CK_RV                    gck_session_C_CopyObject                       (GckSession* self, 
                                                                         CK_OBJECT_HANDLE object,
                                                                         CK_ATTRIBUTE_PTR template, 
                                                                         CK_ULONG count,
                                                                         CK_OBJECT_HANDLE_PTR new_object);

CK_RV                    gck_session_C_DestroyObject                    (GckSession* self, 
                                                                         CK_OBJECT_HANDLE object);

CK_RV                    gck_session_C_GetObjectSize                    (GckSession* self, 
                                                                         CK_OBJECT_HANDLE object,
                                                                         CK_ULONG_PTR size);

CK_RV                    gck_session_C_GetAttributeValue                (GckSession* self, 
                                                                         CK_OBJECT_HANDLE handle, 
                                                                         CK_ATTRIBUTE_PTR template, 
                                                                         CK_ULONG count);

CK_RV                    gck_session_C_SetAttributeValue                (GckSession* self, 
                                                                         CK_OBJECT_HANDLE handle, 
                                                                         CK_ATTRIBUTE_PTR template, 
                                                                         CK_ULONG count);

CK_RV                    gck_session_C_FindObjectsInit                  (GckSession* self, 
                                                                         CK_ATTRIBUTE_PTR template,
                                                                         CK_ULONG count);

CK_RV                    gck_session_C_FindObjects                      (GckSession* self, 
                                                                         CK_OBJECT_HANDLE_PTR objects,
                                                                         CK_ULONG max_count, 
                                                                         CK_ULONG_PTR count);

CK_RV                    gck_session_C_FindObjectsFinal                 (GckSession* self);

CK_RV                    gck_session_C_EncryptInit                      (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_Encrypt                          (GckSession *self, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG data_len,
                                                                         CK_BYTE_PTR encrypted_data, 
                                                                         CK_ULONG_PTR encrypted_data_len);

CK_RV                    gck_session_C_EncryptUpdate                    (GckSession *self, 
                                                                         CK_BYTE_PTR part,
                                                                         CK_ULONG part_len, 
                                                                         CK_BYTE_PTR encrypted_part,
                                                                         CK_ULONG_PTR encrypted_part_len);

CK_RV                    gck_session_C_EncryptFinal                     (GckSession *self, 
                                                                         CK_BYTE_PTR last_part,
                                                                         CK_ULONG_PTR last_part_len);

CK_RV                    gck_session_C_DecryptInit                      (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_Decrypt                          (GckSession *self, 
                                                                         CK_BYTE_PTR enc_data,
                                                                         CK_ULONG enc_data_len, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG_PTR data_len);

CK_RV                    gck_session_C_DecryptUpdate                    (GckSession *self, 
                                                                         CK_BYTE_PTR enc_part,
                                                                         CK_ULONG enc_part_len, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG_PTR part_len);

CK_RV                    gck_session_C_DecryptFinal                     (GckSession *self, 
                                                                         CK_BYTE_PTR last_part,
                                                                         CK_ULONG_PTR last_part_len);

CK_RV                    gck_session_C_DigestInit                       (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism);

CK_RV                    gck_session_C_Digest                           (GckSession *self, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG data_len,
                                                                         CK_BYTE_PTR digest, 
                                                                         CK_ULONG_PTR digest_len);

CK_RV                    gck_session_C_DigestUpdate                     (GckSession *self, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG part_len);

CK_RV                    gck_session_C_DigestKey                        (GckSession *self, 
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_DigestFinal                      (GckSession *self, 
                                                                         CK_BYTE_PTR digest,
                                                                         CK_ULONG_PTR digest_len);

CK_RV                    gck_session_C_SignInit                         (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism, 
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_Sign                             (GckSession *self, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG data_len,
                                                                         CK_BYTE_PTR signature, 
                                                                         CK_ULONG_PTR signature_len);

CK_RV                    gck_session_C_SignUpdate                       (GckSession *self, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG part_len);

CK_RV                    gck_session_C_SignFinal                        (GckSession *self, 
                                                                         CK_BYTE_PTR signature,
                                                                         CK_ULONG_PTR signature_len);

CK_RV                    gck_session_C_SignRecoverInit                  (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_SignRecover                      (GckSession *self, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG data_len, 
                                                                         CK_BYTE_PTR signature, 
                                                                         CK_ULONG_PTR signature_len);

CK_RV                    gck_session_C_VerifyInit                       (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_Verify                           (GckSession *self, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG data_len,
                                                                         CK_BYTE_PTR signature, 
                                                                         CK_ULONG signature_len);

CK_RV                    gck_session_C_VerifyUpdate                     (GckSession *self, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG part_len);

CK_RV                    gck_session_C_VerifyFinal                      (GckSession *self, 
                                                                         CK_BYTE_PTR signature,
                                                                         CK_ULONG signature_len);

CK_RV                    gck_session_C_VerifyRecoverInit                (GckSession *self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE key);

CK_RV                    gck_session_C_VerifyRecover                    (GckSession *self, 
                                                                         CK_BYTE_PTR signature,
                                                                         CK_ULONG signature_len, 
                                                                         CK_BYTE_PTR data, 
                                                                         CK_ULONG_PTR data_len);

CK_RV                    gck_session_C_DigestEncryptUpdate              (GckSession *self, 
                                                                         CK_BYTE_PTR part,
                                                                         CK_ULONG part_len, 
                                                                         CK_BYTE_PTR enc_part,
                                                                         CK_ULONG_PTR enc_part_len);

CK_RV                    gck_session_C_DecryptDigestUpdate              (GckSession *self, 
                                                                         CK_BYTE_PTR enc_part,
                                                                         CK_ULONG enc_part_len, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG_PTR part_len);

CK_RV                    gck_session_C_SignEncryptUpdate                (GckSession *self, 
                                                                         CK_BYTE_PTR part,
                                                                         CK_ULONG part_len, 
                                                                         CK_BYTE_PTR enc_part,
                                                                         CK_ULONG_PTR enc_part_len);

CK_RV                    gck_session_C_DecryptVerifyUpdate              (GckSession *self, 
                                                                         CK_BYTE_PTR enc_part,
                                                                         CK_ULONG enc_part_len, 
                                                                         CK_BYTE_PTR part, 
                                                                         CK_ULONG_PTR part_len);

CK_RV                    gck_session_C_GenerateKey                      (GckSession* self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_ATTRIBUTE_PTR template, 
                                                                         CK_ULONG count, 
                                                                         CK_OBJECT_HANDLE_PTR key);

CK_RV                    gck_session_C_GenerateKeyPair                  (GckSession* self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_ATTRIBUTE_PTR pub_template, 
                                                                         CK_ULONG pub_count,
                                                                         CK_ATTRIBUTE_PTR priv_template, 
                                                                         CK_ULONG priv_count,
                                                                         CK_OBJECT_HANDLE_PTR pub_key, 
                                                                         CK_OBJECT_HANDLE_PTR priv_key);

CK_RV                    gck_session_C_WrapKey                          (GckSession* self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE wrapping_key, 
                                                                         CK_OBJECT_HANDLE key,
                                                                         CK_BYTE_PTR wrapped_key, 
                                                                         CK_ULONG_PTR wrapped_key_len);

CK_RV                    gck_session_C_UnwrapKey                        (GckSession* self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE unwrapping_key, 
                                                                         CK_BYTE_PTR wrapped_key,
                                                                         CK_ULONG wrapped_key_len, 
                                                                         CK_ATTRIBUTE_PTR template,
                                                                         CK_ULONG count, 
                                                                         CK_OBJECT_HANDLE_PTR key);

CK_RV                    gck_session_C_DeriveKey                        (GckSession* self, 
                                                                         CK_MECHANISM_PTR mechanism,
                                                                         CK_OBJECT_HANDLE base_key, 
                                                                         CK_ATTRIBUTE_PTR template,
                                                                         CK_ULONG count, 
                                                                         CK_OBJECT_HANDLE_PTR key);

CK_RV                    gck_session_C_SeedRandom                       (GckSession* self, 
                                                                         CK_BYTE_PTR seed, 
                                                                         CK_ULONG seed_len);

CK_RV                    gck_session_C_GenerateRandom                   (GckSession* self, 
                                                                         CK_BYTE_PTR random_data,
                                                                         CK_ULONG random_len);

#endif /* __GCK_SESSION_H__ */
