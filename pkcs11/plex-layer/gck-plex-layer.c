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

#include "config.h"

#include "gck-plex-layer.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11i.h"

#include <glib.h>

#include <string.h>

typedef struct _Mapping {
	CK_SLOT_ID plex_slot;
	CK_SLOT_ID real_slot;
	CK_FUNCTION_LIST_PTR funcs;
} Mapping;

G_LOCK_DEFINE_STATIC (plex_layer);

static GList *plex_modules = NULL;
static Mapping *plex_mappings = NULL;
static guint n_plex_mappings = 0;

#define MANUFACTURER_ID         "GNOME Keyring                   "
#define LIBRARY_DESCRIPTION     "GNOME Keyring Daemon Core       "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1

/* Start plex slots slightly higher for testing */
#define PLEX_MAPPING_OFFSET 0x10

#define HANDLE_SLOT_BITS ((sizeof (CK_ULONG) * 8) - 10)
#define HANDLE_REAL_MASK (((CK_ULONG)-1) >> 10) 


static gboolean
map_slot_down (CK_SLOT_ID_PTR slot, Mapping *mapping)
{
	CK_SLOT_ID id = *slot;
	gboolean ret = TRUE;

	if (id < PLEX_MAPPING_OFFSET)
		return FALSE;
	id -= PLEX_MAPPING_OFFSET;
	
	g_assert (mapping);
	
	G_LOCK (plex_layer);
	
		if (id > n_plex_mappings) {
			ret = FALSE;
		} else {
			memcpy (mapping, &plex_mappings[id], sizeof (Mapping));
			*slot = mapping->real_slot;
		}

	G_UNLOCK (plex_layer);

	return ret;
}

#define MAP_SLOT_UP(slot, map) G_STMT_START { \
	


#define MAP_SLOT_DOWN(slot, map) G_STMT_START { \
	if (!map_slot_down (&slot, &map)) \
		return CKR_SLOT_ID_INVALID; \
	} G_STMT_END

#define MAP_SESSION_UP(map, session) G_STMT_START { \
	g_return_val_if_fail ((session) < CK_GNOME_MAX_HANDLE, CKR_GENERAL_ERROR); \
	session = ((session) | ((map.plex_slot) << HANDLE_SLOT_BITS)); \
	} G_STMT_END

#define MAP_SESSION_DOWN(session, map) G_STMT_START { \
	CK_SLOT_ID slot = (session >> HANDLE_SLOT_BITS); \
	if (!map_slot_down (&slot, &map)) \
		return CKR_SESSION_HANDLE_INVALID; \
	session &= HANDLE_REAL_MASK; \
	} G_STMT_END 

static CK_RV
plex_C_Initialize (CK_VOID_PTR init_args)
{
	CK_FUNCTION_LIST_PTR funcs;
	GArray *mappings = NULL;
	CK_SLOT_ID_PTR slots;
	Mapping mapping;
	CK_ULONG i, count;
	CK_RV rv = CKR_OK;
	GList *l;
	
	mappings = g_array_new (FALSE, TRUE, sizeof (Mapping));
	
	G_LOCK (plex_layer);
	
		if (plex_mappings)
			rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
	
		for (l = plex_modules; rv == CKR_OK && l != NULL; l = g_list_next (l)) {
			funcs = l->data;
			
			/* Initialize each module */
			rv = (funcs->C_Initialize) (init_args);
			if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
				rv = CKR_OK;
			if (rv != CKR_OK)
				break;
			
			/* And then ask it for its slots */
			rv = (funcs->C_GetSlotList) (FALSE, NULL, &count);
			if (rv != CKR_OK)
				break;
			if (!count)
				continue;
			slots = g_new0 (CK_SLOT_ID, count);
			rv = (funcs->C_GetSlotList) (FALSE, slots, &count);
			if (rv != CKR_OK) {
				 g_free (slots);
				 break;
			}
			
			/* And now add a mapping for each of those slots */
			for (i = 0; i < count; ++i) {
				memset (&mapping, 0, sizeof (mapping));
				mapping.plex_slot = mappings->len + PLEX_MAPPING_OFFSET;
				mapping.real_slot = slots[i];
				mapping.funcs = funcs;
				g_array_append_val (mappings, mapping);
			}
			
			g_free (slots);
		}
		
		/* If failed, then finalize all the ones that succeeded */
		if (rv != CKR_OK && l != NULL) {
			for (l = g_list_previous (l); l; l = g_list_previous (l)) {
				funcs = l->data;
				(funcs->C_Finalize) (NULL);
			}
		}
		
		/* If succeeded then swap in mappings */
		if (rv == CKR_OK) {
			g_assert (!plex_mappings);
			n_plex_mappings = mappings->len;
			plex_mappings = (Mapping*)g_array_free (mappings, FALSE);
			mappings = NULL;
		}
	
	G_UNLOCK (plex_layer);
	
	/* If failed or somehow unused then free */
	if (mappings) 
		g_array_free (mappings, TRUE);
	
	return rv;
}

static CK_RV
plex_C_Finalize (CK_VOID_PTR reserved)
{
	guint i;
	
	G_LOCK (plex_layer);

		for (i = 0; i < n_plex_mappings; ++i)
			(plex_mappings[i].funcs->C_Finalize) (NULL);
		g_free (plex_mappings);
		plex_mappings = NULL;
	
	G_UNLOCK (plex_layer);
	
	return CKR_OK;
}

static CK_RV
plex_C_GetInfo (CK_INFO_PTR info)
{
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	
	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy ((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);
	return CKR_OK;
}

static CK_RV
plex_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	if (!list)
		return CKR_ARGUMENTS_BAD;
	*list = gck_plex_layer_get_functions ();
	return CKR_OK;
}

static CK_RV
plex_C_GetSlotList (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	CK_SLOT_INFO info;
	Mapping *mapping;
	CK_ULONG index;
	CK_RV rv;
	
	guint i;
	
	if (!count)
		return CKR_ARGUMENTS_BAD;
	
	G_LOCK (plex_layer);

		rv = CKR_OK;
		index = 0;

		/* Go through and build up a map */
		for (i = 0; i < n_plex_mappings; ++i) {
			mapping = &plex_mappings[i];
		
			/* Skip ones without a token if requested */
			if (token_present) {
				rv = (mapping->funcs->C_GetSlotInfo) (mapping->real_slot, &info);
				if (rv != CKR_OK)
					break;
				if (!(info.flags & CKF_TOKEN_PRESENT))
					continue;
			}
		
			/* Fill in the slot if we can */
			if (slot_list && *count > index)
				slot_list[index] = mapping->plex_slot;
			
			++index;
		}
		
		if (slot_list && *count < index)
			rv = CKR_BUFFER_TOO_SMALL;

		*count = index;
		
	G_UNLOCK (plex_layer);
	
	return rv;
}

static CK_RV
plex_C_GetSlotInfo (CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	Mapping map;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_GetSlotInfo) (id, info);
}

static CK_RV
plex_C_GetTokenInfo (CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	Mapping map;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_GetTokenInfo) (id, info);
}

static CK_RV
plex_C_GetMechanismList (CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list, CK_ULONG_PTR count)
{
	Mapping map;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_GetMechanismList) (id, mechanism_list, count);
}

static CK_RV
plex_C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
	Mapping map;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_GetMechanismInfo) (id, type, info);
}

static CK_RV
plex_C_InitToken (CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	Mapping map;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_InitToken) (id, pin, pin_len, label);
}

static CK_RV
plex_C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved)
{
	/* TODO: We could implement this by polling, esp. the nonblock case. */
	return CKR_NO_EVENT;
}

static CK_RV
plex_C_OpenSession (CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data, CK_NOTIFY callback, CK_SESSION_HANDLE_PTR handle)
{
	Mapping map;
	CK_RV rv;
	
	if (handle == NULL)
		return CKR_ARGUMENTS_BAD;
	
	MAP_SLOT_DOWN (id, map);
	rv = (map.funcs->C_OpenSession) (id, flags, user_data, callback, handle);
	if (rv == CKR_OK)
		MAP_SESSION_UP (map, *handle);
	
	return rv;
}

static CK_RV
plex_C_CloseSession (CK_SESSION_HANDLE handle)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_CloseSession) (handle);
}

static CK_RV
plex_C_CloseAllSessions (CK_SLOT_ID id)
{
	Mapping map;
	CK_G_APPLICATION_ID app = id & ~CK_GNOME_MAX_SLOT;
	id = id & CK_GNOME_MAX_SLOT;
	MAP_SLOT_DOWN (id, map);
	return (map.funcs->C_CloseAllSessions) (id | app);
}

static CK_RV
plex_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GetFunctionStatus) (handle);
}

static CK_RV
plex_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_CancelFunction) (handle);
}

static CK_RV
plex_C_GetSessionInfo (CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;
	
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;
	
	MAP_SESSION_DOWN (handle, map);
	rv = (map.funcs->C_GetSessionInfo) (handle, info);
	if (rv == CKR_OK)
		info->slotID = map.plex_slot;
	
	return rv;
}

static CK_RV
plex_C_InitPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_InitPIN) (handle, pin, pin_len);
}

static CK_RV
plex_C_SetPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_pin_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SetPIN) (handle, old_pin, old_pin_len, new_pin, new_pin_len);
}

static CK_RV
plex_C_GetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GetOperationState) (handle, operation_state, operation_state_len);
}

static CK_RV
plex_C_SetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state,
                          CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                          CK_OBJECT_HANDLE authentication_key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SetOperationState) (handle, operation_state, operation_state_len, encryption_key, authentication_key);
}

static CK_RV
plex_C_Login (CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
              CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Login) (handle, user_type, pin, pin_len);
}

static CK_RV
plex_C_Logout (CK_SESSION_HANDLE handle)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Logout) (handle);
}

static CK_RV
plex_C_CreateObject (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                     CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_CreateObject) (handle, template, count, new_object);
}

static CK_RV
plex_C_CopyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                   CK_ATTRIBUTE_PTR template, CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_CopyObject) (handle, object, template, count, new_object);
}

static CK_RV
plex_C_DestroyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DestroyObject) (handle, object);
}

static CK_RV
plex_C_GetObjectSize (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                      CK_ULONG_PTR size)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GetObjectSize) (handle, object, size);
}

static CK_RV
plex_C_GetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GetAttributeValue) (handle, object, template, count);
}

static CK_RV
plex_C_SetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SetAttributeValue) (handle, object, template, count);
}

static CK_RV
plex_C_FindObjectsInit (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                        CK_ULONG count)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_FindObjectsInit) (handle, template, count);
}

static CK_RV
plex_C_FindObjects (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR objects,
                    CK_ULONG max_count, CK_ULONG_PTR count)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_FindObjects) (handle, objects, max_count, count);
}

static CK_RV
plex_C_FindObjectsFinal (CK_SESSION_HANDLE handle)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_FindObjectsFinal) (handle);
}

static CK_RV
plex_C_EncryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_EncryptInit) (handle, mechanism, key);
}

static CK_RV
plex_C_Encrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Encrypt) (handle, data, data_len, encrypted_data, encrypted_data_len);
}

static CK_RV
plex_C_EncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                      CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                      CK_ULONG_PTR encrypted_part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
}

static CK_RV
plex_C_EncryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                     CK_ULONG_PTR last_part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_EncryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
plex_C_DecryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DecryptInit) (handle, mechanism, key);
}

static CK_RV
plex_C_Decrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_data,
                CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Decrypt) (handle, enc_data, enc_data_len, data, data_len);
}

static CK_RV
plex_C_DecryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                     CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
plex_C_DecryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                     CK_ULONG_PTR last_part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DecryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
plex_C_DigestInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DigestInit) (handle, mechanism);
}

static CK_RV
plex_C_Digest (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
               CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Digest) (handle, data, data_len, digest, digest_len);
}

static CK_RV
plex_C_DigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DigestUpdate) (handle, part, part_len);
}

static CK_RV
plex_C_DigestKey (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DigestKey) (handle, key);
}

static CK_RV
plex_C_DigestFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR digest,
                    CK_ULONG_PTR digest_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DigestFinal) (handle, digest, digest_len);
}

static CK_RV
plex_C_SignInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignInit) (handle, mechanism, key);
}

static CK_RV
plex_C_Sign (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
             CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Sign) (handle, data, data_len, signature, signature_len);
}

static CK_RV
plex_C_SignUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignUpdate) (handle, part, part_len);
}

static CK_RV
plex_C_SignFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                  CK_ULONG_PTR signature_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignFinal) (handle, signature, signature_len);
}

static CK_RV
plex_C_SignRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignRecoverInit) (handle, mechanism, key);
}

static CK_RV
plex_C_SignRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len, 
                    CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignRecover) (handle, data, data_len, signature, signature_len);
}

static CK_RV
plex_C_VerifyInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_VerifyInit) (handle, mechanism, key);
}

static CK_RV
plex_C_Verify (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
               CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_Verify) (handle, data, data_len, signature, signature_len);
}

static CK_RV
plex_C_VerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_VerifyUpdate) (handle, part, part_len);
}

static CK_RV
plex_C_VerifyFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                    CK_ULONG signature_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_VerifyFinal) (handle, signature, signature_len);
}

static CK_RV
plex_C_VerifyRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_VerifyRecoverInit) (handle, mechanism, key);
}

static CK_RV
plex_C_VerifyRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                     CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_VerifyRecover) (handle, signature, signature_len, data, data_len);
}

static CK_RV
plex_C_DigestEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                            CK_ULONG part_len, CK_BYTE_PTR enc_part,
                            CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
plex_C_DecryptDigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                            CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                            CK_ULONG_PTR part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
plex_C_SignEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                          CK_ULONG part_len, CK_BYTE_PTR enc_part,
                          CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
plex_C_DecryptVerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                            CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                            CK_ULONG_PTR part_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
plex_C_GenerateKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_ATTRIBUTE_PTR template, CK_ULONG count, 
                    CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GenerateKey) (handle, mechanism, template, count, key);
}

static CK_RV
plex_C_GenerateKeyPair (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                        CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                        CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                        CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GenerateKeyPair) (handle, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key);
}

static CK_RV
plex_C_WrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_WrapKey) (handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
}

static CK_RV
plex_C_UnwrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                  CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                  CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_UnwrapKey) (handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key);
}

static CK_RV
plex_C_DeriveKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                  CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_DeriveKey) (handle, mechanism, base_key, template, count, key);
}

static CK_RV
plex_C_SeedRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_SeedRandom) (handle, seed, seed_len);
}

static CK_RV
plex_C_GenerateRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR random_data,
                      CK_ULONG random_len)
{
	Mapping map;
	MAP_SESSION_DOWN (handle, map);
	return (map.funcs->C_GenerateRandom) (handle, random_data, random_len);
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

static CK_FUNCTION_LIST plex_function_list = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	plex_C_Initialize,
	plex_C_Finalize,
	plex_C_GetInfo,
	plex_C_GetFunctionList,
	plex_C_GetSlotList,
	plex_C_GetSlotInfo,
	plex_C_GetTokenInfo,
	plex_C_GetMechanismList,
	plex_C_GetMechanismInfo,
	plex_C_InitToken,
	plex_C_InitPIN,
	plex_C_SetPIN,
	plex_C_OpenSession,
	plex_C_CloseSession,
	plex_C_CloseAllSessions,
	plex_C_GetSessionInfo,
	plex_C_GetOperationState,
	plex_C_SetOperationState,
	plex_C_Login,
	plex_C_Logout,
	plex_C_CreateObject,
	plex_C_CopyObject,
	plex_C_DestroyObject,
	plex_C_GetObjectSize,
	plex_C_GetAttributeValue,
	plex_C_SetAttributeValue,
	plex_C_FindObjectsInit,
	plex_C_FindObjects,
	plex_C_FindObjectsFinal,
	plex_C_EncryptInit,
	plex_C_Encrypt,
	plex_C_EncryptUpdate,
	plex_C_EncryptFinal,
	plex_C_DecryptInit,
	plex_C_Decrypt,
	plex_C_DecryptUpdate,
	plex_C_DecryptFinal,
	plex_C_DigestInit,
	plex_C_Digest,
	plex_C_DigestUpdate,
	plex_C_DigestKey,
	plex_C_DigestFinal,
	plex_C_SignInit,
	plex_C_Sign,
	plex_C_SignUpdate,
	plex_C_SignFinal,
	plex_C_SignRecoverInit,
	plex_C_SignRecover,
	plex_C_VerifyInit,
	plex_C_Verify,
	plex_C_VerifyUpdate,
	plex_C_VerifyFinal,
	plex_C_VerifyRecoverInit,
	plex_C_VerifyRecover,
	plex_C_DigestEncryptUpdate,
	plex_C_DecryptDigestUpdate,
	plex_C_SignEncryptUpdate,
	plex_C_DecryptVerifyUpdate,
	plex_C_GenerateKey,
	plex_C_GenerateKeyPair,
	plex_C_WrapKey,
	plex_C_UnwrapKey,
	plex_C_DeriveKey,
	plex_C_SeedRandom,
	plex_C_GenerateRandom,
	plex_C_GetFunctionStatus,
	plex_C_CancelFunction,
	plex_C_WaitForSlotEvent
};

/* -----------------------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

CK_FUNCTION_LIST_PTR
gck_plex_layer_get_functions (void)
{
	return &plex_function_list;
}

void
gck_plex_layer_add_module (CK_FUNCTION_LIST_PTR funcs)
{
	g_assert (funcs);
	
	G_LOCK (plex_layer);
	
		plex_modules = g_list_append (plex_modules, funcs);
		
	G_UNLOCK (plex_layer);
}
