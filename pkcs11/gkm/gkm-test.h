/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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

#include <glib.h>

#include "pkcs11/pkcs11.h"

#ifndef TESTMODULE_H_
#define TESTMODULE_H_

#define         gkm_assert_cmprv(v1, cmp, v2) \
		do { CK_RV __v1 = (v1), __v2 = (v2); \
			if (__v1 cmp __v2) ; else \
				gkm_assertion_message_cmprv (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, \
				                           #v1 " " #cmp " " #v2, __v1, #cmp, __v2); \
		} while (0)

void            gkm_assertion_message_cmprv        (const gchar *domain,
                                                    const gchar *file,
                                                    int line,
                                                    const gchar *func,
                                                    const gchar *expr,
                                                    CK_RV arg1,
                                                    const gchar *cmp,
                                                    CK_RV arg2);

CK_RV           gkm_test_C_Initialize              (CK_VOID_PTR pInitArgs);

CK_RV           gkm_test_C_Finalize                (CK_VOID_PTR pReserved);

CK_RV           gkm_test_C_GetInfo                 (CK_INFO_PTR pInfo);

CK_RV           gkm_test_C_GetFunctionList         (CK_FUNCTION_LIST_PTR_PTR list);

CK_RV           gkm_test_C_GetSlotList             (CK_BBOOL tokenPresent,
                                                    CK_SLOT_ID_PTR pSlotList,
                                                    CK_ULONG_PTR pulCount);

CK_RV           gkm_test_C_GetSlotInfo             (CK_SLOT_ID slotID,
                                                    CK_SLOT_INFO_PTR pInfo);

CK_RV           gkm_test_C_GetTokenInfo            (CK_SLOT_ID slotID,
                                                    CK_TOKEN_INFO_PTR pInfo);

CK_RV           gkm_test_C_GetMechanismList        (CK_SLOT_ID slotID,
                                                    CK_MECHANISM_TYPE_PTR pMechanismList,
                                                    CK_ULONG_PTR pulCount);

CK_RV           gkm_test_C_GetMechanismInfo        (CK_SLOT_ID slotID,
                                                    CK_MECHANISM_TYPE type,
                                                    CK_MECHANISM_INFO_PTR pInfo);

CK_RV           gkm_test_C_InitToken               (CK_SLOT_ID slotID,
                                                    CK_UTF8CHAR_PTR pPin,
                                                    CK_ULONG ulPinLen,
                                                    CK_UTF8CHAR_PTR pLabel);

CK_RV           gkm_test_C_WaitForSlotEvent        (CK_FLAGS flags,
                                                    CK_SLOT_ID_PTR pSlot,
                                                    CK_VOID_PTR pReserved);

CK_RV           gkm_test_C_OpenSession             (CK_SLOT_ID slotID,
                                                    CK_FLAGS flags,
                                                    CK_VOID_PTR pApplication,
                                                    CK_NOTIFY Notify,
                                                    CK_SESSION_HANDLE_PTR phSession);

CK_RV           gkm_test_C_CloseSession            (CK_SESSION_HANDLE hSession);

CK_RV           gkm_test_C_CloseAllSessions        (CK_SLOT_ID slotID);

CK_RV           gkm_test_C_GetFunctionStatus       (CK_SESSION_HANDLE hSession);

CK_RV           gkm_test_C_CancelFunction          (CK_SESSION_HANDLE hSession);

CK_RV           gkm_test_C_GetSessionInfo          (CK_SESSION_HANDLE hSession,
                                                    CK_SESSION_INFO_PTR pInfo);

CK_RV           gkm_test_C_InitPIN                 (CK_SESSION_HANDLE hSession,
                                                    CK_UTF8CHAR_PTR pPin,
                                                    CK_ULONG ulPinLen);

CK_RV           gkm_test_C_SetPIN                  (CK_SESSION_HANDLE hSession,
                                                    CK_UTF8CHAR_PTR pOldPin,
                                                    CK_ULONG ulOldLen,
                                                    CK_UTF8CHAR_PTR pNewPin,
                                                    CK_ULONG ulNewLen);

CK_RV           gkm_test_C_GetOperationState       (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pOperationState,
                                                    CK_ULONG_PTR pulOperationStateLen);

CK_RV           gkm_test_C_SetOperationState       (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pOperationState,
                                                    CK_ULONG ulOperationStateLen,
                                                    CK_OBJECT_HANDLE hEncryptionKey,
                                                    CK_OBJECT_HANDLE hAuthenticationKey);

CK_RV           gkm_test_C_Login                   (CK_SESSION_HANDLE hSession,
                                                    CK_USER_TYPE userType,
                                                    CK_UTF8CHAR_PTR pPin,
                                                    CK_ULONG pPinLen);

CK_RV           gkm_test_C_Logout                  (CK_SESSION_HANDLE hSession);

CK_RV           gkm_test_C_CreateObject            (CK_SESSION_HANDLE hSession,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount,
                                                    CK_OBJECT_HANDLE_PTR phObject);

CK_RV           gkm_test_C_CopyObject              (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount,
                                                    CK_OBJECT_HANDLE_PTR phNewObject);

CK_RV           gkm_test_C_DestroyObject           (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject);

CK_RV           gkm_test_C_GetObjectSize           (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject,
                                                    CK_ULONG_PTR pulSize);

CK_RV           gkm_test_C_GetAttributeValue       (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount);

CK_RV           gkm_test_C_SetAttributeValue       (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hObject,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount);

CK_RV           gkm_test_C_FindObjectsInit         (CK_SESSION_HANDLE hSession,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount);

CK_RV           gkm_test_C_FindObjects             (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE_PTR phObject,
                                                    CK_ULONG ulMaxObjectCount,
                                                    CK_ULONG_PTR pulObjectCount);

CK_RV           gkm_test_C_FindObjectsFinal        (CK_SESSION_HANDLE hSession);

CK_RV           gkm_test_C_EncryptInit             (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_Encrypt                 (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG ulDataLen,
                                                    CK_BYTE_PTR pEncryptedData,
                                                    CK_ULONG_PTR pulEncryptedDataLen);

CK_RV           gkm_test_C_EncryptUpdate           (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG_PTR pulEncryptedPartLen);

CK_RV           gkm_test_C_EncryptFinal            (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pLastEncryptedPart,
                                                    CK_ULONG_PTR pulLastEncryptedPartLen);

CK_RV           gkm_test_C_DecryptInit             (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_Decrypt                 (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pEncryptedData,
                                                    CK_ULONG ulEncryptedDataLen,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG_PTR pulDataLen);

CK_RV           gkm_test_C_DecryptUpdate           (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG ulEncryptedPartLen,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG_PTR pulPartLen);

CK_RV           gkm_test_C_DecryptFinal            (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pLastPart,
                                                    CK_ULONG_PTR pulLastPartLen);

CK_RV           gkm_test_C_DigestInit              (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism);

CK_RV           gkm_test_C_Digest                  (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG ulDataLen,
                                                    CK_BYTE_PTR pDigest,
                                                    CK_ULONG_PTR pulDigestLen);

CK_RV           gkm_test_C_DigestUpdate            (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen);

CK_RV           gkm_test_C_DigestKey               (CK_SESSION_HANDLE hSession,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_DigestFinal             (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pDigest,
                                                    CK_ULONG_PTR pulDigestLen);

CK_RV           gkm_test_C_SignInit                (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_Sign                    (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG ulDataLen,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG_PTR pulSignatureLen);

CK_RV           gkm_test_C_SignUpdate              (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen);

CK_RV           gkm_test_C_SignFinal               (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG_PTR pulSignatureLen);

CK_RV           gkm_test_C_SignRecoverInit         (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_SignRecover             (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG ulDataLen,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG_PTR pulSignatureLen);

CK_RV           gkm_test_C_VerifyInit              (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_Verify                  (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG ulDataLen,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG ulSignatureLen);

CK_RV           gkm_test_C_VerifyUpdate            (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen);

CK_RV           gkm_test_C_VerifyFinal             (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG pulSignatureLen);

CK_RV           gkm_test_C_VerifyRecoverInit       (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hKey);

CK_RV           gkm_test_C_VerifyRecover           (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pSignature,
                                                    CK_ULONG pulSignatureLen,
                                                    CK_BYTE_PTR pData,
                                                    CK_ULONG_PTR pulDataLen);

CK_RV           gkm_test_C_DigestEncryptUpdate     (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG_PTR ulEncryptedPartLen);

CK_RV           gkm_test_C_DecryptDigestUpdate     (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG ulEncryptedPartLen,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG_PTR pulPartLen);

CK_RV           gkm_test_C_SignEncryptUpdate       (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG ulPartLen,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG_PTR ulEncryptedPartLen);

CK_RV           gkm_test_C_DecryptVerifyUpdate     (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pEncryptedPart,
                                                    CK_ULONG ulEncryptedPartLen,
                                                    CK_BYTE_PTR pPart,
                                                    CK_ULONG_PTR pulPartLen);

CK_RV           gkm_test_C_GenerateKey             (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount,
                                                    CK_OBJECT_HANDLE_PTR phKey);

CK_RV           gkm_test_C_GenerateKeyPair         (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                                    CK_ULONG ulPublicKeyAttributeCount,
                                                    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                                    CK_ULONG ulPrivateKeyAttributeCount,
                                                    CK_OBJECT_HANDLE_PTR phPublicKey,
                                                    CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV           gkm_test_C_WrapKey                 (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hWrappingKey,
                                                    CK_OBJECT_HANDLE hKey,
                                                    CK_BYTE_PTR pWrappedKey,
                                                    CK_ULONG_PTR pulWrappedKeyLen);

CK_RV           gkm_test_C_UnwrapKey               (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE pUnwrappingKey,
                                                    CK_BYTE_PTR pWrappedKey,
                                                    CK_ULONG pulWrappedKeyLen,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount,
                                                    CK_OBJECT_HANDLE_PTR phKey);

CK_RV           gkm_test_C_DeriveKey               (CK_SESSION_HANDLE hSession,
                                                    CK_MECHANISM_PTR pMechanism,
                                                    CK_OBJECT_HANDLE hBaseKey,
                                                    CK_ATTRIBUTE_PTR pTemplate,
                                                    CK_ULONG ulCount,
                                                    CK_OBJECT_HANDLE_PTR phKey);

CK_RV           gkm_test_C_SeedRandom              (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pSeed,
                                                    CK_ULONG ulSeedLen);

CK_RV           gkm_test_C_GenerateRandom          (CK_SESSION_HANDLE hSession,
                                                    CK_BYTE_PTR pRandomData,
                                                    CK_ULONG ulRandomLen);

/*
 * Some dumb crypto mechanisms for simple testing.
 *
 * CKM_T_CAPITALIZE (encrypt/decrypt)
 *     capitalizes to encrypt
 *     lowercase to decrypt
 *
 * CKM_T_PREFIX (sign/verify)
 *     sign prefixes data with key label
 *     verify unprefixes data with key label.
 *
 * CKM_T_GENERATE (generate-pair)
 *     generates a pair of keys, mechanism param should be 'generate'
 *
 * CKM_T_WRAP (wrap key)
 *     wraps key by returning value, mechanism param should be 'wrap'
 *
 * CKM_T_DERIVE (derive-key)
 *     derives key by setting value to 'derived'.
 *     mechanism param should be 'derive'
 */

#define CKM_T_CAPITALIZE    (CKM_VENDOR_DEFINED | 1)
#define CKM_T_PREFIX        (CKM_VENDOR_DEFINED | 2)
#define CKM_T_GENERATE      (CKM_VENDOR_DEFINED | 3)
#define CKM_T_WRAP          (CKM_VENDOR_DEFINED | 4)
#define CKM_T_DERIVE        (CKM_VENDOR_DEFINED | 5)

#define GKM_TEST_SLOT_ONE  52
#define GKM_TEST_SLOT_TWO  134

#endif /* TESTMODULE_H_ */
