/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-private.h - various ids and signatures for our protocol

   Copyright (C) 2008, Stef Walter

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

#ifndef P11_RPC_CALLS_H
#define P11_RPC_CALLS_H

#include "config.h"

#include <stdlib.h>
#include <stdarg.h>

#include "common/gkr-buffer.h"

#include "pkcs11/pkcs11.h"


/* Whether to print debug output or not */
#define DEBUG_OUTPUT 1


/* The calls, must be in sync with array below */
enum {
	P11_RPC_CALL_ERROR = 0,
	
	P11_RPC_CALL_C_Initialize,
	P11_RPC_CALL_C_Finalize,
	P11_RPC_CALL_C_GetInfo,
	P11_RPC_CALL_C_GetSlotList,
	P11_RPC_CALL_C_GetSlotInfo,
	P11_RPC_CALL_C_GetTokenInfo,
	P11_RPC_CALL_C_GetMechanismList,
	P11_RPC_CALL_C_GetMechanismInfo,
	P11_RPC_CALL_C_InitToken,
	P11_RPC_CALL_C_WaitForSlotEvent,
	
	P11_RPC_CALL_C_OpenSession,
	
	P11_RPC_CALL_C_CloseSession,
	P11_RPC_CALL_C_CloseAllSessions,
	P11_RPC_CALL_C_GetFunctionStatus,
	P11_RPC_CALL_C_CancelFunction,
	
	P11_RPC_CALL_C_GetSessionInfo,
	P11_RPC_CALL_C_InitPIN,
	P11_RPC_CALL_C_SetPIN,
	P11_RPC_CALL_C_GetOperationState,
	P11_RPC_CALL_C_SetOperationState,
	P11_RPC_CALL_C_Login,
	P11_RPC_CALL_C_Logout,
	P11_RPC_CALL_C_CreateObject,
	P11_RPC_CALL_C_CopyObject,
	P11_RPC_CALL_C_DestroyObject,
	P11_RPC_CALL_C_GetObjectSize,
	P11_RPC_CALL_C_GetAttributeValue,
	P11_RPC_CALL_C_SetAttributeValue,
	P11_RPC_CALL_C_FindObjectsInit,
	P11_RPC_CALL_C_FindObjects,
	P11_RPC_CALL_C_FindObjectsFinal,
	P11_RPC_CALL_C_EncryptInit,
	P11_RPC_CALL_C_Encrypt,
	P11_RPC_CALL_C_EncryptUpdate,
	P11_RPC_CALL_C_EncryptFinal,
	P11_RPC_CALL_C_DecryptInit,
	P11_RPC_CALL_C_Decrypt,
	P11_RPC_CALL_C_DecryptUpdate,
	P11_RPC_CALL_C_DecryptFinal,
	P11_RPC_CALL_C_DigestInit,
	P11_RPC_CALL_C_Digest,
	P11_RPC_CALL_C_DigestUpdate,
	P11_RPC_CALL_C_DigestKey,
	P11_RPC_CALL_C_DigestFinal,
	P11_RPC_CALL_C_SignInit,
	P11_RPC_CALL_C_Sign,
	P11_RPC_CALL_C_SignUpdate,
	P11_RPC_CALL_C_SignFinal,
	P11_RPC_CALL_C_SignRecoverInit,
	P11_RPC_CALL_C_SignRecover,
	P11_RPC_CALL_C_VerifyInit,
	P11_RPC_CALL_C_Verify,
	P11_RPC_CALL_C_VerifyUpdate,
	P11_RPC_CALL_C_VerifyFinal,
	P11_RPC_CALL_C_VerifyRecoverInit,
	P11_RPC_CALL_C_VerifyRecover,
	P11_RPC_CALL_C_DigestEncryptUpdate,
	P11_RPC_CALL_C_DecryptDigestUpdate,
	P11_RPC_CALL_C_SignEncryptUpdate,
	P11_RPC_CALL_C_DecryptVerifyUpdate,
	P11_RPC_CALL_C_GenerateKey,
	P11_RPC_CALL_C_GenerateKeyPair,
	P11_RPC_CALL_C_WrapKey,
	P11_RPC_CALL_C_UnwrapKey,
	P11_RPC_CALL_C_DeriveKey,
	P11_RPC_CALL_C_SeedRandom,
	P11_RPC_CALL_C_GenerateRandom,
	
	P11_RPC_CALL_MAX
};

typedef struct _P11RpcCall {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} P11RpcCall;

/*
 *  a_ = prefix denotes array of _
 *  A  = CK_ATTRIBUTE
 *  f_ = prefix denotes buffer for _
 *  M  = CK_MECHANISM
 *  u  = CK_ULONG
 *  s  = space padded string
 *  v  = CK_VERSION
 *  y  = CK_BYTE  
 *  z  = null terminated string
 */

const static P11RpcCall p11_rpc_calls[] = {
	{ P11_RPC_CALL_ERROR,                  "ERROR",                  NULL,      NULL                   },
	{ P11_RPC_CALL_C_Initialize,           "C_Initialize",           "ay",      ""                     },
	{ P11_RPC_CALL_C_Finalize,             "C_Finalize",             "",        ""                     },
	{ P11_RPC_CALL_C_GetInfo,              "C_GetInfo",              "",        "vsusv"                },
	{ P11_RPC_CALL_C_GetSlotList,          "C_GetSlotList",          "yfu",     "au"                   },
	{ P11_RPC_CALL_C_GetSlotInfo,          "C_GetSlotInfo",          "u",       "ssuvv"                },
	{ P11_RPC_CALL_C_GetTokenInfo,         "C_GetTokenInfo",         "u",       "ssssuuuuuuuuuuuvvs"   },
	{ P11_RPC_CALL_C_GetMechanismList,     "C_GetMechanismList",     "ufu",     "au"                   },
	{ P11_RPC_CALL_C_GetMechanismInfo,     "C_GetMechanismInfo",     "uu",      "uuu"                  },
	{ P11_RPC_CALL_C_InitToken,            "C_InitToken",            "uayz",    ""                     },
	{ P11_RPC_CALL_C_WaitForSlotEvent,     "C_WaitForSlotEvent",     "u",       "u"                    },
	{ P11_RPC_CALL_C_OpenSession,          "C_OpenSession",          "uu",      "u"                    },
	{ P11_RPC_CALL_C_CloseSession,         "C_CloseSession",         "u",       ""                     },
	{ P11_RPC_CALL_C_CloseAllSessions,     "C_CloseAllSessions",     "u",       ""                     },
	{ P11_RPC_CALL_C_GetFunctionStatus,    "C_GetFunctionStatus",    "u",       ""                     },
	{ P11_RPC_CALL_C_CancelFunction,       "C_CancelFunction",       "u",       ""                     },
	{ P11_RPC_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "u",       "uuuu"                 },
	{ P11_RPC_CALL_C_InitPIN,              "C_InitPIN",              "uay",     ""                     },
	{ P11_RPC_CALL_C_SetPIN,               "C_SetPIN",               "uayay",   ""                     },
	{ P11_RPC_CALL_C_GetOperationState,    "C_GetOperationState",    "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SetOperationState,    "C_SetOperationState",    "uayuu",   ""                     },
	{ P11_RPC_CALL_C_Login,                "C_Login",                "uuay",    ""                     },
	{ P11_RPC_CALL_C_Logout,               "C_Logout",               "u",       ""                     },
	{ P11_RPC_CALL_C_CreateObject,         "C_CreateObject",         "uaA",     "u"                    },
	{ P11_RPC_CALL_C_CopyObject,           "C_CopyObject",           "uuaA",    "u"                    },
	{ P11_RPC_CALL_C_DestroyObject,        "C_DestroyObject",        "uu",      ""                     },
	{ P11_RPC_CALL_C_GetObjectSize,        "C_GetObjectSize",        "uu",      "u"                    },
	{ P11_RPC_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uufA",    "aAu"                  },
	{ P11_RPC_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "uuaA",    ""                     },
	{ P11_RPC_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "uaA",     ""                     },
	{ P11_RPC_CALL_C_FindObjects,          "C_FindObjects",          "ufu",     "au"                   },
	{ P11_RPC_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "u",       ""                     },
	{ P11_RPC_CALL_C_EncryptInit,          "C_EncryptInit",          "uMu"      ""                     },
	{ P11_RPC_CALL_C_Encrypt,              "C_Encrypt",              "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_EncryptFinal,         "C_EncryptFinal",         "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_DecryptInit,          "C_DecryptInit",          "uMu",     ""                     },
	{ P11_RPC_CALL_C_Decrypt,              "C_Decrypt",              "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptFinal,         "C_DecryptFinal",         "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_DigestInit,           "C_DigestInit",           "uM",      ""                     },
	{ P11_RPC_CALL_C_Digest,               "C_Digest",               "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DigestUpdate,         "C_DigestUpdate",         "uay",     ""                     },
	{ P11_RPC_CALL_C_DigestKey,            "C_DigestKey",            "uu",      ""                     },
	{ P11_RPC_CALL_C_DigestFinal,          "C_DigestFinal",          "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SignInit,             "C_SignInit",             "uMu",     ""                     },
	{ P11_RPC_CALL_C_Sign,                 "C_Sign",                 "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_SignUpdate,           "C_SignUpdate",           "uay",     ""                     },
	{ P11_RPC_CALL_C_SignFinal,            "C_SignFinal",            "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "uMu",     ""                     },
	{ P11_RPC_CALL_C_SignRecover,          "C_SignRecover",          "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_VerifyInit,           "C_VerifyInit",           "uMu",     ""                     },
	{ P11_RPC_CALL_C_Verify,               "C_Verify",               "uayay",   ""                     },
	{ P11_RPC_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "uay",     ""                     },
	{ P11_RPC_CALL_C_VerifyFinal,          "C_VerifyFinal",          "uay",     ""                     },
	{ P11_RPC_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "uMu",     ""                     },
	{ P11_RPC_CALL_C_VerifyRecover,        "C_VerifyRecover",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "uayfy",   "ay"                   }, 
	{ P11_RPC_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_GenerateKey,          "C_GenerateKey",          "uMaA",    "u"                    },
	{ P11_RPC_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "uMaAaA",  "uu"                   },
	{ P11_RPC_CALL_C_WrapKey,              "C_WrapKey",              "uMuufy",  "ay"                   },
	{ P11_RPC_CALL_C_UnwrapKey,            "C_UnwrapKey",            "uMuayaA", "u"                    },
	{ P11_RPC_CALL_C_DeriveKey,            "C_DeriveKey",            "uMuaA",   "u"                    },
	{ P11_RPC_CALL_C_SeedRandom,           "C_SeedRandom",           "uay",     ""                     },
	{ P11_RPC_CALL_C_GenerateRandom,       "C_GenerateRandom",       "ufy",     "ay"                   },
};

#ifdef _DEBUG 
#define P11_RPC_CHECK_CALLS() \
	{ int i; for (i = 0; i < P11_RPC_CALL_MAX; ++i) assert (p11_rpc_calls[i].call_id == i); }
#endif 

#define P11_RPC_HANDSHAKE \
	((unsigned char*)"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1")
#define P11_RPC_HANDSHAKE_LEN \
	(sizeof (P11_RPC_HANDSHAKE) - 1)

#define P11_RPC_SOCKET_EXT 	"pkcs11"

typedef enum _P11RpcMessageType {
	P11_RPC_REQUEST = 1,
	P11_RPC_RESPONSE
} P11RpcMessageType;

typedef struct _P11RpcMessage {
	int call_id;
	P11RpcMessageType call_type;
	const char *signature;
	GkrBuffer buffer;

	size_t parsed;
	const char *sigverify;
} P11RpcMessage;

P11RpcMessage*           p11_rpc_message_new                     (GkrBufferAllocator allocator);

void                     p11_rpc_message_free                    (P11RpcMessage *msg);

void                     p11_rpc_message_reset                   (P11RpcMessage *msg);

int                      p11_rpc_message_equals                  (P11RpcMessage *m1, 
                                                                  P11RpcMessage *m2);

#define                  p11_rpc_message_is_verified(msg)        ((msg)->sigverify[0] == 0)

#define                  p11_rpc_message_buffer_error(msg)       (gkr_buffer_has_error(&(msg)->buffer))

int                      p11_rpc_message_prep                    (P11RpcMessage *msg, 
                                                                  int call_id, 
                                                                  P11RpcMessageType type);

int                      p11_rpc_message_parse                   (P11RpcMessage *msg, 
                                                                  P11RpcMessageType type);

int                      p11_rpc_message_verify_part             (P11RpcMessage *msg, 
                                                                  const char* part);

int                      p11_rpc_message_write_byte              (P11RpcMessage *msg,
                                                                  CK_BYTE val);

int                      p11_rpc_message_write_ulong             (P11RpcMessage *msg, 
                                                                  CK_ULONG val);

int                      p11_rpc_message_write_zero_string       (P11RpcMessage *msg,
                                                                  CK_UTF8CHAR* string);

int                      p11_rpc_message_write_space_string      (P11RpcMessage *msg,
                                                                  CK_UTF8CHAR* buffer,
                                                                  CK_ULONG length);

int                      p11_rpc_message_write_byte_buffer       (P11RpcMessage *msg, 
                                                                  CK_ULONG count);

int                      p11_rpc_message_write_byte_array        (P11RpcMessage *msg, 
                                                                  CK_BYTE_PTR arr, 
                                                                  CK_ULONG num);

int                      p11_rpc_message_write_ulong_buffer      (P11RpcMessage *msg, 
                                                                  CK_ULONG count);

int                      p11_rpc_message_write_ulong_array       (P11RpcMessage *msg, 
                                                                  CK_ULONG_PTR arr, 
                                                                  CK_ULONG num);

int                      p11_rpc_message_write_attribute_buffer  (P11RpcMessage *msg, 
                                                                  CK_ATTRIBUTE_PTR arr, 
                                                                  CK_ULONG num);

int                      p11_rpc_message_write_attribute_array   (P11RpcMessage *msg, 
                                                                  CK_ATTRIBUTE_PTR arr, 
                                                                  CK_ULONG num);

int                      p11_rpc_message_write_version           (P11RpcMessage *msg,
                                                                  CK_VERSION* version);


int                      p11_rpc_message_read_byte               (P11RpcMessage *msg,
                                                                  CK_BYTE* val);

int                      p11_rpc_message_read_ulong              (P11RpcMessage *msg, 
                                                                  CK_ULONG* val);

int                      p11_rpc_message_read_space_string       (P11RpcMessage *msg,
                                                                  CK_UTF8CHAR* buffer,
                                                                  CK_ULONG length);

int                      p11_rpc_message_read_version            (P11RpcMessage *msg,
                                                                  CK_VERSION* version);


void                     p11_rpc_warn                            (const char* msg, ...);

void                     p11_rpc_debug                           (const char* msg, ...);

#ifdef G_DISABLE_ASSERT
#define assert(x)
#else
#include <assert.h>
#endif

/*
 * PKCS#11 mechanism parameters are not easy to serialize. They're 
 * completely different for so many mechanisms, they contain 
 * pointers to arbitrary memory, and many callers don't initialize
 * them completely or properly. 
 * 
 * We only support certain mechanisms. 
 * 
 * Also callers do yucky things like leaving parts of the structure
 * pointing to garbage if they don't think it's going to be used.
 */

int    p11_rpc_mechanism_is_supported        (CK_MECHANISM_TYPE mech);
void   p11_rpc_mechanism_list_purge          (CK_MECHANISM_TYPE_PTR mechs, CK_ULONG_PTR n_mechs);
int    p11_rpc_mechanism_has_sane_parameters (CK_MECHANISM_TYPE type);
int    p11_rpc_mechanism_has_no_parameters   (CK_MECHANISM_TYPE mech);

#endif /* P11_RPC_CALLS_H */
