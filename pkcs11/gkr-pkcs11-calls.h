/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-calls.h - various ids and signatures for our protocol

   Copyright (C) 2007, Nate Nielsen

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

   Author: Nate Nielsen <nielsen@memberwebs.com>
*/

#ifndef GKR_PKCS11_CALLS_H
#define GKR_PKCS11_CALLS_H

#include "config.h"

/* The calls, must be in sync with array below */
enum {
	PKCS11_CALL_ERROR = 0,
	PKCS11_CALL_C_OpenSession,
	PKCS11_CALL_C_GetSessionInfo,
	PKCS11_CALL_C_InitPIN,
	PKCS11_CALL_C_SetPIN,
	PKCS11_CALL_C_GetOperationState,
	PKCS11_CALL_C_SetOperationState,
	PKCS11_CALL_C_Login,
	PKCS11_CALL_C_Logout,
	PKCS11_CALL_C_CreateObject,
	PKCS11_CALL_C_CopyObject,
	PKCS11_CALL_C_DestroyObject,
	PKCS11_CALL_C_GetObjectSize,
	PKCS11_CALL_C_GetAttributeValue,
	PKCS11_CALL_C_SetAttributeValue,
	PKCS11_CALL_C_FindObjectsInit,
	PKCS11_CALL_C_FindObjects,
	PKCS11_CALL_C_FindObjectsFinal,
	PKCS11_CALL_C_EncryptInit,
	PKCS11_CALL_C_Encrypt,
	PKCS11_CALL_C_EncryptUpdate,
	PKCS11_CALL_C_EncryptFinal,
	PKCS11_CALL_C_DecryptInit,
	PKCS11_CALL_C_Decrypt,
	PKCS11_CALL_C_DecryptUpdate,
	PKCS11_CALL_C_DecryptFinal,
	PKCS11_CALL_C_DigestInit,
	PKCS11_CALL_C_Digest,
	PKCS11_CALL_C_DigestUpdate,
	PKCS11_CALL_C_DigestKey,
	PKCS11_CALL_C_DigestFinal,
	PKCS11_CALL_C_SignInit,
	PKCS11_CALL_C_Sign,
	PKCS11_CALL_C_SignUpdate,
	PKCS11_CALL_C_SignFinal,
	PKCS11_CALL_C_SignRecoverInit,
	PKCS11_CALL_C_SignRecover,
	PKCS11_CALL_C_VerifyInit,
	PKCS11_CALL_C_Verify,
	PKCS11_CALL_C_VerifyUpdate,
	PKCS11_CALL_C_VerifyFinal,
	PKCS11_CALL_C_VerifyRecoverInit,
	PKCS11_CALL_C_VerifyRecover,
	PKCS11_CALL_C_DigestEncryptUpdate,
	PKCS11_CALL_C_DecryptDigestUpdate,
	PKCS11_CALL_C_SignEncryptUpdate,
	PKCS11_CALL_C_DecryptVerifyUpdate,
	PKCS11_CALL_C_GenerateKey,
	PKCS11_CALL_C_GenerateKeyPair,
	PKCS11_CALL_C_WrapKey,
	PKCS11_CALL_C_UnwrapKey,
	PKCS11_CALL_C_DeriveKey,
	PKCS11_CALL_C_SeedRandom,
	PKCS11_CALL_C_GenerateRandom,
	
	PKCS11_CALL_MAX
};

typedef struct _GkrPkcs11CallInfo {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} GkrPkcs11CallInfo;

const static GkrPkcs11CallInfo gkr_pkcs11_calls[] = {
	{ PKCS11_CALL_ERROR,                  "ERROR",                  NULL,      NULL     },
	{ PKCS11_CALL_C_OpenSession,          "C_OpenSession",          "ayuuu",   ""       },
	{ PKCS11_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "",        "I"      },
	{ PKCS11_CALL_C_InitPIN,              "C_InitPIN",              "ay",      ""       },
	{ PKCS11_CALL_C_SetPIN,               "C_SetPIN",               "ayay",    ""       },
	{ PKCS11_CALL_C_GetOperationState,    "C_GetOperationState",    "",        "ay"     },
	{ PKCS11_CALL_C_SetOperationState,    "C_SetOperationState",    "ayuu",    ""       },
	{ PKCS11_CALL_C_Login,                "C_Login",                "uay",     ""       },
	{ PKCS11_CALL_C_Logout,               "C_Logout",               "",        ""       },
	{ PKCS11_CALL_C_CreateObject,         "C_CreateObject",         "aA",      "u"      },
	{ PKCS11_CALL_C_CopyObject,           "C_CopyObject",           "uaA",     "u"      },
	{ PKCS11_CALL_C_DestroyObject,        "C_DestroyObject",        "u",       ""       },
	{ PKCS11_CALL_C_GetObjectSize,        "C_GetObjectSize",        "u",       "u"      },
	{ PKCS11_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uaA",     "aAu"    },
	{ PKCS11_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "uaA",     ""       },
	{ PKCS11_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "aA",      ""       },
	{ PKCS11_CALL_C_FindObjects,          "C_FindObjects",          "u",       "au"     },
	{ PKCS11_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "",        ""       },
	{ PKCS11_CALL_C_EncryptInit,          "C_EncryptInit",          "Mu",      ""       },
	{ PKCS11_CALL_C_Encrypt,              "C_Encrypt",              "ay",      "ay"     },
	{ PKCS11_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "ay",      "ay"     },
	{ PKCS11_CALL_C_EncryptFinal,         "C_EncryptFinal",         "",        "ay"     },
	{ PKCS11_CALL_C_DecryptInit,          "C_DecryptInit",          "Mu",      ""       },
	{ PKCS11_CALL_C_Decrypt,              "C_Decrypt",              "ay",      "ay"     },
	{ PKCS11_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "ay",      "ay"     },
	{ PKCS11_CALL_C_DecryptFinal,         "C_DecryptFinal",         "",        "ay"     },
	{ PKCS11_CALL_C_DigestInit,           "C_DigestInit",           "M",       ""       },
	{ PKCS11_CALL_C_Digest,               "C_Digest",               "ay",      "ay"     },
	{ PKCS11_CALL_C_DigestUpdate,         "C_DigestUpdate",         "ay",      ""       },
	{ PKCS11_CALL_C_DigestKey,            "C_DigestKey",            "u",       ""       },
	{ PKCS11_CALL_C_DigestFinal,          "C_DigestFinal",          "",        "ay"     },
	{ PKCS11_CALL_C_SignInit,             "C_SignInit",             "Mu",      ""       },
	{ PKCS11_CALL_C_Sign,                 "C_Sign",                 "ay",      "ay"     },
	{ PKCS11_CALL_C_SignUpdate,           "C_SignUpdate",           "ay",      ""       },
	{ PKCS11_CALL_C_SignFinal,            "C_SignFinal",            "",        "ay"     },
	{ PKCS11_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "Mu",      ""       },
	{ PKCS11_CALL_C_SignRecover,          "C_SignRecover",          "ay",      "ay"     },
	{ PKCS11_CALL_C_VerifyInit,           "C_VerifyInit",           "Mu",      ""       },
	{ PKCS11_CALL_C_Verify,               "C_Verify",               "ayay",    ""     },
	{ PKCS11_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "ay",      ""       },
	{ PKCS11_CALL_C_VerifyFinal,          "C_VerifyFinal",          "",        "ay"     },
	{ PKCS11_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "Mu",      ""       },
	{ PKCS11_CALL_C_VerifyRecover,        "C_VerifyRecover",        "ay",      "ay"     },
	{ PKCS11_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "ay",      "ay"     }, 
	{ PKCS11_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "ay",      "ay"     },
	{ PKCS11_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "ay",      "ay"     },
	{ PKCS11_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "ay",      "ay"     },
	{ PKCS11_CALL_C_GenerateKey,          "C_GenerateKey",          "MaA",     "u"      },
	{ PKCS11_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "MaAaA",   "uu"     },
	{ PKCS11_CALL_C_WrapKey,              "C_WrapKey",              "Muu",     "ay"     },
	{ PKCS11_CALL_C_UnwrapKey,            "C_UnwrapKey",            "MuayaA",  "u"      },
	{ PKCS11_CALL_C_DeriveKey,            "C_DeriveKey",            "MuaA",    "u"      },
	{ PKCS11_CALL_C_SeedRandom,           "C_SeedRandom",           "ay",      ""       },
	{ PKCS11_CALL_C_GenerateRandom,       "C_GenerateRandom",       "u",       "ay"     },
};

#ifdef _DEBUG 
#define GKR_PKCS11_CHECK_CALLS() \
	{ int i; for (i = 0; i < PKCS11_CALL_MAX; ++i) assert (gkr_pkcs11_calls[i].call_id == i); }
#endif 

#define GKR_PKCS11_HANDSHAKE \
	("PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-" VERSION)
#define GKR_PKCS11_HANDSHAKE_LEN \
	(sizeof (GKR_PKCS11_HANDSHAKE) - 1)

#define GKR_PKCS11_SOCKET_EXT 	".pkcs11"

#endif /* GKR_PKCS11_CALLS_H */
