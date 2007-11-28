/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-cryptoki-calls.h - various ids and signatures for our protocol

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

#ifndef GKR_CRYPTOKI_CALLS_H
#define GKR_CRYPTOKI_CALLS_H

#include "config.h"

/* The calls, must be in sync with array below */
enum {
	CRYPTOKI_CALL_ERROR = 0,
	CRYPTOKI_CALL_C_OpenSession,
	CRYPTOKI_CALL_C_GetSessionInfo,
	CRYPTOKI_CALL_C_InitPIN,
	CRYPTOKI_CALL_C_SetPIN,
	CRYPTOKI_CALL_C_GetOperationState,
	CRYPTOKI_CALL_C_SetOperationState,
	CRYPTOKI_CALL_C_Login,
	CRYPTOKI_CALL_C_Logout,
	CRYPTOKI_CALL_C_CreateObject,
	CRYPTOKI_CALL_C_CopyObject,
	CRYPTOKI_CALL_C_DestroyObject,
	CRYPTOKI_CALL_C_GetObjectSize,
	CRYPTOKI_CALL_C_GetAttributeValue,
	CRYPTOKI_CALL_C_SetAttributeValue,
	CRYPTOKI_CALL_C_FindObjectsInit,
	CRYPTOKI_CALL_C_FindObjects,
	CRYPTOKI_CALL_C_FindObjectsFinal,
	CRYPTOKI_CALL_C_EncryptInit,
	CRYPTOKI_CALL_C_Encrypt,
	CRYPTOKI_CALL_C_EncryptUpdate,
	CRYPTOKI_CALL_C_EncryptFinal,
	CRYPTOKI_CALL_C_DecryptInit,
	CRYPTOKI_CALL_C_Decrypt,
	CRYPTOKI_CALL_C_DecryptUpdate,
	CRYPTOKI_CALL_C_DecryptFinal,
	CRYPTOKI_CALL_C_DigestInit,
	CRYPTOKI_CALL_C_Digest,
	CRYPTOKI_CALL_C_DigestUpdate,
	CRYPTOKI_CALL_C_DigestKey,
	CRYPTOKI_CALL_C_DigestFinal,
	CRYPTOKI_CALL_C_SignInit,
	CRYPTOKI_CALL_C_Sign,
	CRYPTOKI_CALL_C_SignUpdate,
	CRYPTOKI_CALL_C_SignFinal,
	CRYPTOKI_CALL_C_SignRecoverInit,
	CRYPTOKI_CALL_C_SignRecover,
	CRYPTOKI_CALL_C_VerifyInit,
	CRYPTOKI_CALL_C_Verify,
	CRYPTOKI_CALL_C_VerifyUpdate,
	CRYPTOKI_CALL_C_VerifyFinal,
	CRYPTOKI_CALL_C_VerifyRecoverInit,
	CRYPTOKI_CALL_C_VerifyRecover,
	CRYPTOKI_CALL_C_DigestEncryptUpdate,
	CRYPTOKI_CALL_C_DecryptDigestUpdate,
	CRYPTOKI_CALL_C_SignEncryptUpdate,
	CRYPTOKI_CALL_C_DecryptVerifyUpdate,
	CRYPTOKI_CALL_C_GenerateKey,
	CRYPTOKI_CALL_C_GenerateKeyPair,
	CRYPTOKI_CALL_C_WrapKey,
	CRYPTOKI_CALL_C_UnwrapKey,
	CRYPTOKI_CALL_C_DeriveKey,
	CRYPTOKI_CALL_C_SeedRandom,
	CRYPTOKI_CALL_C_GenerateRandom,
	
	CRYPTOKI_CALL_MAX
};

typedef struct _GkrCryptokiCallInfo {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} GkrCryptokiCallInfo;

const static GkrCryptokiCallInfo gkr_cryptoki_calls[] = {
	{ CRYPTOKI_CALL_ERROR,                  "ERROR",                  NULL,      NULL     },
	{ CRYPTOKI_CALL_C_OpenSession,          "C_OpenSession",          "ayuu",    ""       },
	{ CRYPTOKI_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "",        "I"      },
	{ CRYPTOKI_CALL_C_InitPIN,              "C_InitPIN",              "ay",      ""       },
	{ CRYPTOKI_CALL_C_SetPIN,               "C_SetPIN",               "ayay",    ""       },
	{ CRYPTOKI_CALL_C_GetOperationState,    "C_GetOperationState",    "",        "ay"     },
	{ CRYPTOKI_CALL_C_SetOperationState,    "C_SetOperationState",    "ayuu",    ""       },
	{ CRYPTOKI_CALL_C_Login,                "C_Login",                "uay",     ""       },
	{ CRYPTOKI_CALL_C_Logout,               "C_Logout",               "",        ""       },
	{ CRYPTOKI_CALL_C_CreateObject,         "C_CreateObject",         "aA",      "u"      },
	{ CRYPTOKI_CALL_C_CopyObject,           "C_CopyObject",           "uaA",     "u"      },
	{ CRYPTOKI_CALL_C_DestroyObject,        "C_DestroyObject",        "u",       ""       },
	{ CRYPTOKI_CALL_C_GetObjectSize,        "C_GetObjectSize",        "u",       "u"      },
	{ CRYPTOKI_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uaA",     "aAu"    },
	{ CRYPTOKI_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "u",       "aA"     },
	{ CRYPTOKI_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "aA",      ""       },
	{ CRYPTOKI_CALL_C_FindObjects,          "C_FindObjects",          "u",       "au"     },
	{ CRYPTOKI_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "",        ""       },
	{ CRYPTOKI_CALL_C_EncryptInit,          "C_EncryptInit",          "Mu",      ""       },
	{ CRYPTOKI_CALL_C_Encrypt,              "C_Encrypt",              "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_EncryptFinal,         "C_EncryptFinal",         "",        "ay"     },
	{ CRYPTOKI_CALL_C_DecryptInit,          "C_DecryptInit",          "Mu",      ""       },
	{ CRYPTOKI_CALL_C_Decrypt,              "C_Decrypt",              "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_DecryptFinal,         "C_DecryptFinal",         "",        "ay"     },
	{ CRYPTOKI_CALL_C_DigestInit,           "C_DigestInit",           "M",       ""       },
	{ CRYPTOKI_CALL_C_Digest,               "C_Digest",               "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_DigestUpdate,         "C_DigestUpdate",         "ay",      ""       },
	{ CRYPTOKI_CALL_C_DigestKey,            "C_DigestKey",            "u",       ""       },
	{ CRYPTOKI_CALL_C_DigestFinal,          "C_DigestFinal",          "",        "ay"     },
	{ CRYPTOKI_CALL_C_SignInit,             "C_SignInit",             "Mu",      ""       },
	{ CRYPTOKI_CALL_C_Sign,                 "C_Sign",                 "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_SignUpdate,           "C_SignUpdate",           "ay",      ""       },
	{ CRYPTOKI_CALL_C_SignFinal,            "C_SignFinal",            "",        "ay"     },
	{ CRYPTOKI_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "Mu",      ""       },
	{ CRYPTOKI_CALL_C_SignRecover,          "C_SignRecover",          "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_VerifyInit,           "C_VerifyInit",           "Mu",      ""       },
	{ CRYPTOKI_CALL_C_Verify,               "C_Verify",               "ayay",    ""     },
	{ CRYPTOKI_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "ay",      ""       },
	{ CRYPTOKI_CALL_C_VerifyFinal,          "C_VerifyFinal",          "",        "ay"     },
	{ CRYPTOKI_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "Mu",      ""       },
	{ CRYPTOKI_CALL_C_VerifyRecover,        "C_VerifyRecover",        "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "ay",      "ay"     }, 
	{ CRYPTOKI_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "ay",      "ay"     },
	{ CRYPTOKI_CALL_C_GenerateKey,          "C_GenerateKey",          "MaA",     "u"      },
	{ CRYPTOKI_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "MaAaA",   "uu"     },
	{ CRYPTOKI_CALL_C_WrapKey,              "C_WrapKey",              "Muu",     "ay"     },
	{ CRYPTOKI_CALL_C_UnwrapKey,            "C_UnwrapKey",            "MuayaA",  "u"      },
	{ CRYPTOKI_CALL_C_DeriveKey,            "C_DeriveKey",            "MuaA",    "u"      },
	{ CRYPTOKI_CALL_C_SeedRandom,           "C_SeedRandom",           "ay",      ""       },
	{ CRYPTOKI_CALL_C_GenerateRandom,       "C_GenerateRandom",       "u",       "ay"     },
};

#ifdef _DEBUG 
#define GKR_CRYPTOKI_CHECK_CALLS() \
	{ int i; for (i = 0; i < CRYPTOKI_CALL_MAX; ++i) assert (gkr_cryptoki_calls[i].call_id == i); }
#endif 

#define GKR_CRYPTOKI_HANDSHAKE \
	("PRIVATE-GNOME-KEYRING-CRYPTOKI-PROTOCOL-V-" VERSION)
#define GKR_CRYPTOKI_HANDSHAKE_LEN \
	(sizeof (GKR_CRYPTOKI_HANDSHAKE) - 1)

#define GKR_CRYPTOKI_SOCKET_EXT 	".cryptoki"

#endif /* GKR_CRYPTOKI_CALLS_H */
