/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-daemon-session.c - PKCS#11 session in daemon

   Copyright (C) 2007, Stefan Walter

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

#include <glib.h>

#include "gkr-pkcs11-message.h"
#include "gkr-pkcs11-calls.h"
#include "gkr-pkcs11-daemon.h"
#include "gkr-pkcs11-dsa.h"
#include "gkr-pkcs11-rsa.h"
#include "pkcs11.h"

#include "common/gkr-async.h"
#include "common/gkr-buffer.h"
#include "common/gkr-crypto.h"
#include "common/gkr-unix-credentials.h"

#include "keyrings/gkr-keyring-login.h"

#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-object-manager.h"
#include "pk/gkr-pk-object-storage.h"
#include "pk/gkr-pk-util.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

struct _SessionInfo;
typedef struct _SessionInfo SessionInfo;

enum
{
	OPERATION_NONE = 0,
	OPERATION_FIND,
	OPERATION_ENCRYPT,
	OPERATION_DECRYPT,
	OPERATION_SIGN,
	OPERATION_VERIFY
};

typedef void (*OperationCleanup) (SessionInfo* sinfo);

struct _SessionInfo {
	pid_t pid;		    /* Process ID of client */
	gboolean valid;             /* Session is valid */
	gboolean readonly;          /* Session is readonly */
	
	guint operation_type;
	GDestroyNotify operation_cleanup;
	gpointer operation_data;
	
	guint deverror;                 /* The 'device' error code */
	
	GkrPkObjectManager *manager;	/* The object manager for this session */
	GHashTable *objects;		/* Objects owned by the session */
};

/* 
 * TODO: Would this be the right error to pass back on a message 
 * parse failure? Or should we just disconnect? 
 */
#define PROTOCOL_ERROR   CKR_DEVICE_ERROR

/* -----------------------------------------------------------------------------
 * SESSION OBJECTS 
 */

static void
session_add_object (SessionInfo *sinfo, GkrPkObject *object)
{
	g_assert (sinfo);
	
	g_return_if_fail (object->handle != 0);
	g_return_if_fail (object->location == 0);
	g_return_if_fail (object->manager == sinfo->manager);

	/* We assume the ownership */
	g_object_ref (object);
	g_hash_table_insert (sinfo->objects, GUINT_TO_POINTER (object->handle), object);
}

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static void
begin_operation (SessionInfo *sinfo, guint type, gpointer data, GDestroyNotify cleanup)
{
	g_assert (sinfo);
	g_assert (type != OPERATION_NONE);
	g_assert (sinfo->operation_type == OPERATION_NONE);
	
	sinfo->operation_type = type;
	sinfo->operation_data = data;
	sinfo->operation_cleanup = cleanup;
}

static void
finish_operation (SessionInfo *sinfo)
{
	if (sinfo->operation_data) {
		if (sinfo->operation_cleanup)
			(sinfo->operation_cleanup) (sinfo->operation_data);
		sinfo->operation_data = NULL;
	}
	
	sinfo->operation_cleanup = NULL;
	sinfo->operation_type = OPERATION_NONE;
}

/* -----------------------------------------------------------------------------
 * PROTOCOL PARSING 
 */

static GArray*
read_attribute_array (GkrPkcs11Message* msg)
{
	CK_ATTRIBUTE attr;
	GArray* attrs;
	guint32 num, i;
	guchar validity;
	const guchar *value;
	gsize n_value;

	g_assert (msg);
	g_assert (gkr_pkcs11_message_verify_part (msg, "aA"));

	/* Get the number of items. We need this value to be correct */
	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, 
	                            &msg->parsed, &num))
		return NULL; /* parse error */
	
	attrs = gkr_pk_attributes_new ();

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {

		memset (&attr, 0, sizeof (attr));
	
		/* The attribute type */
		gkr_buffer_get_uint32 (&msg->buffer, msg->parsed,
		                       &msg->parsed, (guint32*)(&attr.type));
		
		/* Attribute validity */
		gkr_buffer_get_byte (&msg->buffer, msg->parsed,
		                     &msg->parsed, &validity);

		/* And the data itself */
		if (validity)
			gkr_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, 
			                           &value, &n_value);
		
		/* Don't act on this data unless no errors */
		if (gkr_buffer_has_error (&msg->buffer))
			break;

		if (validity) 
			gkr_pk_attribute_set_data (&attr, value, n_value);
		else
			attr.ulValueLen = (CK_ULONG)-1;
		
		/* Transfer ownership of the attribute to the array */
		g_array_append_val (attrs, attr);
	}
	
	if (gkr_buffer_has_error (&msg->buffer)) {
		gkr_pk_attributes_free (attrs);
		attrs = NULL;
	}
	
	return attrs;
}

static gboolean
read_byte_array (GkrPkcs11Message *msg, CK_BYTE_PTR *val, CK_ULONG *vlen)
{
	const unsigned char* v;
	size_t l; 
	
	g_assert (msg && val && vlen);
	g_assert (gkr_pkcs11_message_verify_part (msg, "ay"));

	if (!gkr_buffer_get_byte_array (&msg->buffer, msg->parsed,
	                                &(msg->parsed), &v, &l))
		return FALSE;
	
	*val = (CK_BYTE_PTR)v;
	*vlen = l;
	return TRUE;
}

static gboolean
read_mechanism (GkrPkcs11Message* msg, CK_MECHANISM_PTR mech)
{
	const guchar *value;
	gsize n_value;
	guint32 num;
	
	g_assert (msg);
	g_assert (gkr_pkcs11_message_verify_part (msg, "M"));
	
	/* Get the mechanism type */
	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, 
	                            &num))
		return FALSE; /* parse error */
		
	if (!gkr_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, 
	                                &value, &n_value))
		return FALSE; /* parse error */
		
	mech->mechanism = num;
	mech->pParameter = (CK_VOID_PTR)value;
	mech->ulParameterLen = n_value;
	return TRUE;
}

static CK_RV
read_object (GkrPkcs11Message *msg, SessionInfo *sinfo, GkrPkObject **res)
{
	CK_OBJECT_HANDLE obj;
	GkrPkObjectManager *manager;
	
	if (gkr_pkcs11_message_read_uint32 (msg, &obj) != CKR_OK)
		return PROTOCOL_ERROR;
	
	/* Find the object in question */
	if (obj & GKR_PK_OBJECT_IS_PERMANENT)
		manager = gkr_pk_object_manager_for_token ();
	else
		manager = sinfo->manager;
		
	*res = gkr_pk_object_manager_lookup (manager, obj);
	if (!*res)
		return CKR_OBJECT_HANDLE_INVALID;
		
	return CKR_OK;
}

static void
write_session_info (GkrPkcs11Message *msg, CK_ULONG slot, CK_ULONG state, 
                    CK_ULONG flags, CK_ULONG deverror)
{
	g_assert (msg);
	g_assert (gkr_pkcs11_message_verify_part (msg, "I"));

	/* The slot id */
	gkr_buffer_add_uint32 (&msg->buffer, slot);

	/* The state */
	gkr_buffer_add_uint32 (&msg->buffer, state);

	/* The flags */
	gkr_buffer_add_uint32 (&msg->buffer, flags);

	/* The device error code */
	gkr_buffer_add_uint32 (&msg->buffer, deverror);
}

/* -----------------------------------------------------------------------------
 * SESSION OPERATIONS
 */

static CK_RV
session_C_OpenSession (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	CK_BYTE_PTR sig = NULL;
	CK_ULONG siglen, slotid, flags, pid;
	
	if (!read_byte_array (req, &sig, &siglen))
		return PROTOCOL_ERROR;
	if (gkr_pkcs11_message_read_uint32 (req, &pid) != CKR_OK)
		return PROTOCOL_ERROR;
	if (gkr_pkcs11_message_read_uint32 (req, &slotid) != CKR_OK)
		return PROTOCOL_ERROR;
	if (gkr_pkcs11_message_read_uint32 (req, &flags) != CKR_OK)
		return PROTOCOL_ERROR;
	
	/* Verify that the module signature matches */
	if (siglen != GKR_PKCS11_HANDSHAKE_LEN || 
	    memcmp (sig, GKR_PKCS11_HANDSHAKE, siglen) != 0) {
		g_warning ("pkcs11 module is not speaking correct protocol");
		return CKR_DEVICE_ERROR;
	}
	
	/* Mark session as valid and ready for action */
	sinfo->readonly = (flags & CKF_RW_SESSION) ? FALSE : TRUE;
	sinfo->valid = TRUE;
	
	/* 
	 * TODO: Once we have support for actually pulling out the
	 * peer's user/pid, we should use that instead of what the
	 * client tells us.
	 */ 
	sinfo->pid = pid;
	sinfo->manager = gkr_pk_object_manager_instance_for_client (pid);
	
	return CKR_OK;
}

static CK_RV 
session_C_GetSessionInfo (SessionInfo *sinfo, GkrPkcs11Message *req, 
                          GkrPkcs11Message *resp)
{
	uint32_t flags, state;

	/* No in arguments */

	if (gkr_keyring_login_is_unlocked ())
		state = sinfo->readonly ? CKS_RO_USER_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
	else 
		state = sinfo->readonly ? CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION;

	flags = 0;
	if (!sinfo->readonly)
		flags |= CKF_RW_SESSION;
	write_session_info (resp, 0, state, flags, sinfo->deverror);

	return CKR_OK;
}

static CK_RV
session_C_InitPIN (SessionInfo *sinfo, GkrPkcs11Message *req, 
                   GkrPkcs11Message *resp)
{
	/* We don't support this stuff. We don't support 'SO' logins. */
	return CKR_USER_NOT_LOGGED_IN;
}

static CK_RV
session_C_SetPIN (SessionInfo *sinfo, GkrPkcs11Message *req, 
                  GkrPkcs11Message *resp)
{
	/* 
	 * TODO: We may support this in the future. Since we are a 
	 * CKF_PROTECTED_AUTHENTICATION_PATH type token, we would 
	 * not accept a PIN, but instead prompt for it. 
	 */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_GetOperationState (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	/* Nope, We don't bend that way */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_SetOperationState (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	/* Nope. We don't bend that way */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_Login (SessionInfo *sinfo, GkrPkcs11Message *req, 
                 GkrPkcs11Message *resp)
{
	CK_BYTE_PTR pin = NULL;
	CK_ULONG user_type, pin_len;
	
	if (gkr_pkcs11_message_read_uint32 (req, &user_type) != CKR_OK)
		return PROTOCOL_ERROR;
	if (!read_byte_array (req, &pin, &pin_len))
		return PROTOCOL_ERROR;

	if (user_type != CKU_USER) {

		/* Readonly session, SO can't log in */
		if (sinfo->readonly)
			return CKR_SESSION_READ_ONLY_EXISTS;
		
		/* Actually SO can't log in at all ... */
		/* PKCS#11 QUESTION: What should we really be returning here? */
		return CKR_USER_TYPE_INVALID;
	}
	
	/* 
	 * Implement by unlocking gnome-keyring default keyring, since we 
	 * a CKF_PROTECTED_AUTHENTICATION_PATH type token, we would 
	 * not accept a PIN, but instead prompt for it. 
	 */
	if (!gkr_keyring_login_unlock (NULL))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

static CK_RV
session_C_Logout (SessionInfo *sinfo, GkrPkcs11Message *req, 
                  GkrPkcs11Message *resp)
{
	if (!gkr_keyring_login_is_unlocked ())
		return CKR_USER_NOT_LOGGED_IN;
	
	/* 
	 * TODO: What do we do here. I don't think we actually want to
	 * lock the login keyring.
	 */ 
	
	return CKR_OK;
}

/* -----------------------------------------------------------------------------
 * OBJECT OPERATIONS
 */

static CK_RV
session_C_CreateObject (SessionInfo *sinfo, GkrPkcs11Message *req, 
                        GkrPkcs11Message *resp)
{
	GkrPkObjectManager *manager;
	CK_ATTRIBUTE_PTR attr;
	CK_OBJECT_CLASS cls;
	GkrPkObject *object;
	GArray *attrs = NULL;
	CK_BBOOL token;
	GError *err = NULL;
	gboolean res;
	guint i;
	CK_RV ret;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;

	if (!(attrs = read_attribute_array (req)))
		return PROTOCOL_ERROR;

	if (!gkr_pk_attributes_ulong (attrs, CKA_CLASS, &cls)) {
	    	ret = CKR_TEMPLATE_INCOMPLETE;
	    	goto done;
	} 
	
	/* Can only create public objects unless logged in */
	if (!gkr_keyring_login_is_unlocked () && gkc_pk_class_is_private (cls)) {
		ret = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}
	
	/* Find out if its a token object or not */
	token = CK_FALSE;
	for (i = 0; i < attrs->len; ++i) {
		attr = &(g_array_index (attrs, CK_ATTRIBUTE, i));
		if (attr->type == CKA_TOKEN) {
			if (attr && attr->pValue && attr->ulValueLen == sizeof (CK_BBOOL))
				token = *((CK_BBOOL*)attr->pValue);
				
			/* Mark that attribute as used */
			gkr_pk_attribute_consume (attr);
			break;
		}
	}
	
	/* A readonly session cannot create token objects */
	if (token && sinfo->readonly) {
		ret = CKR_SESSION_READ_ONLY;
		goto done;
	}

	/* Create the object with the right object manager */
	manager = token ? gkr_pk_object_manager_for_token () : sinfo->manager;
	ret = gkr_pk_object_create (manager, attrs, &object);
	                 		
	if (ret != CKR_OK) 
		goto done;

	g_return_val_if_fail (object, CKR_GENERAL_ERROR);
		
	/* Token objects get stored in the main object storage */
	if (token) {
		g_return_val_if_fail (object->storage != NULL, CKR_GENERAL_ERROR);
		res = gkr_pk_object_storage_add (gkr_pk_object_storage_get (), object, &err);
		if (!res) {
			g_warning ("couldn't write created object to disk: %s", 
			           err && err->message ? err->message : "");
			g_clear_error (&err);
			ret = CKR_GENERAL_ERROR;
			goto done;
		}
			
	/* Session objects are owned by the session */
	} else {
		session_add_object (sinfo, object);
	}

	gkr_pkcs11_message_write_uint32 (resp, object->handle);
	ret = CKR_OK;
	
done:
	g_object_unref (object);
	gkr_pk_attributes_free (attrs);
	return ret;
}

static CK_RV
session_C_CopyObject (SessionInfo *sinfo, GkrPkcs11Message *req, 
                      GkrPkcs11Message *resp)
{
	/* 
	 * TODO: We need to implement this, initially perhaps only 
	 * only for session objects.
	 */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DestroyObject (SessionInfo *sinfo, GkrPkcs11Message *req, 
                         GkrPkcs11Message *resp)
{
	CK_OBJECT_HANDLE obj;
	GkrPkObjectManager *manager;
	GkrPkObject *object;
	CK_RV ret = CKR_OK;
	gboolean res;
	GError *err = NULL;
	CK_BBOOL priv;
	
	if (gkr_pkcs11_message_read_uint32 (req, &obj) != CKR_OK)
		return PROTOCOL_ERROR;
	
	/* Find the object in question */
	if (obj & GKR_PK_OBJECT_IS_PERMANENT)
		manager = gkr_pk_object_manager_for_token ();
	else
		manager = sinfo->manager;
		
	object = gkr_pk_object_manager_lookup (manager, obj);
	if (!object)
		return CKR_OBJECT_HANDLE_INVALID;
		
	/* We can only destroy public objects unless logged in */
	if (!gkr_keyring_login_is_unlocked ()) {
		ret = gkr_pk_object_get_bool (object, CKA_PRIVATE, &priv);
		g_return_val_if_fail (ret == CKR_OK, CKR_GENERAL_ERROR);
		
		if (priv)
			return CKR_USER_NOT_LOGGED_IN;
	}
	
	/* A token object */
	if (obj & GKR_PK_OBJECT_IS_PERMANENT) {

		/* A readonly session cannot destroy token objects */
		if (sinfo->readonly)
			return CKR_SESSION_READ_ONLY;
			
		g_return_val_if_fail (object->storage, CKR_GENERAL_ERROR);
		res = gkr_pk_object_storage_remove (object->storage, object, &err);
		if (!res) {
			g_warning ("couldn't remove object from disk: %s", 
			           err && err->message ? err->message : "");
			g_clear_error (&err);
			ret = CKR_GENERAL_ERROR;
		}
	
	/* A session object */
	} else {
		/* 
		 * TODO: This just hides the object, does not destroy. 
		 * The problem is that we need to locate the actual
		 * session where this is owned, which we currently 
		 * don't track.
		 */
		gkr_pk_object_manager_unregister (manager, object);
		ret = CKR_OK;
	}
		 
	return ret;
}

static CK_RV
session_C_GetObjectSize (SessionInfo *sinfo, GkrPkcs11Message *req, 
                         GkrPkcs11Message *resp)
{
	/* TODO: We need to implement this */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_GetAttributeValue (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	GkrPkObject *object;
	GArray* attrs;
	CK_RV soft_ret = CKR_OK;
	CK_RV ret = CKR_OK;
	
	ret = read_object (req, sinfo, &object);
	if (ret != CKR_OK)
		return ret;

	if (!(attrs = read_attribute_array (req)))
		return PROTOCOL_ERROR;
		
	ret = gkr_pk_object_get_attributes (object, attrs);

	/* Certain ones aren't real failures */
	switch (ret) {
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
		soft_ret = ret;
		ret = CKR_OK;
		break;
	case CKR_BUFFER_TOO_SMALL:
		g_assert (FALSE && "we shouldn't be returning this anywhere");
		break;
	};
	
	if (ret == CKR_OK) {
		gkr_pkcs11_message_write_attribute_array (resp, (CK_ATTRIBUTE_PTR)attrs->data, 
		                                                 attrs->len);
		gkr_pkcs11_message_write_uint32 (resp, soft_ret);
	}
	
	/* Attributes have been filled in with allocated values, so deep free */
	gkr_pk_attributes_free (attrs);
	
	return ret;
}

static CK_RV
session_C_SetAttributeValue (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	GkrPkObject *object;
	GArray* attrs;
	CK_RV ret;
	
	ret = read_object (req, sinfo, &object);
	if (ret != CKR_OK)
		return ret;

	if (!(attrs = read_attribute_array (req)))
		return PROTOCOL_ERROR;
		
	ret = gkr_pk_object_set_attributes (object, attrs);
	gkr_pk_attributes_free (attrs);
	
	return ret;
}

static void 
free_object_list (gpointer data)
{
	GList *l, *objects = data;
	for (l = objects; l; l = g_list_next (l)) 
		g_object_unref (l->data);
	g_list_free (objects);
}

static CK_RV
session_C_FindObjectsInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                           GkrPkcs11Message *resp)
{
	CK_BBOOL token;
	GList *l, *objects = NULL;
	GArray *attrs;
	gboolean all;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;
	
	if (!(attrs = read_attribute_array (req)))
		return PROTOCOL_ERROR;
	
	all = !gkr_pk_attributes_boolean (attrs, CKA_TOKEN, &token);
	objects = NULL;
	
	/* All or only token objects? */
	if(all || token) {
		l = gkr_pk_object_manager_find (gkr_pk_object_manager_for_token (), 0, attrs);
		objects = g_list_concat (objects, l);
	}
	
	/* All or only session objects? */
	if (all || !token) {
		l = gkr_pk_object_manager_find (sinfo->manager, 0, attrs);
		objects = g_list_concat (objects, l);
	}
	
	for (l = objects; l; l = g_list_next (l))
		g_object_ref (GKR_PK_OBJECT (l->data));
	begin_operation (sinfo, OPERATION_FIND, objects, free_object_list);
	
	gkr_pk_attributes_free (attrs);
	
	/* No response */
	return CKR_OK;
}

static CK_RV
session_C_FindObjects (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	GkrPkObject *obj;
	GList* objects;
	CK_ULONG max, n_objects, i;

	if (sinfo->operation_type != OPERATION_FIND)
		return CKR_OPERATION_NOT_INITIALIZED;
	
	if (gkr_pkcs11_message_read_uint32 (req, &max) != CKR_OK)
		return PROTOCOL_ERROR;
	
	objects = (GList*)sinfo->operation_data;
	
	/* Write out an array of ulongs */
	g_assert (gkr_pkcs11_message_verify_part (resp, "au"));
	
	/* First the number returned */
	n_objects = MIN (max, g_list_length (objects));
	gkr_buffer_add_uint32 (&resp->buffer, n_objects);
	
	/* Now each of them */
	for (i = 0; i < n_objects; ++i) {
		obj = GKR_PK_OBJECT (objects->data);
		objects = g_list_remove (objects, obj);
		
		g_assert (obj);
		g_assert (obj->handle);
		
		gkr_buffer_add_uint32 (&resp->buffer, obj->handle);
		g_object_unref (obj);
	}

	/* In case we get called again, or there are leftovers */
	sinfo->operation_data = objects;
	
	return CKR_OK;
}

static CK_RV
session_C_FindObjectsFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                            GkrPkcs11Message *resp)
{
	if (sinfo->operation_type != OPERATION_FIND)
		return CKR_OPERATION_NOT_INITIALIZED;
	
	finish_operation (sinfo);
	return CKR_OK;
}

/* -----------------------------------------------------------------------------
 * ENCRYPTION OPERATIONS
 */

typedef struct _CryptContext {
	CK_MECHANISM_TYPE mechanism;	
	GkrPkObject *key;
} CryptContext;

static CryptContext*
new_crypt_context (CK_MECHANISM_TYPE mech, GkrPkObject *key)
{
	CryptContext *ctx;
	g_assert (key);
	ctx = g_new0 (CryptContext, 1);
	ctx->mechanism = mech;
	ctx->key = key;
	g_object_ref (key);
	return ctx;
}

static void
free_crypt_context (gpointer data)
{
	CryptContext *ctx = (CryptContext*)data;
	if (ctx->key)
		g_object_unref (ctx->key);
	g_free (ctx);
}

static CK_RV
session_C_EncryptInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	GkrPkObject *key;
	CK_MECHANISM mech;
	CK_RV ret;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;

	if (!read_mechanism (req, &mech))
		return PROTOCOL_ERROR;
	ret = read_object (req, sinfo, &key);
	if (ret != CKR_OK)
		return ret;
		
	switch (mech.mechanism) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_encrypt (key, NULL, NULL, 0, NULL, 0);
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};
		
	if (ret == CKR_OK)
		begin_operation (sinfo, OPERATION_ENCRYPT, 
		                 new_crypt_context (mech.mechanism, key), 
		                 free_crypt_context);
	
 	return ret;
}

static CK_RV
session_C_Encrypt (SessionInfo *sinfo, GkrPkcs11Message *req, 
                   GkrPkcs11Message *resp)
{
	CryptContext *ctx;
	CK_BYTE_PTR plain;
	CK_ULONG n_plain;
	gsize n_encrypted;
	guchar *encrypted;
	CK_RV ret;
	
	if (sinfo->operation_type != OPERATION_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!read_byte_array (req, &plain, &n_plain))
		return PROTOCOL_ERROR;
	
	ctx = (CryptContext*)sinfo->operation_data;
	switch (ctx->mechanism) {
	case CKM_RSA_PKCS:
		ret = gkr_pkcs11_rsa_encrypt (ctx->key, gkr_crypto_rsa_pad_two, 
		                              plain, n_plain, 
	                                      &encrypted, &n_encrypted);
		break;
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_encrypt (ctx->key, gkr_crypto_rsa_pad_raw, 
		                              plain, n_plain, 
	                                      &encrypted, &n_encrypted);
		break;
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	};
	
	if (ret == CKR_OK) {
		g_return_val_if_fail (encrypted, CKR_GENERAL_ERROR);
		ret = gkr_pkcs11_message_write_byte_array (resp, encrypted, n_encrypted);
		g_free (encrypted);
	}
	
	finish_operation (sinfo);
	return ret;
}

static CK_RV
session_C_EncryptUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                         GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental encryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_EncryptFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                        GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental encryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * DECRYPTION OPERATIONS
 */

static CK_RV
session_C_DecryptInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	GkrPkObject *key;
	CK_MECHANISM mech;
	CK_RV ret;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;

	if (!read_mechanism (req, &mech))
		return PROTOCOL_ERROR;
	ret = read_object (req, sinfo, &key);
	if (ret != CKR_OK)
		return ret;
		
	switch (mech.mechanism) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_decrypt (key, NULL, NULL, 0, NULL, 0);
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};
		
	if (ret == CKR_OK)
		begin_operation (sinfo, OPERATION_DECRYPT, 
		                 new_crypt_context (mech.mechanism, key), 
		                 free_crypt_context);
	
 	return ret;
}

static CK_RV
session_C_Decrypt (SessionInfo *sinfo, GkrPkcs11Message *req, 
                   GkrPkcs11Message *resp)
{
	CryptContext *ctx;
	CK_BYTE_PTR encrypted;
	CK_ULONG n_encrypted;
	gsize n_data;
	guchar *data;
	CK_RV ret;
	
	if (sinfo->operation_type != OPERATION_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!read_byte_array (req, &encrypted, &n_encrypted))
		return PROTOCOL_ERROR;
	
	ctx = (CryptContext*)sinfo->operation_data;
	switch (ctx->mechanism) {
	case CKM_RSA_PKCS:
		ret = gkr_pkcs11_rsa_decrypt (ctx->key, gkr_crypto_rsa_unpad_two, 
		                              encrypted, n_encrypted, 
	                                      &data, &n_data);
		break;
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_decrypt (ctx->key, NULL, 
		                              encrypted, n_encrypted, 
	                                      &data, &n_data);
		break;
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	};
	
	if (ret == CKR_OK) {
		g_return_val_if_fail (data, CKR_GENERAL_ERROR);
		ret = gkr_pkcs11_message_write_byte_array (resp, data, n_data);
		g_free (data);
	}
	
	finish_operation (sinfo);
	return ret;
}

static CK_RV
session_C_DecryptUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                         GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental decryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DecryptFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                        GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental decryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * DIGEST OPERATIONS
 */

static CK_RV
session_C_DigestInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                      GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_Digest (SessionInfo *sinfo, GkrPkcs11Message *req, 
                  GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DigestUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                        GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DigestKey (SessionInfo *sinfo, GkrPkcs11Message *req, 
                     GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DigestFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * SIGN OPERATIONS
 */

static CK_RV
session_C_SignInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                    GkrPkcs11Message *resp)
{
	GkrPkObject *key;
	CK_MECHANISM mech;
	CK_RV ret;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;

	if (!read_mechanism (req, &mech))
		return PROTOCOL_ERROR;
	ret = read_object (req, sinfo, &key);
	if (ret != CKR_OK)
		return ret;
		
	switch (mech.mechanism) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_sign (key, NULL, NULL, 0, NULL, 0);
		break;
	case CKM_DSA:
		ret = gkr_pkcs11_dsa_sign (key, NULL, 0, NULL, 0);
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};
		
	if (ret == CKR_OK)
		begin_operation (sinfo, OPERATION_SIGN, 
		                 new_crypt_context (mech.mechanism, key), 
		                 free_crypt_context);
	
 	return ret;
}

static CK_RV
session_C_Sign (SessionInfo *sinfo, GkrPkcs11Message *req, 
                GkrPkcs11Message *resp)
{
	CryptContext *ctx;
	CK_BYTE_PTR data;
	CK_ULONG n_data;
	gsize n_signature;
	guchar *signature;
	CK_RV ret;
	
	if (sinfo->operation_type != OPERATION_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!read_byte_array (req, &data, &n_data))
		return PROTOCOL_ERROR;
	
	ctx = (CryptContext*)sinfo->operation_data;
	switch (ctx->mechanism) {
	case CKM_RSA_PKCS:
		ret = gkr_pkcs11_rsa_sign (ctx->key, gkr_crypto_rsa_pad_one, 
		                           data, n_data, 
		                           &signature, &n_signature);
		break;
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_sign (ctx->key, gkr_crypto_rsa_pad_raw,
		                           data, n_data, 
	                                   &signature, &n_signature);
		break;
	case CKM_DSA:
		ret = gkr_pkcs11_dsa_sign (ctx->key, data, n_data, 
		                           &signature, &n_signature);
		break;
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	};
	
	if (ret == CKR_OK) {
		g_return_val_if_fail (signature, CKR_GENERAL_ERROR);
		ret = gkr_pkcs11_message_write_byte_array (resp, signature, n_signature);
		g_free (signature);
	}
	
	finish_operation (sinfo);
	return ret;
}

static CK_RV
session_C_SignUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                      GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental signing */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_SignFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                     GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental signing */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_SignRecoverInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                           GkrPkcs11Message *resp)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_SignRecover (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * VERIFY OPERATIONS
 */

static CK_RV
session_C_VerifyInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                      GkrPkcs11Message *resp)
{
	GkrPkObject *key;
	CK_MECHANISM mech;
	CK_RV ret;
	
	if (sinfo->operation_type)
		return CKR_OPERATION_ACTIVE;

	if (!read_mechanism (req, &mech))
		return PROTOCOL_ERROR;
	ret = read_object (req, sinfo, &key);
	if (ret != CKR_OK)
		return ret;
		
	switch (mech.mechanism) {
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_verify (key, NULL, NULL, 0, NULL, 0);
		break;
	case CKM_DSA:
		ret = gkr_pkcs11_dsa_verify (key, NULL, 0, NULL, 0);
		break;
	default:
		ret = CKR_MECHANISM_INVALID;
		break;
	};
		
	if (ret == CKR_OK)
		begin_operation (sinfo, OPERATION_VERIFY, 
		                 new_crypt_context (mech.mechanism, key), 
		                 free_crypt_context);
	
 	return ret;
}

static CK_RV
session_C_Verify (SessionInfo *sinfo, GkrPkcs11Message *req, 
                  GkrPkcs11Message *resp)
{
	CryptContext *ctx;
	CK_BYTE_PTR signature, data;
	CK_ULONG n_signature, n_data;
	CK_RV ret;
	
	if (sinfo->operation_type != OPERATION_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (!read_byte_array (req, &data, &n_data))
		return PROTOCOL_ERROR;
	if (!read_byte_array (req, &signature, &n_signature))
		return PROTOCOL_ERROR;
	
	ctx = (CryptContext*)sinfo->operation_data;
	switch (ctx->mechanism) {
	case CKM_RSA_PKCS:
		ret = gkr_pkcs11_rsa_verify (ctx->key, gkr_crypto_rsa_pad_one, 
		                             data, n_data, 
	                                     signature, n_signature);
		break;
	case CKM_RSA_X_509:
		ret = gkr_pkcs11_rsa_verify (ctx->key, gkr_crypto_rsa_pad_raw, 
		                             data, n_data, 
	                                     signature, n_signature);
		break;
	case CKM_DSA:
		ret = gkr_pkcs11_dsa_verify (ctx->key, data, n_data, 
		                             signature, n_signature);
		break;
	default:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
		break;
	};
	
	finish_operation (sinfo);
	return ret;
}

static CK_RV
session_C_VerifyUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                        GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental verifying */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_VerifyFinal (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	/* RSA keys don't support this incremental verifying */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_VerifyRecoverInit (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	/* RSA keys don't support this recoverable signing */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_VerifyRecover (SessionInfo *sinfo, GkrPkcs11Message *req, 
                         GkrPkcs11Message *resp)
{
	/* RSA keys don't support this recoverable signing */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * COMPOUND OPERATIONS
 */

static CK_RV
session_C_DigestEncryptUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                               GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DecryptDigestUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                               GkrPkcs11Message *resp)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_SignEncryptUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                             GkrPkcs11Message *resp)
{
	/* Can't do this with an RSA key */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DecryptVerifyUpdate (SessionInfo *sinfo, GkrPkcs11Message *req, 
                               GkrPkcs11Message *resp)
{
	/* Can't do this with an RSA key */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * KEY OPERATIONS
 */

static CK_RV
session_C_GenerateKey (SessionInfo *sinfo, GkrPkcs11Message *req, 
                       GkrPkcs11Message *resp)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_GenerateKeyPair (SessionInfo *sinfo, GkrPkcs11Message *req, 
                           GkrPkcs11Message *resp)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_WrapKey (SessionInfo *sinfo, GkrPkcs11Message *req, 
                   GkrPkcs11Message *resp)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_UnwrapKey (SessionInfo *sinfo, GkrPkcs11Message *req, 
                     GkrPkcs11Message *resp)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
session_C_DeriveKey (SessionInfo *sinfo, GkrPkcs11Message *req, 
                     GkrPkcs11Message *resp)
{
	/* RSA keys don't support derivation */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------------
 * RANDOM OPERATIONS
 */

static CK_RV
session_C_SeedRandom (SessionInfo *sinfo, GkrPkcs11Message *req, 
                      GkrPkcs11Message *resp)
{
	/* We don't have a RNG */
 	return CKR_RANDOM_NO_RNG;
}

static CK_RV
session_C_GenerateRandom (SessionInfo *sinfo, GkrPkcs11Message *req, 
                          GkrPkcs11Message *resp)
{
	/* We don't have a RNG */
 	return CKR_RANDOM_NO_RNG;
}

/* -----------------------------------------------------------------------------
 * SESSION THREAD 
 */

static SessionInfo*
session_info_new ()
{
	SessionInfo *sinfo = g_new0 (SessionInfo, 1);
	sinfo->objects = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_object_unref);
	return sinfo;
}

static void 
session_info_free (SessionInfo *sinfo)
{
	if (sinfo->manager)
		g_object_unref (sinfo->manager);
	g_hash_table_destroy (sinfo->objects);
	g_free (sinfo);
}

static gboolean
session_process (SessionInfo *sinfo, GkrPkcs11Message *req, 
                 GkrPkcs11Message *resp)
{
	CK_RV ret = CKR_OK;
	
	/* This should have been checked by the parsing code */
	g_assert (req->call_id > PKCS11_CALL_ERROR);
	g_assert (req->call_id < PKCS11_CALL_MAX);
	
	/* Prepare a response for the function to fill in */
	gkr_pkcs11_message_prep (resp, req->call_id, GKR_PKCS11_RESPONSE);
	
	switch(req->call_id) {
	
	#define CASE_CALL(name) \
		case PKCS11_CALL_##name: \
			ret = session_##name (sinfo, req, resp); \
			break; 
	CASE_CALL(C_OpenSession)
	CASE_CALL(C_GetSessionInfo)
	CASE_CALL(C_InitPIN)
	CASE_CALL(C_SetPIN)
	CASE_CALL(C_GetOperationState)
	CASE_CALL(C_SetOperationState)
	CASE_CALL(C_Login)
	CASE_CALL(C_Logout)
	CASE_CALL(C_CreateObject)
	CASE_CALL(C_CopyObject)
	CASE_CALL(C_DestroyObject)
	CASE_CALL(C_GetObjectSize)
	CASE_CALL(C_GetAttributeValue)
	CASE_CALL(C_SetAttributeValue)
	CASE_CALL(C_FindObjectsInit)
	CASE_CALL(C_FindObjects)
	CASE_CALL(C_FindObjectsFinal)
	CASE_CALL(C_EncryptInit)
	CASE_CALL(C_Encrypt)
	CASE_CALL(C_EncryptUpdate)
	CASE_CALL(C_EncryptFinal)
	CASE_CALL(C_DecryptInit)
	CASE_CALL(C_Decrypt)
	CASE_CALL(C_DecryptUpdate)
	CASE_CALL(C_DecryptFinal)
	CASE_CALL(C_DigestInit)
	CASE_CALL(C_Digest)
	CASE_CALL(C_DigestUpdate)
	CASE_CALL(C_DigestKey)
	CASE_CALL(C_DigestFinal)
	CASE_CALL(C_SignInit)
	CASE_CALL(C_Sign)
	CASE_CALL(C_SignUpdate)
	CASE_CALL(C_SignFinal)
	CASE_CALL(C_SignRecoverInit)
	CASE_CALL(C_SignRecover)
	CASE_CALL(C_VerifyInit)
	CASE_CALL(C_Verify)
	CASE_CALL(C_VerifyUpdate)
	CASE_CALL(C_VerifyFinal)
	CASE_CALL(C_VerifyRecoverInit)
	CASE_CALL(C_VerifyRecover)
	CASE_CALL(C_DigestEncryptUpdate)
	CASE_CALL(C_DecryptDigestUpdate)
	CASE_CALL(C_SignEncryptUpdate)
	CASE_CALL(C_DecryptVerifyUpdate)
	CASE_CALL(C_GenerateKey)
	CASE_CALL(C_GenerateKeyPair)
	CASE_CALL(C_WrapKey)
	CASE_CALL(C_UnwrapKey)
	CASE_CALL(C_DeriveKey)
	CASE_CALL(C_SeedRandom)
	CASE_CALL(C_GenerateRandom)
	#undef CASE_CALL
	
	default:
		/* This should have been caught by the parse code */
		g_return_val_if_reached (FALSE);
		break;
	};

	/* Parsing errors? */
	if (gkr_pkcs11_message_buffer_error (req)) {
		g_warning ("invalid request from module, probably too short");
		ret = PROTOCOL_ERROR;
	}

	/* Out of memory errors? */
	if (gkr_pkcs11_message_buffer_error (resp)) {
		g_warning ("out of memory error putting together message");
		ret = CKR_DEVICE_MEMORY;
	}
	
	/* A filled in response */
	if (ret == CKR_OK) {
		
		/*
		 * Since we're dealing with many many functions above generating
		 * these messages we want to make sure each of them actually
		 * does what it's supposed to.
		 */

		g_assert (gkr_pkcs11_message_is_verified (resp));
		g_assert (resp->call_type == GKR_PKCS11_RESPONSE);
		g_assert (resp->call_id == req->call_id);
		g_assert (gkr_pkcs11_calls[resp->call_id].response);
		g_assert (strcmp (gkr_pkcs11_calls[resp->call_id].response, 
		                  resp->signature) == 0);
		
	/* Fill in an error respnose */
	} else {
		/*
		 * When there's an error any operation automatically done.
		 * We make an exception for functions which we don't implement. 
		 */
		if (ret != CKR_FUNCTION_NOT_SUPPORTED)
			finish_operation (sinfo);
		
		gkr_pkcs11_message_prep (resp, PKCS11_CALL_ERROR, GKR_PKCS11_RESPONSE);
		gkr_buffer_add_uint32 (&resp->buffer, (uint32_t)ret);

		/* Out of memory errors? */
		g_assert (!gkr_pkcs11_message_buffer_error (resp));
	}
	
	return TRUE;
}

static gboolean
session_read (int sock, guchar* data, size_t len)
{
	int r;
	
	g_assert (sock >= 0);
	g_assert (data);
	g_assert (len > 0);

	while (len > 0) {
	
		/* Don't block other threads during the read */
		gkr_async_begin_concurrent ();

			r = read (sock, data, len);
			
		gkr_async_end_concurrent ();
		
		if (r == 0) {
			/* Connection was closed on client */
			return FALSE;
		} else if (r == -1) {
			if (errno == EBADF || errno == 0) {
				/* Connection was closed by main thread */
				return FALSE;
			} else if (errno != EAGAIN && errno != EINTR) {
				g_warning ("couldn't receive data: %s", strerror (errno));
				return FALSE;
			}
		} else {
			data += r;
			len -= r;
		}
	}
	
	return TRUE;
}

static gboolean
session_write (int sock, guchar* data, size_t len)
{
	int r;

	g_assert (sock >= 0);
	g_assert (data);
	g_assert (len > 0);

	while (len > 0) {
	
		/* Don't block other threads during the read */
		gkr_async_begin_concurrent ();
	
			r = write (sock, data, len);
		
		gkr_async_end_concurrent ();
		
		if (r == -1) {
			if (errno == EPIPE) {
				/* Connection closed from client */
				return FALSE;
			} else if (errno == EBADF || errno == 0) {
				/* Connection closed from main thread */
				return FALSE;
			} else if (errno != EAGAIN && errno != EINTR) {
				g_warning ("couldn't send data: %s", strerror (errno));
				return FALSE;
			}
		} else {
			data += r;
			len -= r;
		}
	}
	
	return TRUE;
}

static gboolean
session_read_credentials (int sock, pid_t *pid, uid_t *uid)
{
	gboolean ret;
	
	gkr_async_begin_concurrent ();
	
		ret = gkr_unix_credentials_read (sock, pid, uid) >= 0;
		
	gkr_async_end_concurrent ();
	
	return ret;
}

gpointer
gkr_pkcs11_daemon_session_thread (gpointer user_data)
{
	SessionInfo *sinfo;
	GkrPkcs11Message *req, *resp;
	guchar buf[4];
	CK_RV ret;
	uint32_t len;
	int sock;
	uid_t uid;
	pid_t pid;
	
	/* The argument to the worker thread is the socket */
	sock = GPOINTER_TO_INT (user_data);
	g_assert (sock >= 0);
	
	/* Make sure the credentials are appropriate */
	if (!session_read_credentials (sock, &pid, &uid))
		return NULL;
	if (getuid() != uid) {
		g_warning ("uid mismatch: %u, should be %u\n", (guint)uid, (guint)getuid());
		return NULL;
	}
	
	/* Setup our buffers */
	/* TODO: Do these need to be secure buffers? */
	req = gkr_pkcs11_message_new ((GkrBufferAllocator)g_realloc);
	resp = gkr_pkcs11_message_new ((GkrBufferAllocator)g_realloc);
	if (!req || !resp)
		g_error ("out of memory");
	
	sinfo = session_info_new ();
	
	/* The main thread loop */
	while (TRUE) {
		
		if (gkr_async_is_stopping ())
			break;
		
		gkr_pkcs11_message_reset (req);
		gkr_pkcs11_message_reset (resp);
		
		/* Read the number of bytes ... */
		if (!session_read (sock, buf, 4))
			break;
		len = gkr_buffer_decode_uint32 (buf);
		
		/* Allocate memory */
		if (len >= 0x0FFFFFFF) { 
			g_warning ("invalid message size from module: %u bytes", len); 
			break;
		}
		
		gkr_buffer_reserve (&req->buffer, req->buffer.len + len); 
		
		/* ... and read/parse in the actual message */
		if (!session_read (sock, req->buffer.buf, len))
			break;
		gkr_buffer_add_empty (&req->buffer, len);
		ret = gkr_pkcs11_message_parse (req, GKR_PKCS11_REQUEST);
		if (ret != CKR_OK)
			break;
			
		if (gkr_async_is_stopping ())
			break;
		
		/* ... send for processing ... */
		if (!session_process (sinfo, req, resp)) 
			break;
			
		if (gkr_async_is_stopping ())
			break;
		
		/* .. send back response length, and then response data */
		gkr_buffer_encode_uint32 (buf, resp->buffer.len);
		if(!session_write (sock, buf, 4) ||
		   !session_write (sock, resp->buffer.buf, resp->buffer.len))
			break;
	}
	
	session_info_free (sinfo);
	
	/* socket is closed elsewhere */
	shutdown (sock, SHUT_RDWR);
	
	return NULL;
}

