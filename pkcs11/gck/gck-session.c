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

#include "config.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11i.h"

#include "gck-attributes.h"
#include "gck-authenticator.h"
#include "gck-crypto.h"
#include "gck-key.h"
#include "gck-factory.h"
#include "gck-manager.h"
#include "gck-memory-store.h"
#include "gck-session.h"
#include "gck-sexp.h"
#include "gck-transaction.h"
#include "gck-util.h"

enum {
	PROP_0,
	PROP_MODULE,
	PROP_SLOT_ID,
	PROP_APARTMENT,
	PROP_HANDLE,
	PROP_READ_ONLY,
	PROP_MANAGER,
	PROP_LOGGED_IN
};

struct _GckSessionPrivate {

	CK_SESSION_HANDLE handle;
	CK_SLOT_ID slot_id;
	CK_ULONG apartment;

	GckModule *module;
	GckManager *manager;
	GckStore *store;

	CK_USER_TYPE logged_in;
	gboolean read_only;

	CK_NOTIFY notify_callback;
	CK_VOID_PTR application_ptr;
	
	/* Objects owned by this session */
	GHashTable *objects;

	/* Used for operations */
	void (*current_operation) (GckSession *self);
	GckObject *current_object;
	GckAuthenticator *authenticator;

	/* Used for find operations */
	GArray *found_objects;
	
	/* Used for crypto operations */
	GckSexp *crypto_sexp;
	CK_MECHANISM_TYPE crypto_mechanism;
	CK_ATTRIBUTE_TYPE crypto_method;
};

G_DEFINE_TYPE (GckSession, gck_session, G_TYPE_OBJECT);

static void add_object (GckSession *self, GckTransaction *transaction, GckObject *object);
static void remove_object (GckSession *self, GckTransaction *transaction, GckObject *object);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
cleanup_crypto (GckSession *self)
{
	g_assert (self->pv->current_operation == cleanup_crypto);

	if (self->pv->crypto_sexp) {
		gck_sexp_unref (self->pv->crypto_sexp);
		self->pv->crypto_sexp = NULL;
	}

	self->pv->crypto_mechanism = 0;
	self->pv->crypto_method = 0;

	g_assert (GCK_IS_KEY (self->pv->current_object));
	if (self->pv->current_object)
		g_object_unref (self->pv->current_object);
	self->pv->current_object = NULL;

	if (self->pv->authenticator) {
		g_object_set_data (G_OBJECT (self->pv->authenticator), "owned-by-session", NULL);
		g_object_unref (self->pv->authenticator);
		self->pv->authenticator = NULL;
	}

	self->pv->current_operation = NULL;
}

static CK_RV
prepare_crypto (GckSession *self, CK_MECHANISM_PTR mech, 
                CK_ATTRIBUTE_TYPE method, CK_OBJECT_HANDLE handle)
{
	GckObject *object;
	CK_MECHANISM_TYPE_PTR mechanisms;
	CK_ULONG n_mechanisms, i;
	gsize n_data;
	gboolean have;
	CK_RV rv;
	
	g_assert (GCK_IS_SESSION (self));

	/* Cancel any current operation */
	if (self->pv->current_operation) {
		(self->pv->current_operation) (self);
		g_assert (!self->pv->current_operation);
	}
	
	g_assert (!self->pv->crypto_sexp);
	
	/* First find the object */
	rv = gck_session_lookup_readable_object (self, handle, &object);
	if (rv != CKR_OK)
		return rv;
	
	if (!GCK_IS_KEY (object))
		return CKR_KEY_HANDLE_INVALID;

	/* Lookup the mechanisms this object can do */
	mechanisms = gck_object_get_attribute_data (object, self, CKA_ALLOWED_MECHANISMS, &n_data);
	g_return_val_if_fail (mechanisms, CKR_GENERAL_ERROR);
	g_return_val_if_fail (n_data % sizeof (CK_MECHANISM_TYPE) == 0, CKR_GENERAL_ERROR);
	n_mechanisms = n_data / sizeof (CK_MECHANISM_TYPE);
	
	/* See if ours is represented */
	have = FALSE;
	for (i = 0; !have && i < n_mechanisms; ++i) {
		if (mechanisms[i] == mech->mechanism)
			have = TRUE;
	}
	
	g_free (mechanisms);

	if (have == FALSE)
		return CKR_KEY_TYPE_INCONSISTENT;

	/* Check that the object can do this method */
	if (!gck_object_get_attribute_boolean (object, self, method, &have) || !have)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	
	/* Track the cyrpto object */
	self->pv->current_object = object;
	g_object_ref (object);
	
	/* And note what we're setup for */
	self->pv->current_operation = cleanup_crypto;
	self->pv->crypto_mechanism = mech->mechanism;
	self->pv->crypto_method = method;

	return CKR_OK;
}

static CK_RV
process_crypto (GckSession *self, CK_ATTRIBUTE_TYPE method, CK_BYTE_PTR bufone, 
                CK_ULONG n_bufone, CK_BYTE_PTR buftwo, CK_ULONG_PTR n_buftwo)
{
	CK_RV rv = CKR_OK;
	
	g_assert (GCK_IS_SESSION (self));

	if (self->pv->current_operation != cleanup_crypto)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (method != self->pv->crypto_method)
		return CKR_OPERATION_NOT_INITIALIZED;
	
	if (!bufone || !n_buftwo)
		rv = CKR_ARGUMENTS_BAD;
	
	if (rv == CKR_OK) {
		/* Load up the actual sexp we're going to use */
		if (!self->pv->crypto_sexp) {
			g_return_val_if_fail (GCK_IS_KEY (self->pv->current_object), CKR_GENERAL_ERROR);
			self->pv->crypto_sexp = gck_key_acquire_crypto_sexp (GCK_KEY (self->pv->current_object), self);
			if (!self->pv->crypto_sexp)
				rv = CKR_USER_NOT_LOGGED_IN;
		}
	}

	if (rv == CKR_OK) {
		g_assert (self->pv->crypto_mechanism);
		rv = gck_crypto_perform (gck_sexp_get (self->pv->crypto_sexp), self->pv->crypto_mechanism, 
		                         method, bufone, n_bufone, buftwo, n_buftwo);
	}
	
	/* Under these conditions the operation isn't complete */
	if (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_USER_NOT_LOGGED_IN || 
	    (rv == CKR_OK && buftwo == NULL))
		return rv;
	
	cleanup_crypto (self);
	return rv;
}

static void
cleanup_found (GckSession *self)
{
	g_assert (GCK_IS_SESSION (self));
	
	g_assert (self->pv->found_objects);
	g_array_free (self->pv->found_objects, TRUE);
	self->pv->found_objects = NULL;
	
	self->pv->current_operation = NULL;
}

static CK_RV
lookup_object_from_handle (GckSession *self, CK_OBJECT_HANDLE handle,
                           gboolean writable, GckObject **result)
{
	GckManager *manager;
	GckObject *object;
	gboolean is_private;
	gboolean is_token;
	gboolean is_modifiable;
	
	g_return_val_if_fail (result, CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_GENERAL_ERROR);
	
	if (handle == 0)
		return CKR_OBJECT_HANDLE_INVALID;

	/* Try looking up in the token manager */
	manager = gck_module_get_manager (self->pv->module);
	object = gck_manager_find_by_handle (manager, handle);
	is_token = TRUE;
	
	/* Try looking up in the session manager */
	if (object == NULL) {
		manager = gck_session_get_manager (self);
		object = gck_manager_find_by_handle (manager, handle);
		is_token = FALSE;
	}
	
	if (object == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	g_return_val_if_fail (manager, CKR_GENERAL_ERROR);
	
	/* 
	 * Check that we're not accessing private objects on a 
	 * non-logged in session 
	 */
	if (self->pv->logged_in != CKU_USER) {
		if (!gck_object_get_attribute_boolean (object, self, CKA_PRIVATE, &is_private))
			is_private = FALSE;
		if (is_private)
			return CKR_USER_NOT_LOGGED_IN;
	}
	
	/* 
	 * If we're going to write to this object check that we're in a 
	 * writable session and object is modifiable.
	 */
	if (writable) {
		if (is_token) {
			if (!gck_object_get_transient (object))
				if (gck_module_get_write_protected (self->pv->module))
					return CKR_TOKEN_WRITE_PROTECTED;
			if (self->pv->read_only)
				return CKR_SESSION_READ_ONLY;
		}
		if (!gck_object_get_attribute_boolean (object, self, CKA_MODIFIABLE, &is_modifiable))
			is_modifiable = FALSE;
		if (!is_modifiable) /* What's a better return code in this case? */
			return CKR_ATTRIBUTE_READ_ONLY;
	}
	
	*result = object;
	return CKR_OK;
}


static gboolean
complete_remove (GckTransaction *transaction, GckSession *self, GckObject *object)
{
	if (gck_transaction_get_failed (transaction))
		add_object (self, NULL, object);
	g_object_unref (object);
	return TRUE;
}

static void
remove_object (GckSession *self, GckTransaction *transaction, GckObject *object)
{
	g_assert (GCK_IS_SESSION (self));
	g_assert (GCK_IS_OBJECT (object));
	
	g_object_ref (object);
	
	gck_manager_unregister_object (self->pv->manager, object);
	if (!g_hash_table_remove (self->pv->objects, object))
		g_return_if_reached ();
	g_object_set (object, "store", NULL, NULL);
	
	if (transaction)
		gck_transaction_add (transaction, self, (GckTransactionFunc)complete_remove, 
		                     g_object_ref (object));
	
	g_object_unref (object);
}

static gboolean
complete_add (GckTransaction *transaction, GckSession *self, GckObject *object)
{
	if (gck_transaction_get_failed (transaction))
		remove_object (self, NULL, object);
	g_object_unref (object);
	return TRUE;
}

static void
add_object (GckSession *self, GckTransaction *transaction, GckObject *object)
{
	g_assert (GCK_IS_SESSION (self));
	g_assert (GCK_IS_OBJECT (object));
	
	/* Must not already be associated with a session or manager */
	g_return_if_fail (gck_object_get_manager (object) == NULL);
	g_return_if_fail (g_object_get_data (G_OBJECT (object), "owned-by-session") == NULL);
	g_return_if_fail (g_hash_table_lookup (self->pv->objects, object) == NULL);
	
	g_hash_table_insert (self->pv->objects, object, g_object_ref (object));
	g_object_set_data (G_OBJECT (object), "owned-by-session", self);
	gck_manager_register_object (self->pv->manager, object);
	g_object_set (object, "store", self->pv->store, NULL);

	if (transaction)
		gck_transaction_add (transaction, self, (GckTransactionFunc)complete_add, 
		                     g_object_ref (object));
}

static gboolean
attributes_find_boolean (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, 
                         CK_ATTRIBUTE_TYPE type, CK_BBOOL *value)
{
	CK_ULONG i;
	
	g_assert (attrs || !n_attrs);
	g_assert (value);
	
	for (i = 0; i < n_attrs; ++i) {
		if (attrs[i].type == type && 
		    attrs[i].pValue != NULL && 
		    attrs[i].ulValueLen == sizeof (CK_BBOOL)) {
			*value = *((CK_BBOOL*)attrs[i].pValue);
			return TRUE;
		}
	}
	
	return FALSE;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */


static GObject* 
gck_session_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckSession *self = GCK_SESSION (G_OBJECT_CLASS (gck_session_parent_class)->constructor(type, n_props, props));
	CK_ATTRIBUTE attr;

	g_return_val_if_fail (self, NULL);	

	/* Register store attributes */
	attr.type = CKA_LABEL;
	attr.pValue = "";
	attr.ulValueLen = 0;
	gck_store_register_schema (self->pv->store, &attr, NULL, 0);
	
	return G_OBJECT (self);
}

static void
gck_session_init (GckSession *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCK_TYPE_SESSION, GckSessionPrivate);
	self->pv->objects = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, gck_util_dispose_unref);
	self->pv->read_only = TRUE;
	
	/* Create the store and register attributes */
	self->pv->store = GCK_STORE (gck_memory_store_new ());
}

static void
gck_session_dispose (GObject *obj)
{
	GckSession *self = GCK_SESSION (obj);

	/* Cleanup any current operation */
	if (self->pv->current_operation)
		(self->pv->current_operation) (self);
	g_assert (!self->pv->current_operation);

	if (self->pv->module)
		g_object_unref (self->pv->module);
	self->pv->module = NULL;

	if (self->pv->authenticator) {
		g_object_set_data (G_OBJECT (self->pv->authenticator), "owned-by-session", NULL);
		g_object_unref (self->pv->authenticator);
		self->pv->authenticator = NULL;
	}

	if (self->pv->manager)
		g_object_unref (self->pv->manager);
	self->pv->manager = NULL;
	
	g_hash_table_remove_all (self->pv->objects);
	
	G_OBJECT_CLASS (gck_session_parent_class)->dispose (obj);
}

static void
gck_session_finalize (GObject *obj)
{
	GckSession *self = GCK_SESSION (obj);

	g_assert (self->pv->module == NULL);
	g_assert (self->pv->manager == NULL);
	
	g_hash_table_destroy (self->pv->objects);
	self->pv->objects = NULL;
	
	g_object_unref (self->pv->store);
	self->pv->store = NULL;
	
	G_OBJECT_CLASS (gck_session_parent_class)->finalize (obj);
}

static void
gck_session_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckSession *self = GCK_SESSION (obj);
	
	switch (prop_id) {
	case PROP_MODULE:
		g_return_if_fail (!self->pv->module);
		self->pv->module = g_value_get_object (value);
		g_return_if_fail (self->pv->module);
		g_object_ref (self->pv->module);
		break;
	case PROP_MANAGER:
		g_return_if_fail (!self->pv->manager);
		self->pv->manager = g_value_get_object (value);
		g_return_if_fail (self->pv->manager);
		g_object_ref (self->pv->manager);
		break;
	case PROP_SLOT_ID:
		self->pv->slot_id = g_value_get_ulong (value);
		break;
	case PROP_APARTMENT:
		self->pv->apartment = g_value_get_ulong (value);
		break;
	case PROP_HANDLE:
		self->pv->handle = g_value_get_ulong (value);
		g_return_if_fail (self->pv->handle != 0);
		break;
	case PROP_READ_ONLY:
		self->pv->read_only = g_value_get_boolean (value);
		break;
	case PROP_LOGGED_IN:
		gck_session_set_logged_in (self, g_value_get_ulong (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_session_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GckSession *self = GCK_SESSION (obj);
	
	switch (prop_id) {
	case PROP_MODULE:
		g_value_set_object (value, gck_session_get_module (self));
		break;
	case PROP_MANAGER:
		g_value_set_object (value, gck_session_get_manager (self));
		break;
	case PROP_SLOT_ID:
		g_value_set_ulong (value, gck_session_get_slot_id (self));
		break;
	case PROP_APARTMENT:
		g_value_set_ulong (value, gck_session_get_apartment (self));
		break;
	case PROP_HANDLE:
		g_value_set_ulong (value, gck_session_get_handle (self));
		break;
	case PROP_READ_ONLY:
		g_value_set_boolean (value, gck_session_get_read_only (self));
		break;
	case PROP_LOGGED_IN:
		g_value_set_ulong (value, gck_session_get_logged_in (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_session_class_init (GckSessionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gck_session_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GckSessionPrivate));

	gobject_class->constructor = gck_session_constructor;
	gobject_class->dispose = gck_session_dispose;
	gobject_class->finalize = gck_session_finalize;
	gobject_class->set_property = gck_session_set_property;
	gobject_class->get_property = gck_session_get_property;
    
	g_object_class_install_property (gobject_class, PROP_MODULE,
	         g_param_spec_object ("module", "Module", "Module this session belongs to", 
	                              GCK_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_MANAGER,
	         g_param_spec_object ("manager", "Manager", "Object manager for this session", 
	                              GCK_TYPE_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_HANDLE,
	         g_param_spec_ulong ("handle", "Handle", "PKCS#11 session handle", 
	                             0, G_MAXULONG, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SLOT_ID,
	         g_param_spec_ulong ("slot-id", "Slot ID", "Slot ID this session is opened on", 
	                             0, G_MAXULONG, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_APARTMENT,
	         g_param_spec_ulong ("apartment", "Apartment", "Apartment this session is opened on",
	                             0, G_MAXULONG, 0, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_READ_ONLY,
	         g_param_spec_boolean ("read-only", "Read Only", "Whether a read-only session or not",
	                               TRUE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_LOGGED_IN,
	         g_param_spec_ulong ("logged-in", "Logged in", "Whether this session is logged in or not", 
	                             0, G_MAXULONG, CKU_NONE, G_PARAM_READWRITE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckSession*
gck_session_for_session_object (GckObject *obj)
{
	g_return_val_if_fail (GCK_IS_OBJECT (obj), NULL);
	return GCK_SESSION (g_object_get_data (G_OBJECT (obj), "owned-by-session"));
}

CK_SESSION_HANDLE
gck_session_get_handle (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), 0);
	return self->pv->handle;
}

CK_SLOT_ID
gck_session_get_slot_id (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), 0);
	return self->pv->slot_id;	
}

CK_ULONG
gck_session_get_apartment (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), 0);
	return self->pv->apartment;
}

GckModule*
gck_session_get_module (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), NULL);
	g_return_val_if_fail (GCK_IS_MODULE (self->pv->module), NULL);
	return self->pv->module;	
}

GckManager*
gck_session_get_manager (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), NULL);
	g_return_val_if_fail (GCK_IS_MANAGER (self->pv->manager), NULL);
	return self->pv->manager;	
}

gulong
gck_session_get_logged_in (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), FALSE);
	return self->pv->logged_in;
}

void
gck_session_set_logged_in (GckSession *self, gulong logged_in)
{
	g_return_if_fail (GCK_IS_SESSION (self));
	self->pv->logged_in = logged_in;
	g_object_notify (G_OBJECT (self), "logged-in");
}

gboolean
gck_session_get_read_only (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), TRUE);
	return self->pv->read_only;
}

CK_RV
gck_session_lookup_readable_object (GckSession *self, CK_OBJECT_HANDLE handle, 
                                    GckObject **result)
{
	return lookup_object_from_handle (self, handle, FALSE, result);
}

CK_RV
gck_session_lookup_writable_object (GckSession *self, CK_OBJECT_HANDLE handle, 
                                    GckObject **result)
{
	return lookup_object_from_handle (self, handle, TRUE, result);
}

CK_RV
gck_session_login_context_specific (GckSession *self, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	GckAuthenticator *authenticator;
	gboolean always_auth;
	gboolean is_private;
	GckObject *object;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_GENERAL_ERROR);

	if (!self->pv->current_object)
		return CKR_OPERATION_NOT_INITIALIZED;

	object = self->pv->current_object;
	g_return_val_if_fail (GCK_IS_OBJECT (object), CKR_GENERAL_ERROR);
	
	if (!gck_object_get_attribute_boolean (object, self, CKA_ALWAYS_AUTHENTICATE, &always_auth))
		always_auth = FALSE; 
	if (!gck_object_get_attribute_boolean (object, self, CKA_PRIVATE, &is_private))
		is_private = FALSE;
	
	/* A strange code, but that's what the spec says */
	if (always_auth == FALSE) 
		return CKR_OPERATION_NOT_INITIALIZED;
	
	/* Double check that the object has what it takes */
	g_return_val_if_fail (is_private == TRUE, CKR_GENERAL_ERROR);

	/* Now create the strange object */
	rv = gck_authenticator_create (self->pv->current_object, pin, n_pin, &authenticator);
	if (rv != CKR_OK)
		return rv;

	if (self->pv->authenticator)
		g_object_unref (self->pv->authenticator);
	g_object_set_data (G_OBJECT (authenticator), "owned-by-session", self);
	self->pv->authenticator = authenticator;

	return CKR_OK;
}

void
gck_session_destroy_session_object (GckSession *self, GckTransaction *transaction,
                                    GckObject *obj)
{
	g_return_if_fail (GCK_IS_SESSION (self));
	g_return_if_fail (gck_session_for_session_object (obj) == self);
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));

	/* Don't actually destroy the authenticator */
	if (self->pv->authenticator && GCK_OBJECT (self->pv->authenticator) == obj)
		return;

	remove_object (self, transaction, obj);
}

gboolean
gck_session_for_each_authenticator (GckSession *self, GckObject *object,
                                    GckAuthenticatorFunc func, gpointer user_data)
{
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attrs[2];
	GList *results, *l;

	g_return_val_if_fail (GCK_IS_SESSION (self), FALSE);
	g_return_val_if_fail (GCK_IS_OBJECT (object), FALSE);
	g_return_val_if_fail (func, FALSE);

	/* Do we have one right on the session */
	if (self->pv->authenticator != NULL &&
	    gck_authenticator_get_object (self->pv->authenticator) == object) {
		if ((func) (self->pv->authenticator, object, user_data))
			return TRUE;
	}

	klass = CKO_GNOME_AUTHENTICATOR;
	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &klass;
	attrs[0].ulValueLen = sizeof (klass);

	handle = gck_object_get_handle (object);
	attrs[1].type = CKA_GNOME_OBJECT;
	attrs[1].pValue = &handle;
	attrs[1].ulValueLen = sizeof (handle);

	/* Find any on the session */
	results = gck_manager_find_by_attributes (self->pv->manager,
	                                          attrs, G_N_ELEMENTS (attrs));

	for (l = results; l; l = g_list_next (l)) {
		if ((func) (l->data, object, user_data))
			break;
	}

	g_list_free (results);

	if (l != NULL)
		return TRUE;

	/* Find any in the token */
	results = gck_manager_find_by_attributes (gck_module_get_manager (self->pv->module), 
	                                          attrs, G_N_ELEMENTS (attrs));

	for (l = results; l; l = g_list_next (l)) {
		if ((func) (l->data, object, user_data))
			break;
	}

	g_list_free (results);
	
	return (l != NULL);
}

/* -----------------------------------------------------------------------------
 * PKCS#11
 */

CK_RV 
gck_session_C_GetFunctionStatus (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV 
gck_session_C_CancelFunction (GckSession *self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
gck_session_C_GetSessionInfo(GckSession* self, CK_SESSION_INFO_PTR info)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!info)
		return CKR_ARGUMENTS_BAD;
	
	info->slotID = self->pv->slot_id;
	if (self->pv->logged_in == CKU_USER)
		info->state = self->pv->read_only ? CKS_RO_USER_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
	else if (self->pv->logged_in == CKU_SO)
		info->state = CKS_RW_SO_FUNCTIONS;
	else
		info->state = self->pv->read_only ? CKS_RO_PUBLIC_SESSION : CKS_RW_PUBLIC_SESSION;
	info->flags = CKF_SERIAL_SESSION;
	if (!self->pv->read_only)
		info->flags |= CKF_RW_SESSION;
	info->ulDeviceError = 0;
	
	return CKR_OK;
}

CK_RV
gck_session_C_GetOperationState (GckSession* self, CK_BYTE_PTR operation_state,
                                 CK_ULONG_PTR operation_state_len)
{
	/* Nope, We don't bend that way */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_SetOperationState (GckSession* self, CK_BYTE_PTR operation_state,
                                 CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                                 CK_OBJECT_HANDLE authentication_key)
{
	/* Nope. We don't bend that way */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_CreateObject (GckSession* self, CK_ATTRIBUTE_PTR template,
                            CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	GckObject *object = NULL;
	GckTransaction *transaction;
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_attrs, i;
	GckFactory factory;
	gboolean is_token;
	gboolean is_transient;
	gboolean is_private;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!new_object)
		return CKR_ARGUMENTS_BAD;
	if (!(!count || template))
		return CKR_ARGUMENTS_BAD;

	/* Find out if we can create such an object */
	factory = gck_module_find_factory (gck_session_get_module (self), template, count);
	if (!factory)
		return CKR_TEMPLATE_INCOMPLETE;
	
	/* Find out where we'll be creating this */
	if (!gck_attributes_find_boolean (template, count, CKA_TOKEN, &is_token))
		is_token = FALSE;
	if (!gck_attributes_find_boolean (template, count, CKA_GNOME_TRANSIENT, &is_transient))
		is_transient = FALSE;
		
	/* See if we can create due to read-only */
	if (is_token) {
		if (!is_transient && gck_module_get_write_protected (self->pv->module))
			return CKR_TOKEN_WRITE_PROTECTED;
		if (self->pv->read_only)
			return CKR_SESSION_READ_ONLY;
	}
	
	/* The transaction for this whole dealio */
	transaction = gck_transaction_new ();
	
	/* 
	 * Duplicate the memory for the attributes (but not values) so we 
	 * can 'consume' in the factory function 
	 */
	attrs = g_memdup (template, count * sizeof (CK_ATTRIBUTE));
	n_attrs = count;
	
	/* Actually create the object */
	object = NULL;
	(factory) (self, transaction, attrs, n_attrs, &object);

	if (!gck_transaction_get_failed (transaction)) {
		g_return_val_if_fail (object, CKR_GENERAL_ERROR);

		/* Can only create public objects unless logged in */
		if (gck_session_get_logged_in (self) != CKU_USER &&
		    gck_object_get_attribute_boolean (object, self, CKA_PRIVATE, &is_private) && 
		    is_private == TRUE) {
			gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		}
	}
	
	/* Give the object a chance to create additional attributes */
	if (!gck_transaction_get_failed (transaction)) {
		gck_object_create_attributes (object, self, transaction, attrs, n_attrs);
	}

	/* Find somewhere to store the object */
	if (!gck_transaction_get_failed (transaction)) {
		if (is_token) 
			gck_module_store_token_object (self->pv->module, transaction, object); 
		else
			add_object (self, transaction, object);
	}

	/* Next go through and set all attributes that weren't used initially */
	gck_attributes_consume (attrs, n_attrs, CKA_TOKEN, G_MAXULONG);
	for (i = 0; i < n_attrs && !gck_transaction_get_failed (transaction); ++i) {
		if (!gck_attribute_consumed (&attrs[i]))
			gck_object_set_attribute (object, self, transaction, &attrs[i]);
	}

	gck_transaction_complete (transaction);
	rv = gck_transaction_get_result (transaction);
	g_object_unref (transaction);
	if (rv == CKR_OK) {
		g_assert (object);
		*new_object = gck_object_get_handle (object);
	}
	if (object) 
		g_object_unref (object);
	g_free (attrs);
	
	return rv;
}

CK_RV
gck_session_C_CopyObject (GckSession* self, CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template, CK_ULONG count,
                          CK_OBJECT_HANDLE_PTR new_object)
{
	/* 
	 * TODO: We need to implement this, initially perhaps only 
	 * only for session objects.
	 */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_GetObjectSize (GckSession* self, CK_OBJECT_HANDLE object, CK_ULONG_PTR size)
{
	/* TODO: Do we need to implement this? */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_GetAttributeValue (GckSession* self, CK_OBJECT_HANDLE handle, 
                                 CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	GckObject *object;
	CK_ULONG i;
	CK_RV code, rv;
	
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!(!count || template))
		return CKR_ARGUMENTS_BAD;
	
	rv = gck_session_lookup_readable_object (self, handle, &object);
	if (rv != CKR_OK)
		return rv;
	
	rv = CKR_OK;
	
	for (i = 0; i < count; ++i) {
		code = gck_object_get_attribute (object, self, &template[i]);

		/* Not a true error, keep going */
		if (code == CKR_ATTRIBUTE_SENSITIVE ||
		    code == CKR_ATTRIBUTE_TYPE_INVALID) {
			template[i].ulValueLen = (CK_ULONG)-1;
			rv = code;
			
		} else if(code == CKR_BUFFER_TOO_SMALL) {
			rv = code;
			
		/* Any other error aborts */
		} else if (code != CKR_OK) {
			rv = code;
			break;
		}
	}

	return rv;
}

CK_RV
gck_session_C_SetAttributeValue (GckSession* self, CK_OBJECT_HANDLE handle, 
                                 CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	/* TODO: Need to implement this */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DestroyObject (GckSession* self, CK_OBJECT_HANDLE handle)
{
	GckObject *object;
	GckSession *session;
	GckTransaction *transaction;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	
	rv = gck_session_lookup_writable_object (self, handle, &object);
	if (rv != CKR_OK)
		return rv;
	
	transaction = gck_transaction_new ();

	/* Lookup the actual session that owns this object, if no session, then a token object */
	session = gck_session_for_session_object (object);
	if (session != NULL)
		remove_object (session, transaction, object);
	else
		gck_module_remove_token_object (self->pv->module, transaction, object);
	
	gck_transaction_complete (transaction);
	rv = gck_transaction_get_result (transaction);
	g_object_unref (transaction);
	
	if (rv == CKR_OK) {
		/* Check that it's really gone */
		g_return_val_if_fail (gck_session_lookup_readable_object (self, handle, &object) == 
		                      CKR_OBJECT_HANDLE_INVALID, CKR_GENERAL_ERROR);
	}
	
	return rv;
}

CK_RV
gck_session_C_FindObjectsInit (GckSession* self, CK_ATTRIBUTE_PTR template,
                               CK_ULONG count)
{
	CK_BBOOL token = CK_FALSE;
	gboolean also_private;
	CK_RV rv = CKR_OK;
	GArray *found;
	gboolean all;
	
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!(template || !count))
		return CKR_ARGUMENTS_BAD;
	
	/* Cancel any current operation */
	if (self->pv->current_operation) {
		(self->pv->current_operation) (self);
		g_assert (!self->pv->current_operation);
	}

	/* See whether this is token or not */
	all = !attributes_find_boolean (template, count, CKA_TOKEN, &token);
	
	/* An array of object handles */
	found = g_array_new (FALSE, TRUE, sizeof (CK_OBJECT_HANDLE));

	/* If not logged in, then skip private objects */
	also_private = gck_session_get_logged_in (self) == CKU_USER; 

	if (all || token) {
		rv = gck_module_refresh_token (self->pv->module);
		if (rv == CKR_OK)
			rv = gck_manager_find_handles (gck_module_get_manager (self->pv->module), 
			                               also_private, template, count, found);
	}
	
	if (rv == CKR_OK && (all || !token)) {
		rv = gck_manager_find_handles (self->pv->manager, also_private,
		                               template, count, found);
	}

	if (rv != CKR_OK) {
		g_array_free (found, TRUE);
		return rv;
	}
	
	g_assert (!self->pv->current_operation);
	g_assert (!self->pv->found_objects);
	
	self->pv->found_objects = found;
	self->pv->current_operation = cleanup_found;
	
	return CKR_OK;
}

CK_RV
gck_session_C_FindObjects (GckSession* self, CK_OBJECT_HANDLE_PTR objects,
                           CK_ULONG max_count, CK_ULONG_PTR count)
{
	CK_ULONG n_objects, i;
	GArray *found;
	
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!(objects || !max_count))
		return CKR_ARGUMENTS_BAD;
	if (!count)
		return CKR_ARGUMENTS_BAD;

	if (self->pv->current_operation != cleanup_found)
		return CKR_OPERATION_NOT_INITIALIZED;
	
	g_assert (self->pv->found_objects);
	found = self->pv->found_objects;
	
	n_objects = MIN (max_count, found->len);
	if (n_objects > 0) {
		for (i = 0; i < n_objects; ++i)
			objects[i] = g_array_index (found, CK_OBJECT_HANDLE, i);
		g_array_remove_range (found, 0, n_objects);
	}
	
	*count = n_objects;
	return CKR_OK;
	
}

CK_RV
gck_session_C_FindObjectsFinal (GckSession* self)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);

	if (self->pv->current_operation != cleanup_found)
		return CKR_OPERATION_NOT_INITIALIZED;

	cleanup_found (self);
	return CKR_OK;
}

CK_RV
gck_session_C_EncryptInit (GckSession *self, CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!mechanism)
		return CKR_ARGUMENTS_BAD;
	return prepare_crypto (self, mechanism, CKA_ENCRYPT, key);
}

CK_RV
gck_session_C_Encrypt (GckSession *self, CK_BYTE_PTR data, CK_ULONG data_len,
                       CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return process_crypto (self, CKA_ENCRYPT, data, data_len, encrypted_data, encrypted_data_len);
}

CK_RV
gck_session_C_EncryptUpdate (GckSession *self, CK_BYTE_PTR part,
                             CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                             CK_ULONG_PTR encrypted_part_len)
{
	/* Our keys don't support this incremental encryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_EncryptFinal (GckSession *self, CK_BYTE_PTR last_part,
                            CK_ULONG_PTR last_part_len)
{
	/* Our keys don't support this incremental encryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DecryptInit (GckSession *self, CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!mechanism)
		return CKR_ARGUMENTS_BAD;
	return prepare_crypto (self, mechanism, CKA_DECRYPT, key);	
}

CK_RV
gck_session_C_Decrypt (GckSession *self, CK_BYTE_PTR enc_data,
                       CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return process_crypto (self, CKA_DECRYPT, enc_data, enc_data_len, data, data_len);
}

CK_RV
gck_session_C_DecryptUpdate (GckSession *self, CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	/* Our keys don't support this incremental decryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DecryptFinal (GckSession *self, CK_BYTE_PTR last_part,
                            CK_ULONG_PTR last_part_len)
{
	/* Our keys don't support this incremental decryption */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DigestInit (GckSession *self, CK_MECHANISM_PTR mechanism)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_Digest (GckSession *self, CK_BYTE_PTR data, CK_ULONG data_len,
                      CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DigestUpdate (GckSession *self, CK_BYTE_PTR part, CK_ULONG part_len)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DigestKey (GckSession *self, CK_OBJECT_HANDLE key)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DigestFinal (GckSession *self, CK_BYTE_PTR digest,
                           CK_ULONG_PTR digest_len)
{
	/* We don't do digests */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_SignInit (GckSession *self, CK_MECHANISM_PTR mechanism, 
                        CK_OBJECT_HANDLE key)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!mechanism)
		return CKR_ARGUMENTS_BAD;
	return prepare_crypto (self, mechanism, CKA_SIGN, key);
}

CK_RV
gck_session_C_Sign (GckSession *self, CK_BYTE_PTR data, CK_ULONG data_len,
                    CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return process_crypto (self, CKA_SIGN, data, data_len, signature, signature_len);
}

CK_RV
gck_session_C_SignUpdate (GckSession *self, CK_BYTE_PTR part, CK_ULONG part_len)
{
	/* Our keys don't support incremental operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_SignFinal (GckSession *self, CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_len)
{
	/* Our keys don't support incremental operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_SignRecoverInit (GckSession *self, CK_MECHANISM_PTR mechanism,
                               CK_OBJECT_HANDLE key)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_SignRecover (GckSession *self, CK_BYTE_PTR data, CK_ULONG data_len, 
                           CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_VerifyInit (GckSession *self, CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	if (!mechanism)
		return CKR_ARGUMENTS_BAD;
	return prepare_crypto (self, mechanism, CKA_VERIFY, key);
}

CK_RV
gck_session_C_Verify (GckSession *self, CK_BYTE_PTR data, CK_ULONG data_len,
                      CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	g_return_val_if_fail (GCK_IS_SESSION (self), CKR_SESSION_HANDLE_INVALID);
	return process_crypto (self, CKA_VERIFY, data, data_len, signature, &signature_len);
}

CK_RV
gck_session_C_VerifyUpdate (GckSession *self, CK_BYTE_PTR part, CK_ULONG part_len)
{
	/* Our keys don't support incremental operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;	
}

CK_RV
gck_session_C_VerifyFinal (GckSession *self, CK_BYTE_PTR signature,
                           CK_ULONG signature_len)
{
	/* Our keys don't support incremental operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_VerifyRecoverInit (GckSession *self, CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;	
}

CK_RV
gck_session_C_VerifyRecover (GckSession *self, CK_BYTE_PTR signature,
                             CK_ULONG signature_len, CK_BYTE_PTR data, 
                             CK_ULONG_PTR data_len)
{
	/* TODO: Need to implement */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DigestEncryptUpdate (GckSession *self, CK_BYTE_PTR part,
                                   CK_ULONG part_len, CK_BYTE_PTR enc_part,
                                   CK_ULONG_PTR enc_part_len)
{
	/* We don't support double operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DecryptDigestUpdate (GckSession *self, CK_BYTE_PTR enc_part,
                                   CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                                   CK_ULONG_PTR part_len)
{
	/* We don't support double operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;	
}

CK_RV
gck_session_C_SignEncryptUpdate (GckSession *self, CK_BYTE_PTR part,
                                 CK_ULONG part_len, CK_BYTE_PTR enc_part,
				 CK_ULONG_PTR enc_part_len)
{
	/* We don't support double operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;	
}

CK_RV
gck_session_C_DecryptVerifyUpdate (GckSession *self, CK_BYTE_PTR enc_part,
                                   CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                                   CK_ULONG_PTR part_len)
{
	/* We don't support double operations */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_GenerateKey (GckSession* self, CK_MECHANISM_PTR mechanism,
                           CK_ATTRIBUTE_PTR template, CK_ULONG count, 
                           CK_OBJECT_HANDLE_PTR key)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_GenerateKeyPair (GckSession* self, CK_MECHANISM_PTR mechanism,
                               CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                               CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                               CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_WrapKey (GckSession* self, CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_UnwrapKey (GckSession* self, CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                         CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                         CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	/* TODO: We need to implement this */
 	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
gck_session_C_DeriveKey (GckSession* self, CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                         CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	/* Our keys don't support derivation */
 	return CKR_FUNCTION_NOT_SUPPORTED;	
}

CK_RV
gck_session_C_SeedRandom (GckSession* self, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	/* We don't have a RNG */
 	return CKR_RANDOM_NO_RNG;
}

CK_RV
gck_session_C_GenerateRandom (GckSession* self, CK_BYTE_PTR random_data,
                              CK_ULONG random_len)
{
	/* We don't have a RNG */
 	return CKR_RANDOM_NO_RNG;	
}
