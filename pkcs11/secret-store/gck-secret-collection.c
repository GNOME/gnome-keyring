/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#include "gck-secret-binary.h"
#include "gck-secret-collection.h"
#include "gck-secret-data.h"
#include "gck-secret-item.h"
#include "gck-secret-textual.h"

#include "gck/gck-attributes.h"
#include "gck/gck-credential.h"
#include "gck/gck-secret.h"
#include "gck/gck-session.h"
#include "gck/gck-transaction.h"

#include <glib/gi18n.h>

#include "pkcs11/pkcs11i.h"

enum {
	PROP_0,
	PROP_FILENAME
};

struct _GckSecretCollection {
	GckSecretObject parent;
	GckSecretData *sdata;
	GHashTable *items;
	gchar *filename;
	guint32 watermark;
	GArray *template;
};

G_DEFINE_TYPE (GckSecretCollection, gck_secret_collection, GCK_TYPE_SECRET_OBJECT);

/* Forward declarations */
static void add_item (GckSecretCollection *, GckTransaction *, GckSecretItem *);
static void remove_item (GckSecretCollection *, GckTransaction *, GckSecretItem *);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GckDataResult
load_collection_and_secret_data (GckSecretCollection *self, GckSecretData *sdata,
                                 const gchar *path)
{
	GckDataResult res;
	GError *error = NULL;
	guchar *data;
	gsize n_data;

	/* Read in the keyring */
	if (!g_file_get_contents (path, (gchar**)&data, &n_data, &error)) {
		g_message ("problem reading keyring: %s: %s",
		           path, error && error->message ? error->message : "");
		g_clear_error (&error);
		return GCK_DATA_FAILURE;
	}

	/* Try to load from an encrypted file, and otherwise plain text */
	res = gck_secret_binary_read (self, sdata, data, n_data);
	if (res == GCK_DATA_UNRECOGNIZED)
		res = gck_secret_textual_read (self, sdata, data, n_data);

	g_free (data);

	return res;
}

static GckCredential*
lookup_unassociated_credential (GckSession *session, CK_OBJECT_HANDLE handle)
{
	GckObject *object;

	if (gck_session_lookup_readable_object (session, handle, &object) != CKR_OK)
		return NULL;

	if (gck_credential_get_object (GCK_CREDENTIAL (object)) != NULL)
		return NULL;

	return GCK_CREDENTIAL (object);
}

static gboolean
find_unlocked_credential (GckCredential *cred, GckObject *object, gpointer user_data)
{
	CK_OBJECT_HANDLE *result = user_data;

	g_return_val_if_fail (!*result, FALSE);

	if (gck_credential_peek_data (cred, GCK_TYPE_SECRET_DATA)) {
		*result = gck_object_get_handle (GCK_OBJECT (cred));
		return TRUE;
	}

	return FALSE;
}

static gboolean
find_unlocked_secret_data (GckCredential *cred, GckObject *object, gpointer user_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (object);
	GckSecretData **result = user_data;

	g_return_val_if_fail (!*result, FALSE);

	*result = gck_credential_pop_data (cred, GCK_TYPE_SECRET_DATA);
	if (*result) {
		g_return_val_if_fail (*result == self->sdata, FALSE);
		return TRUE;
	}

	return FALSE;
}

static void
track_secret_data (GckSecretCollection *self, GckSecretData *data)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));

	if (self->sdata)
		g_object_remove_weak_pointer (G_OBJECT (self->sdata),
		                              (gpointer*)&(self->sdata));
	self->sdata = data;
	if (self->sdata)
		g_object_add_weak_pointer (G_OBJECT (self->sdata),
		                           (gpointer*)&(self->sdata));
}

static void
each_value_to_list (gpointer key, gpointer value, gpointer user_data)
{
	GList **list = user_data;
	*list = g_list_prepend (*list, value);
}

static void
expose_each_item (gpointer key, gpointer value, gpointer user_data)
{
	gboolean expose = GPOINTER_TO_INT (user_data);
	gck_object_expose (value, expose);
}

static gboolean
complete_add (GckTransaction *transaction, GckSecretCollection *self, GckSecretItem *item)
{
	if (gck_transaction_get_failed (transaction))
		remove_item (self, NULL, item);
	g_object_unref (item);
	return TRUE;
}

static void
add_item (GckSecretCollection *self, GckTransaction *transaction, GckSecretItem *item)
{
	const gchar *identifier;
	guint32 number;

	g_assert (GCK_IS_SECRET_COLLECTION (self));
	g_assert (GCK_IS_SECRET_ITEM (item));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	g_return_if_fail (identifier);

	/* Make note of the highest numeric identifier, for later use */
	number = strtoul (identifier, NULL, 10);
	if (number > self->watermark)
		self->watermark = number;

	g_hash_table_replace (self->items, g_strdup (identifier), g_object_ref (item));

	if (gck_object_is_exposed (GCK_OBJECT (self)))
		gck_object_expose_full (GCK_OBJECT (item), transaction, TRUE);
	if (transaction)
		gck_transaction_add (transaction, self, (GckTransactionFunc)complete_add,
		                     g_object_ref (item));

}

static gboolean
complete_remove (GckTransaction *transaction, GckSecretCollection *self, GckSecretItem *item)
{
	if (gck_transaction_get_failed (transaction))
		add_item (self, NULL, item);
	g_object_unref (item);
	return TRUE;
}

static void
remove_item (GckSecretCollection *self, GckTransaction *transaction, GckSecretItem *item)
{
	const gchar *identifier;

	g_assert (GCK_IS_SECRET_COLLECTION (self));
	g_assert (GCK_IS_SECRET_ITEM (item));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	g_return_if_fail (identifier);

	g_object_ref (item);

	g_hash_table_remove (self->items, identifier);

	gck_object_expose_full (GCK_OBJECT (item), transaction, FALSE);
	if (transaction)
		gck_transaction_add (transaction, self, (GckTransactionFunc)complete_remove,
		                     g_object_ref (item));

	g_object_unref (item);
}

static GckObject*
factory_create_collection (GckSession *session, GckTransaction *transaction,
                           CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	GckSecretCollection *collection = NULL;
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attr;
	GckManager *manager;
	gchar *identifier = NULL;
	GckSecretData *sdata;
	gchar *label = NULL;
	GckCredential *cred;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), NULL);
	g_return_val_if_fail (attrs || !n_attrs, NULL);

	manager = gck_manager_for_template (attrs, n_attrs, session);

	/* Must have a credential, which is not associated with an object yet */
	if (!gck_attributes_find_ulong (attrs, n_attrs, CKA_G_CREDENTIAL, &handle)) {
		gck_transaction_fail (transaction, CKR_TEMPLATE_INCOMPLETE);
		return NULL;
	}

	cred = lookup_unassociated_credential (session, handle);
	if (cred == NULL) {
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
		return NULL;
	}

	/* See if a collection attribute was specified, not present means all collections */
	attr = gck_attributes_find (attrs, n_attrs, CKA_LABEL);
	if (attr != NULL) {
		rv = gck_attribute_get_string (attr, &label);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return NULL;
		}
		identifier = g_utf8_strdown (label, -1);
		g_strdelimit (identifier, ":/\\<>|\t\n\r\v ", '_');
		gck_attribute_consume (attr);
	}

	if (!identifier || !identifier[0]) {
		g_free (identifier);
		identifier = g_strdup ("unnamed");
	}

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", gck_session_get_module (session),
	                           "identifier", identifier,
	                           "manager", manager,
	                           "label", label,
	                           NULL);

	g_free (identifier);
	g_free (label);

	gck_credential_connect (cred, GCK_OBJECT (collection));
	sdata = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	gck_credential_set_data (cred, GCK_TYPE_SECRET_DATA, sdata);
	gck_secret_data_set_master (sdata, gck_credential_get_secret (cred));
	track_secret_data (collection, sdata);
	g_object_unref (sdata);

	gck_attributes_consume (attrs, n_attrs, CKA_G_CREDENTIAL, G_MAXULONG);
	gck_session_complete_object_creation (session, transaction, GCK_OBJECT (collection),
	                                      TRUE, attrs, n_attrs);
	return GCK_OBJECT (collection);
}

static gboolean
complete_master_password (GckTransaction *transaction, GObject *object, gpointer user_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (object);
	GckSecret *previous = user_data;

	if (gck_transaction_get_failed (transaction)) {
		if (self->sdata)
			gck_secret_data_set_master (self->sdata, previous);
	}

	if (previous)
		g_object_unref (previous);

	return TRUE;
}

static void
change_master_password (GckSecretCollection *self, GckTransaction *transaction,
                        GckCredential *cred)
{
	GckSecret *previous;

	g_assert (GCK_IS_SECRET_COLLECTION (self));
	g_assert (GCK_IS_TRANSACTION (transaction));
	g_assert (GCK_IS_CREDENTIAL (cred));

	if (!self->sdata) {
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	}

	previous = gck_secret_data_get_master (self->sdata);
	if (previous != NULL)
		g_object_ref (previous);

	gck_credential_connect (cred, GCK_OBJECT (self));
	gck_credential_set_data (cred, GCK_TYPE_SECRET_DATA, self->sdata);
	gck_secret_data_set_master (self->sdata, gck_credential_get_secret (cred));

	gck_transaction_add (transaction, self, complete_master_password, previous);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_secret_collection_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);

	switch (attr->type) {
	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_G_COLLECTION);
	case CKA_G_CREDENTIAL_TEMPLATE:
		return gck_attribute_set_template (attr, self->template);
	}
	return GCK_OBJECT_CLASS (gck_secret_collection_parent_class)->get_attribute (base, session, attr);
}

static void
gck_secret_collection_set_attribute (GckObject *object, GckSession *session,
                                     GckTransaction *transaction, CK_ATTRIBUTE *attr)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (object);
	CK_OBJECT_HANDLE handle = 0;
	GckCredential *cred;
	GArray *template;
	CK_RV rv;

	switch (attr->type) {
	case CKA_G_CREDENTIAL:
		gck_credential_for_each (session, GCK_OBJECT (self),
		                         find_unlocked_credential, &handle);
		if (handle == 0) {
			gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
			return;
		}
		rv = gck_attribute_get_ulong (attr, &handle);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return;
		}
		cred = lookup_unassociated_credential (session, handle);
		if (cred == NULL) {
			gck_transaction_fail (transaction, CKR_ATTRIBUTE_VALUE_INVALID);
			return;
		}
		change_master_password (self, transaction, cred);
		return;
	case CKA_G_CREDENTIAL_TEMPLATE:
		rv = gck_attribute_get_template (attr, &template);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return;
		}
		gck_template_free (self->template);
		self->template = template;
		return;
	};

	return GCK_OBJECT_CLASS (gck_secret_collection_parent_class)->set_attribute (object, session, transaction, attr);
}

static CK_RV
gck_secret_collection_real_unlock (GckObject *obj, GckCredential *cred)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
	GckDataResult res;
	GckSecretData *sdata;
	GckSecret *master;
	CK_RV rv;

	master = gck_credential_get_secret (cred);

	/* Already unlocked, make sure pin matches */
	if (self->sdata) {
		if (!gck_secret_equal (gck_secret_data_get_master (self->sdata), master))
			return CKR_PIN_INCORRECT;

		/* Credential now tracks our secret data */
		gck_credential_set_data (cred, GCK_TYPE_SECRET_DATA, self->sdata);
		return CKR_OK;
	}

	/* New secret data object, setup master password */
	sdata = g_object_new (GCK_TYPE_SECRET_DATA, NULL);
	gck_secret_data_set_master (sdata, master);

	/* Load the data from a file, and decrypt if necessary */
	if (self->filename) {
		res = load_collection_and_secret_data (self, sdata, self->filename);

	/* No filename, password must be null */
	} else {
		if (gck_secret_equals (master, NULL, 0))
			res = GCK_DATA_SUCCESS;
		else
			res = GCK_DATA_LOCKED;
	}

	switch (res) {
	case GCK_DATA_SUCCESS:
		gck_credential_set_data (cred, GCK_TYPE_SECRET_DATA, sdata);
		track_secret_data (self, sdata);
		rv = CKR_OK;
		break;
	case GCK_DATA_LOCKED:
		rv = CKR_PIN_INCORRECT;
		break;
	case GCK_DATA_UNRECOGNIZED:
		g_message ("unrecognized or invalid keyring: %s", self->filename);
		rv = CKR_FUNCTION_FAILED;
		break;
	case GCK_DATA_FAILURE:
		g_message ("failed to read or parse keyring: %s", self->filename);
		rv = CKR_GENERAL_ERROR;
		break;
	default:
		g_assert_not_reached ();
	}

	g_object_unref (sdata);
	return rv;
}

static void
gck_secret_collection_expose (GckObject *base, gboolean expose)
{
	GCK_OBJECT_CLASS (gck_secret_collection_parent_class)->expose_object (base, expose);
	g_hash_table_foreach (GCK_SECRET_COLLECTION (base)->items, expose_each_item, GINT_TO_POINTER (expose));
}

static gboolean
gck_secret_collection_real_is_locked (GckSecretObject *obj, GckSession *session)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
	return !gck_secret_collection_unlocked_have (self, session);
}

static void
gck_secret_collection_init (GckSecretCollection *self)
{
	CK_ULONG idle = 0;
	CK_ULONG after = 0;
	CK_BBOOL token = CK_TRUE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_GNOME_TRANSIENT, &token, sizeof (token) },
		{ CKA_G_DESTRUCT_IDLE, &idle, sizeof (idle) },
		{ CKA_G_DESTRUCT_AFTER, &after, sizeof (after) },
	};

	self->items = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	self->template = gck_template_new (attrs, G_N_ELEMENTS (attrs));
}

static void
gck_secret_collection_set_property (GObject *obj, guint prop_id, const GValue *value,
                                    GParamSpec *pspec)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	switch (prop_id) {
	case PROP_FILENAME:
		gck_secret_collection_set_filename (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_collection_get_property (GObject *obj, guint prop_id, GValue *value,
                                    GParamSpec *pspec)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, gck_secret_collection_get_filename (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_collection_dispose (GObject *obj)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	track_secret_data (self, NULL);
	g_hash_table_remove_all (self->items);

	G_OBJECT_CLASS (gck_secret_collection_parent_class)->dispose (obj);
}

static void
gck_secret_collection_finalize (GObject *obj)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	g_assert (self->sdata == NULL);

	g_hash_table_destroy (self->items);
	self->items = NULL;

	g_free (self->filename);
	self->filename = NULL;

	gck_template_free (self->template);
	self->template = NULL;

	G_OBJECT_CLASS (gck_secret_collection_parent_class)->finalize (obj);
}

static void
gck_secret_collection_class_init (GckSecretCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckSecretObjectClass *secret_class = GCK_SECRET_OBJECT_CLASS (klass);

	gck_secret_collection_parent_class = g_type_class_peek_parent (klass);

	gobject_class->set_property = gck_secret_collection_set_property;
	gobject_class->get_property = gck_secret_collection_get_property;
	gobject_class->dispose = gck_secret_collection_dispose;
	gobject_class->finalize = gck_secret_collection_finalize;

	gck_class->get_attribute = gck_secret_collection_get_attribute;
	gck_class->set_attribute = gck_secret_collection_set_attribute;
	gck_class->unlock = gck_secret_collection_real_unlock;
	gck_class->expose_object = gck_secret_collection_expose;

	secret_class->is_locked = gck_secret_collection_real_is_locked;

	g_object_class_install_property (gobject_class, PROP_FILENAME,
	           g_param_spec_string ("filename", "Filename", "Collection filename (without path)",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	gck_secret_object_class_unique_identifiers (secret_class);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckFactory*
gck_secret_collection_get_factory (void)
{
	static CK_OBJECT_CLASS klass = CKO_G_COLLECTION;

	static CK_ATTRIBUTE attributes[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
	};

	static GckFactory factory = {
		attributes,
		G_N_ELEMENTS (attributes),
		factory_create_collection
	};

	return &factory;
}

const gchar*
gck_secret_collection_get_filename (GckSecretCollection *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	return self->filename;
}

void
gck_secret_collection_set_filename (GckSecretCollection *self, const gchar *filename)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));

	if (self->filename == filename)
		return;
	g_free (self->filename);
	self->filename = g_strdup (filename);
	g_object_notify (G_OBJECT (self), "filename");
}

GList*
gck_secret_collection_get_items (GckSecretCollection *self)
{
	GList *items = NULL;
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_hash_table_foreach (self->items, each_value_to_list, &items);
	return items;
}

GckSecretItem*
gck_secret_collection_get_item (GckSecretCollection *self, const gchar *identifier)
{
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	return g_hash_table_lookup (self->items, identifier);
}

gboolean
gck_secret_collection_has_item (GckSecretCollection *self, GckSecretItem *item)
{
	const gchar *identifier;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (GCK_IS_SECRET_ITEM (item), FALSE);

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	return g_hash_table_lookup (self->items, identifier) == item;
}

GckSecretCollection*
gck_secret_collection_find (CK_ATTRIBUTE_PTR attr, ...)
{
	CK_OBJECT_CLASS klass = CKO_G_COLLECTION;
	GckSecretCollection *result = NULL;
	GckManager *manager;
	CK_ATTRIBUTE attrs[2];
	GList *objects;
	va_list va;

	g_assert (attr);

	attrs[0].type = CKA_CLASS;
	attrs[0].ulValueLen = sizeof (klass);
	attrs[0].pValue = &klass;
	attrs[1].type = CKA_ID;
	attrs[1].ulValueLen = attr->ulValueLen;
	attrs[1].pValue = attr->pValue;

	va_start (va, attr);
	while (!result && (manager = va_arg (va, GckManager*)) != NULL) {
		objects = gck_manager_find_by_attributes (manager, attrs, 2);
		if (objects && GCK_IS_SECRET_COLLECTION (objects->data))
			result = objects->data;
		g_list_free (objects);
	}
	va_end (va);

	return result;
}

GckSecretItem*
gck_secret_collection_new_item (GckSecretCollection *self, const gchar *identifier)
{
	GckSecretItem *item;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	g_return_val_if_fail (!g_hash_table_lookup (self->items, identifier), NULL);

	item = g_object_new (GCK_TYPE_SECRET_ITEM,
	                     "module", gck_object_get_module (GCK_OBJECT (self)),
	                     "manager", gck_object_get_manager (GCK_OBJECT (self)),
	                     "collection", self,
	                     "identifier", identifier,
	                     NULL);

	add_item (self, NULL, item);
	g_object_unref (item);
	return item;
}

GckSecretItem*
gck_secret_collection_create_item (GckSecretCollection *self, GckTransaction *transaction)
{
	GckSecretItem *item;
	gchar *identifier = NULL;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (transaction, NULL);
	g_return_val_if_fail (!gck_transaction_get_failed (transaction), NULL);

	do {
		g_free (identifier);
		identifier = g_strdup_printf ("%d", ++(self->watermark));
	} while (g_hash_table_lookup (self->items, identifier));

	item = g_object_new (GCK_TYPE_SECRET_ITEM,
	                     "module", gck_object_get_module (GCK_OBJECT (self)),
	                     "manager", gck_object_get_manager (GCK_OBJECT (self)),
	                     "collection", self,
	                     "identifier", identifier,
	                     NULL);

	g_free (identifier);
	add_item (self, transaction, item);
	g_object_unref (item);
	return item;
}

void
gck_secret_collection_remove_item (GckSecretCollection *self, GckSecretItem *item)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	g_return_if_fail (GCK_IS_SECRET_ITEM (item));
	g_return_if_fail (gck_secret_collection_has_item (self, item));

	remove_item (self, NULL, item);
}

void
gck_secret_collection_destroy_item (GckSecretCollection *self, GckTransaction *transaction,
                                    GckSecretItem *item)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (GCK_IS_SECRET_ITEM (item));
	g_return_if_fail (gck_secret_collection_has_item (self, item));

	remove_item (self, transaction, item);
}

gboolean
gck_secret_collection_unlocked_have (GckSecretCollection *self, GckSession *session)
{
	CK_OBJECT_HANDLE handle = 0;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (GCK_IS_SESSION (session), FALSE);

	/*
	 * Look for credential objects that this session has access
	 * to, and use those to find the secret data. If a secret data is
	 * found, it should match the one we are tracking in self->sdata.
	 */

	gck_credential_for_each (session, GCK_OBJECT (self), find_unlocked_credential, &handle);
	return handle != 0;
}

GckSecretData*
gck_secret_collection_unlocked_use (GckSecretCollection *self, GckSession *session)
{
	GckSecretData *sdata = NULL;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);

	/*
	 * Look for credential objects that this session has access
	 * to, and use those to find the secret data. If a secret data is
	 * found, it should match the one we are tracking in self->sdata.
	 */

	gck_credential_for_each (session, GCK_OBJECT (self),
	                         find_unlocked_secret_data, &sdata);

	return sdata;
}

void
gck_secret_collection_unlocked_clear (GckSecretCollection *self)
{
	/*
	 * TODO: This is a tough one to implement. I'm holding off and wondering
	 * if we don't need it, perhaps? As it currently stands, what needs to happen
	 * here is we need to find each and every credential that references the
	 * secret data for this collection and completely delete those objects.
	 */
	g_warning ("Clearing of secret data needs implementing");
	track_secret_data (self, NULL);
}

GckDataResult
gck_secret_collection_load (GckSecretCollection *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), GCK_DATA_FAILURE);

	if (!self->filename)
		return GCK_DATA_SUCCESS;

	return load_collection_and_secret_data (self, self->sdata, self->filename);
}

void
gck_secret_collection_save (GckSecretCollection *self, GckTransaction *transaction)
{
	GckSecret *master;
	GckDataResult res;
	guchar *data;
	gsize n_data;

	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));

	/* HACK: We can't save unless the secret data was loaded */
	if (!self->sdata) {
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	}

	/* Don't save ourselves if no filename */
	if (!self->filename)
		return;

	master = gck_secret_data_get_master (self->sdata);
	if (master == NULL || gck_secret_equals (master, NULL, 0))
		res = gck_secret_textual_write (self, self->sdata, &data, &n_data);
	else
		res = gck_secret_binary_write (self, self->sdata, &data, &n_data);

	switch (res) {
	case GCK_DATA_FAILURE:
	case GCK_DATA_UNRECOGNIZED:
		g_warning ("couldn't prepare to write out keyring: %s", self->filename);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		break;
	case GCK_DATA_LOCKED:
		g_warning ("locked error while writing out keyring: %s", self->filename);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		break;
	case GCK_DATA_SUCCESS:
		gck_transaction_write_file (transaction, self->filename, data, n_data);
		g_free (data);
		break;
	default:
		g_assert_not_reached ();
	};
}

void
gck_secret_collection_destroy (GckSecretCollection *self, GckTransaction *transaction)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));

	gck_object_expose_full (GCK_OBJECT (self), transaction, FALSE);
	if (self->filename)
		gck_transaction_remove_file (transaction, self->filename);
}

gint
gck_secret_collection_get_lock_idle (GckSecretCollection *self)
{
	gulong value;
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), 0);
	if (!gck_template_find_ulong (self->template, CKA_G_DESTRUCT_IDLE, &value))
		value = 0;
	return (gint)value;
}

void
gck_secret_collection_set_lock_idle (GckSecretCollection *self, gint lock_timeout)
{
	CK_ULONG value = (lock_timeout < 0) ? 0 : lock_timeout;
	CK_ATTRIBUTE attr = { CKA_G_DESTRUCT_IDLE, &value, sizeof (value) };
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	gck_template_set (self->template, &attr);
}

gint
gck_secret_collection_get_lock_after (GckSecretCollection *self)
{
	gulong value;
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), 0);
	if (!gck_template_find_ulong (self->template, CKA_G_DESTRUCT_AFTER, &value))
		value = 0;
	return (gint)value;
}

void
gck_secret_collection_set_lock_after (GckSecretCollection *self, gint lock_timeout)
{
	CK_ULONG value = (lock_timeout < 0) ? 0 : lock_timeout;
	CK_ATTRIBUTE attr = { CKA_G_DESTRUCT_AFTER, &value, sizeof (value) };
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	gck_template_set (self->template, &attr);
}
