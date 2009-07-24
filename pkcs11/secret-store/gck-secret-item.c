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

#include "gck-secret-item.h"

#include "gck/gck-attributes.h"
#include "gck/gck-login.h"
#include "gck/gck-transaction.h"

#include "pkcs11/pkcs11g.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_SECRET,
	PROP_COLLECTION,
	PROP_FIELDS
};

struct _GckSecretItem {
	GckSecretObject parent;
	GckLogin *secret;
	GHashTable *fields;
	GckSecretCollection *collection;
};

G_DEFINE_TYPE (GckSecretItem, gck_secret_item, GCK_TYPE_SECRET_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static GType
fields_boxed_type (void)
{
	static GType type = 0;
	if (!type) 
		type = g_boxed_type_register_static ("GHashTable_Fields", 
		                                     (GBoxedCopyFunc)g_hash_table_ref,
		                                     (GBoxedFreeFunc)g_hash_table_unref);
	return type;
}

static void
each_field_append (gpointer key, gpointer value, gpointer user_data)
{
	GString *result = user_data;
	g_string_append (result, key);
	g_string_append_c (result, '\0');
	g_string_append (result, value);
	g_string_append_c (result, '\0');
}

static void
each_field_length (gpointer key, gpointer value, gpointer user_data)
{
	gsize *length = user_data;
	*length += strlen (key);
	*length += strlen (value);
	*length += 2;
}

static CK_RV
attribute_set_fields (CK_ATTRIBUTE_PTR attr, GHashTable *fields)
{
	GString *result;
	gsize length;
	CK_RV rv;
	
	g_assert (attr);
	g_assert (fields);
	
	if (!attr->pValue) {
		length = 0;
		g_hash_table_foreach (fields, each_field_length, &length);
		attr->ulValueLen = length;
		return CKR_OK;
	}
	
	result = g_string_sized_new (256);
	g_hash_table_foreach (fields, each_field_append, result);
	
	rv = gck_attribute_set_data (attr, result->str, result->len);
	g_string_free (result, TRUE);
	
	return rv;
}

static CK_RV
attribute_get_fields (CK_ATTRIBUTE_PTR attr, GHashTable **fields)
{
	GHashTable *result;
	gchar *name;
	gsize n_name;
	gchar *value;
	gsize n_value;
	gchar *ptr;
	gchar *last;
	
	g_assert (attr);
	g_assert (fields);

	ptr = attr->pValue;
	last = ptr + attr->ulValueLen;
	
	if (!ptr && last != ptr)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	result = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	while (ptr && ptr != last) {
		g_assert (ptr < last);
		
		name = ptr;
		ptr = memchr (ptr, 0, last - ptr);
		
		/* No value is present? */
		if (!ptr) {
			g_hash_table_unref (result);
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		
		n_name = ptr - name;
		value = ptr;
		ptr = memchr (ptr, 0, last - ptr);
		
		/* The last value */
		if (ptr == NULL)
			ptr = last;
		
		n_value = ptr - value;

		/* Validate the name and value*/
		if (!g_utf8_validate (name, n_name, NULL) || 
		    !g_utf8_validate (value, n_value, NULL)) {
			g_hash_table_unref (result);
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		
		g_hash_table_replace (result, g_strndup (name, n_name), g_strndup (value, n_value));
	}
	
	*fields = result;
	return CKR_OK;
}

static gboolean
complete_set_secret (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);
	GckLogin *old_secret = user_data;
	
	if (gck_transaction_get_failed (transaction)) {
		gck_secret_item_set_secret (self, old_secret);
	} else {
		gck_object_notify_attribute (GCK_OBJECT (obj), CKA_VALUE);
		g_object_notify (G_OBJECT (obj), "secret");
		gck_secret_object_was_modified (GCK_SECRET_OBJECT (self));
	}

	if (old_secret)
		g_object_unref (old_secret);
	return TRUE;
}

static void
begin_set_secret (GckSecretItem *self, GckTransaction *transaction, GckLogin *secret)
{
	g_assert (GCK_IS_SECRET_OBJECT (self));
	g_assert (!gck_transaction_get_failed (transaction));
	
	if (self->secret)
		g_object_ref (self->secret);
	gck_transaction_add (transaction, self, complete_set_secret, self->secret);
	gck_secret_item_set_secret (self, secret);
}


static gboolean
complete_set_fields (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);
	GHashTable *old_fields = user_data;
	
	if (gck_transaction_get_failed (transaction)) {
		if (self->fields)
			g_hash_table_unref (self->fields);
		self->fields = old_fields;
	} else {
		gck_object_notify_attribute (GCK_OBJECT (obj), CKA_G_FIELDS);
		g_object_notify (G_OBJECT (obj), "fields");
		gck_secret_object_was_modified (GCK_SECRET_OBJECT (self));
		if (old_fields)
			g_hash_table_unref (old_fields);
	}

	return TRUE;
}

static void
begin_set_fields (GckSecretItem *self, GckTransaction *transaction, GHashTable *fields)
{
	g_assert (GCK_IS_SECRET_OBJECT (self));
	g_assert (!gck_transaction_get_failed (transaction));
	
	gck_transaction_add (transaction, self, complete_set_fields, self->fields);
	self->fields = fields;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_secret_item_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSecretItem *self = GCK_SECRET_ITEM (base);
	const gchar *identifier;
	const gchar *password;
	gsize n_password;
	
	switch (attr->type) {
	case CKA_VALUE:
		if (gck_secret_item_real_is_locked (self, session))
			return CKR_USER_NOT_LOGGED_IN;
		g_return_val_if_fail (self->secret, CKR_GENERAL_ERROR);
		password = gck_login_get_password (self->secret, &n_password);
		return gck_attribute_set_data (attr, password, n_password);
		
	case CKA_G_COLLECTION:
		g_return_val_if_fail (self->collection, CKR_GENERAL_ERROR);
		identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (self->collection));
		return gck_attribute_set_string (attr, identifier);
		
	case CKA_G_FIELDS:
		return attribute_set_fields (attr, self->fields);
	}
	
	return GCK_OBJECT_CLASS (gck_secret_item_parent_class)->get_attribute (base, session, attr);
}

static void
gck_secret_item_real_set_attribute (GckObject *base, GckSession *session, 
                                    GckTransaction *transaction, CK_ATTRIBUTE_PTR attr)
{
	GckSecretItem *self = GCK_SECRET_ITEM (base);
	GHashTable *fields;
	GckLogin *login;
	CK_RV rv;
	
	/* Check that the object is not locked */
	if (!gck_secret_item_real_is_locked (self, session)) {
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	}
	
	switch (attr->type) {
	case CKA_VALUE:
		login = gck_login_new (attr->pValue, attr->ulValueLen);
		begin_set_secret (self, transaction, login);
		break;
		
	case CKA_G_FIELDS:
		rv = attribute_get_fields (attr, &fields);
		if (rv != CKR_OK)
			gck_transaction_fail (transaction, rv);
		else
			begin_set_fields (self, transaction, fields);
		break;
	}
	
	GCK_OBJECT_CLASS (gck_secret_item_parent_class)->set_attribute (base, session, transaction, attr);
}

static void
gck_secret_item_init (GckSecretItem *self)
{
	
}

static GObject* 
gck_secret_item_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckSecretItem *self = GCK_SECRET_ITEM (G_OBJECT_CLASS (gck_secret_item_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);
	
	g_return_val_if_fail (self->collection, NULL);

	return G_OBJECT (self);
}

static void
gck_secret_item_set_property (GObject *obj, guint prop_id, const GValue *value, 
                              GParamSpec *pspec)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);
	
	switch (prop_id) {
	case PROP_SECRET:
		gck_secret_item_set_secret (self, g_value_get_object (value));
		break;
	case PROP_COLLECTION:
		g_return_if_fail (!self->collection);
		self->collection = g_value_get_object (value);
		g_return_if_fail (self->collection);
		g_object_add_weak_pointer (G_OBJECT (self->collection), 
		                           (gpointer*)&(self->collection));
		break;
	case PROP_FIELDS:
		gck_secret_item_set_fields (self, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_item_get_property (GObject *obj, guint prop_id, GValue *value, 
                              GParamSpec *pspec)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);
	
	switch (prop_id) {
	case PROP_SECRET:
		g_value_set_object (value, gck_secret_item_get_secret (self));
		break;
	case PROP_COLLECTION:
		g_value_set_object (value, gck_secret_item_get_collection (self));
		break;
	case PROP_FIELDS:
		g_value_set_boxed (value, gck_secret_item_get_fields (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_item_dispose (GObject *obj)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);

	if (self->collection)
		g_object_remove_weak_pointer (G_OBJECT (self->collection),
		                              (gpointer*)&(self->collection));
	self->collection = NULL;
	
	gck_secret_item_set_secret (self, NULL);
	
	G_OBJECT_CLASS (gck_secret_item_parent_class)->dispose (obj);
}

static void
gck_secret_item_finalize (GObject *obj)
{
	GckSecretItem *self = GCK_SECRET_ITEM (obj);
	
	g_assert (!self->collection);
	g_assert (!self->secret);
	
	if (self->fields)
		g_hash_table_unref (self->fields);
	self->fields = NULL;

	G_OBJECT_CLASS (gck_secret_item_parent_class)->finalize (obj);
}

static void
gck_secret_item_class_init (GckSecretItemClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckSecretObjectClass *secret_class = GCK_SECRET_OBJECT_CLASS (klass);
	
	gck_secret_item_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->constructor = gck_secret_item_constructor;
	gobject_class->dispose = gck_secret_item_dispose;
	gobject_class->finalize = gck_secret_item_finalize;
	gobject_class->set_property = gck_secret_item_set_property;
	gobject_class->get_property = gck_secret_item_get_property;

	gck_class->get_attribute = gck_secret_item_real_get_attribute;
	gck_class->set_attribute = gck_secret_item_real_set_attribute;
	
	secret_class->is_locked = gck_secret_item_real_is_locked;
	secret_class->lock = gck_secret_item_real_lock;

	g_object_class_install_property (gobject_class, PROP_SECRET,
	           g_param_spec_object ("secret", "Secret", "Item's Secret", 
	                                GCK_TYPE_LOGIN, G_PARAM_READWRITE));
	
	g_object_class_install_property (gobject_class, PROP_SECRET,
	           g_param_spec_object ("collection", "Collection", "Item's Collection", 
	                                GCK_TYPE_SECRET_COLLECTION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	
	g_object_class_install_property (gobject_class, PROP_FIELDS,
	           g_param_spec_boxed ("fields", "Fields", "Item's fields", 
	                               fields_boxed_type (), G_PARAM_READWRITE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckSecretCollection*
gck_secret_item_get_collection (GckSecretItem *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_ITEM (self), NULL);
	return self->collection;
}

GckLogin*
gck_secret_item_get_secret (GckSecretItem *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_ITEM (self), NULL);
	return self->secret;	
}

void
gck_secret_item_set_secret (GckSecretItem *self, GckLogin *secret)
{
	g_return_if_fail (GCK_IS_SECRET_ITEM (self));
	
	if (secret == self->secret)
		return;
	
	if (self->secret)
		g_object_remove_weak_pointer (G_OBJECT (self->secret),
		                              (gpointer*)&(self->secret));
	self->secret = secret;
	if (self->secret)
		g_object_add_weak_pointer (G_OBJECT (self->secret),
		                           (gpointer*)&(self->secret));
	
	g_object_notify (G_OBJECT (self), "secret");
} 

GHashTable*
gck_secret_item_get_fields (GckSecretItem *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_ITEM (self), NULL);
	return self->fields;
}

void
gck_secret_item_set_fields (GckSecretItem *self, GHashTable *fields)
{
	g_return_if_fail (GCK_IS_SECRET_ITEM (self));
	
	if (fields == self->fields)
		return;
	
	if (self->fields)
		g_hash_table_unref (fields);
	self->fields = fields;
	if (self->fields)
		g_hash_table_ref (fields);
	
	g_object_notify (G_OBJECT (self), "fields");
	gck_object_notify_attribute (GCK_OBJECT (self), CKA_G_FIELDS);
	gck_secret_object_was_modified (GCK_SECRET_OBJECT (self));
}
