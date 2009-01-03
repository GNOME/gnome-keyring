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

#include "gck-attributes.h"
#include "gck-object.h"
#include "gck-memory-store.h"
#include "gck-transaction.h"
#include "gck-util.h"

struct _GckMemoryStore {
	GckStore parent;
	GHashTable *entries;
};

typedef struct _Revert {
	GHashTable *attributes;
	CK_ATTRIBUTE_TYPE type;
	CK_ATTRIBUTE_PTR attr;
} Revert;

G_DEFINE_TYPE (GckMemoryStore, gck_memory_store, GCK_TYPE_STORE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
attribute_free (gpointer data)
{
	CK_ATTRIBUTE_PTR attr = data;
	if (attr) {
		g_free (attr->pValue);
		g_slice_free (CK_ATTRIBUTE, attr);
	}
}

static CK_ATTRIBUTE_PTR
attribute_dup (CK_ATTRIBUTE_PTR attr)
{
	CK_ATTRIBUTE_PTR copy;
	g_assert (attr);
	copy = g_slice_new (CK_ATTRIBUTE);
	copy->ulValueLen = attr->ulValueLen;
	copy->pValue = g_memdup (attr->pValue, copy->ulValueLen);
	copy->type = attr->type;
	return copy;
}

static void
object_gone (gpointer data, GObject *was_object)
{
	GckMemoryStore *self;
	
	g_assert (GCK_IS_MEMORY_STORE (data));
	self = GCK_MEMORY_STORE (data);
	
	if (!g_hash_table_remove (self->entries, was_object))
		g_return_if_reached ();
}

static gboolean
remove_each_object (gpointer key, gpointer value, gpointer user_data)
{
	g_assert (GCK_IS_OBJECT (key));
	g_assert (GCK_IS_MEMORY_STORE (user_data));
	
	g_object_weak_unref (key, object_gone, user_data);
	return TRUE;
}

static gboolean
complete_set (GckTransaction *transaction, GckObject *object, Revert *revert)
{
	g_assert (GCK_IS_OBJECT (object));

	if (gck_transaction_get_failed (transaction)) {
		if (revert->attr)
			g_hash_table_replace (revert->attributes, &(revert->attr->type), revert->attr);
		else
			g_hash_table_remove (revert->attributes, &(revert->type));
		
		gck_object_notify_attribute (object, revert->type);

		revert->attr = NULL;
		revert->type = 0;
	}
		
	g_hash_table_unref (revert->attributes);
	attribute_free (revert->attr);
	g_slice_free (Revert, revert);
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_memory_store_real_read_value (GckStore *base, GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckMemoryStore *self = GCK_MEMORY_STORE (base);
	GHashTable *attributes;
	CK_ATTRIBUTE_PTR at;
	
	attributes = g_hash_table_lookup (self->entries, object);
	if (attributes == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	at = g_hash_table_lookup (attributes, &(attr->type));
	if (at == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	g_assert (at->type == attr->type);
	
	/* Yes, we don't fill a buffer, just return pointer */
	attr->pValue = at->pValue;
	attr->ulValueLen = at->ulValueLen;
	
	return CKR_OK;
}

static void
gck_memory_store_real_write_value (GckStore *base, GckTransaction *transaction,
                                   GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckMemoryStore *self = GCK_MEMORY_STORE (base);
	GHashTable *attributes;
	CK_ATTRIBUTE_PTR at;
	Revert *revert;
	
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	
	attributes = g_hash_table_lookup (self->entries, object);
	if (attributes == NULL) {
		g_object_weak_ref (G_OBJECT (object), object_gone, self);
		attributes = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, 
		                                    NULL, attribute_free);
		g_hash_table_replace (self->entries, object, attributes);
	}
	
	/* No need to go any further if no change */
	at = g_hash_table_lookup (attributes, &(attr->type));
	if (at != NULL && gck_attribute_equal (at, attr))
		return;

	revert = g_slice_new0 (Revert);
	revert->attributes = g_hash_table_ref (attributes);
	revert->type = attr->type;
	revert->attr = at;
	g_hash_table_steal (attributes, &(attr->type));
	gck_transaction_add (transaction, object, (GckTransactionFunc)complete_set, revert);

	attr = attribute_dup (attr);
	g_hash_table_replace (attributes, &(attr->type), attr);
	gck_object_notify_attribute (object, attr->type);
}

static GObject* 
gck_memory_store_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckMemoryStore *self = GCK_MEMORY_STORE (G_OBJECT_CLASS (gck_memory_store_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	

	return G_OBJECT (self);
}

static void
gck_memory_store_init (GckMemoryStore *self)
{
	self->entries = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)g_hash_table_unref);
}

static void
gck_memory_store_dispose (GObject *obj)
{
	GckMemoryStore *self = GCK_MEMORY_STORE (obj);
	
	g_hash_table_foreach_remove (self->entries, remove_each_object, self);
    
	G_OBJECT_CLASS (gck_memory_store_parent_class)->dispose (obj);
}

static void
gck_memory_store_finalize (GObject *obj)
{
	GckMemoryStore *self = GCK_MEMORY_STORE (obj);

	g_assert (g_hash_table_size (self->entries) == 0);
	g_hash_table_destroy (self->entries);
	self->entries = NULL;

	G_OBJECT_CLASS (gck_memory_store_parent_class)->finalize (obj);
}

static void
gck_memory_store_set_property (GObject *obj, guint prop_id, const GValue *value, 
                               GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_memory_store_get_property (GObject *obj, guint prop_id, GValue *value, 
                               GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_memory_store_class_init (GckMemoryStoreClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckStoreClass *store_class = GCK_STORE_CLASS (klass);
    
	gobject_class->constructor = gck_memory_store_constructor;
	gobject_class->dispose = gck_memory_store_dispose;
	gobject_class->finalize = gck_memory_store_finalize;
	gobject_class->set_property = gck_memory_store_set_property;
	gobject_class->get_property = gck_memory_store_get_property;
	
	store_class->read_value = gck_memory_store_real_read_value;
	store_class->write_value = gck_memory_store_real_write_value;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckMemoryStore*
gck_memory_store_new (void)
{
	return g_object_new (GCK_TYPE_MEMORY_STORE, NULL);
}
