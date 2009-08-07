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
#include "gck-secret-textual.h"

#include "egg/egg-buffer.h"

#include "gck/gck-serializable.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
};

struct _GckSecretCollection {
	GckSecretObject parent;
	GHashTable *secrets;
	GList *items;
	gchar *password;
};

static void gck_secret_collection_serializable (GckSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GckSecretCollection, gck_secret_collection, GCK_TYPE_SECRET_OBJECT, 0,
               G_IMPLEMENT_INTERFACE (GCK_TYPE_SERIALIZABLE, gck_secret_collection_serializable));

/* -----------------------------------------------------------------------------
 * INTERNAL
 */



/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_secret_collection_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
#if 0
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	
	switch (attr->type) {
	}
#endif	
	return GCK_OBJECT_CLASS (gck_secret_collection_parent_class)->get_attribute (base, session, attr);
}

static void
gck_secret_collection_init (GckSecretCollection *self)
{
	self->secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static GObject*
gck_secret_collection_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (G_OBJECT_CLASS (gck_secret_collection_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);

	return G_OBJECT (self);
}

static void
gck_secret_collection_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                    GParamSpec *pspec)
{
#if 0
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
#endif
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_collection_get_property (GObject *obj, guint prop_id, GValue *value, 
                                    GParamSpec *pspec)
{
#if 0
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
#endif
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_collection_dispose (GObject *obj)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	g_hash_table_remove_all (self->secrets);

	G_OBJECT_CLASS (gck_secret_collection_parent_class)->dispose (obj);
}

static void
gck_secret_collection_finalize (GObject *obj)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);

	if (self->secrets)
		g_hash_table_destroy (self->secrets);
	self->secrets = NULL;

	G_OBJECT_CLASS (gck_secret_collection_parent_class)->finalize (obj);
}

static void
gck_secret_collection_class_init (GckSecretCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	
	gck_secret_collection_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->constructor = gck_secret_collection_constructor;
	gobject_class->dispose = gck_secret_collection_dispose;
	gobject_class->finalize = gck_secret_collection_finalize;
	gobject_class->set_property = gck_secret_collection_set_property;
	gobject_class->get_property = gck_secret_collection_get_property;

	gck_class->get_attribute = gck_secret_collection_get_attribute;
}

static gboolean
gck_secret_collection_real_load (GckSerializable *base, GckSecret *login, const guchar *data, gsize n_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	GckDataResult res;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	res = gck_secret_binary_read (self, data, n_data);
	if (res == GCK_DATA_UNRECOGNIZED)
		res = gck_secret_textual_read (self, data, n_data);

	/* TODO: This doesn't transfer knowledge of 'wrong password' back up */
	return (res == GCK_DATA_SUCCESS);
}

static gboolean
gck_secret_collection_real_save (GckSerializable *base, GckSecret *login, guchar **data, gsize *n_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	GckDataResult res;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	if (self->password == NULL)
		res = gck_secret_textual_write (self, data, n_data);
	else
		res = gck_secret_binary_write (self, data, n_data);

	/* TODO: This doesn't transfer knowledge of 'no password' back up */
	return (res == GCK_DATA_SUCCESS);
}

static void
gck_secret_collection_serializable (GckSerializableIface *iface)
{
	iface->extension = ".keyring";
	iface->load = gck_secret_collection_real_load;
	iface->save = gck_secret_collection_real_save;
}


/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckSecret*
gck_secret_collection_lookup_secret (GckSecretCollection *self,
                                     const gchar *identifier)
{
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	return g_hash_table_lookup (self->secrets, identifier);
}

GList*
gck_secret_collection_get_items (GckSecretCollection *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	return g_list_copy (self->items);
}
