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

#include "gck/gck-session.h"

#include <glib/gi18n.h>

struct _GckSecretCollection {
	GckSecretObject parent;
	GckSecretData *data;
	GHashTable *items;
};

G_DEFINE_TYPE (GckSecretCollection, gck_secret_collection, GCK_TYPE_SECRET_OBJECT);

#if 0
static void gck_secret_collection_serializable (GckSerializableIface *iface);

G_DEFINE_TYPE_EXTENDED (GckSecretCollection, gck_secret_collection, GCK_TYPE_SECRET_OBJECT, 0,
               G_IMPLEMENT_INTERFACE (GCK_TYPE_SERIALIZABLE, gck_secret_collection_serializable));
#endif

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gboolean
find_unlocked_secret_data (GckAuthenticator *auth, GckObject *object, gpointer user_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (object);
	GckSecretData **result = user_data;
	GckSecretData *sdata;

	g_return_val_if_fail (!*result, FALSE);

	sdata = g_object_get_data (G_OBJECT (auth), "collection-secret-data");
	if (sdata) {
		g_return_val_if_fail (sdata == self->data, FALSE);
		*result = sdata;
		return TRUE;
	}

	return FALSE;
}

static void
track_secret_data (GckSecretCollection *self, GckSecretData *data)
{
	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));

	if (self->data)
		g_object_remove_weak_pointer (G_OBJECT (self->data),
		                              (gpointer*)&(self->data));
	self->data = data;
	if (self->data)
		g_object_add_weak_pointer (G_OBJECT (self->data),
		                           (gpointer*)&self->data);
}

static void
each_value_to_list (gpointer key, gpointer value, gpointer user_data)
{
	GList **list = user_data;
	*list = g_list_prepend (*list, value);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_secret_collection_real_unlock (GckObject *obj, GckAuthenticator *auth)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
	GckSecretData *sdata;

	sdata = g_object_new (GCK_TYPE_SECRET_DATA, NULL);

	/* TODO: Implement actual unlock work here */

	g_object_set_data_full (G_OBJECT (auth), "collection-secret-data", sdata, g_object_unref);
	track_secret_data (self, sdata);

	return CKR_OK;
}

static gboolean
gck_secret_collection_real_is_locked (GckSecretObject *obj, GckSession *session)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
	return gck_secret_collection_unlocked_data (self, session) ? FALSE : TRUE;
}

static void
gck_secret_collection_init (GckSecretCollection *self)
{
	self->items = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
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

	g_assert (self->data == NULL);

	g_hash_table_destroy (self->items);
	self->items = NULL;

	G_OBJECT_CLASS (gck_secret_collection_parent_class)->finalize (obj);
}

static void
gck_secret_collection_class_init (GckSecretCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	GckSecretObjectClass *secret_class = GCK_SECRET_OBJECT_CLASS (klass);

	gck_secret_collection_parent_class = g_type_class_peek_parent (klass);

	gobject_class->dispose = gck_secret_collection_dispose;
	gobject_class->finalize = gck_secret_collection_finalize;

	gck_class->unlock = gck_secret_collection_real_unlock;

	secret_class->is_locked = gck_secret_collection_real_is_locked;
}

#if 0
static gboolean
gck_secret_collection_real_load (GckSerializable *base, GckSecret *login, const guchar *data, gsize n_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	GckDataResult res;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	res = gck_secret_binary_read (self, login, data, n_data);
	if (res == GCK_DATA_UNRECOGNIZED)
		res = gck_secret_textual_read (self, data, n_data);

	/* TODO: This doesn't transfer knowledge of 'wrong password' back up */
	return (res == GCK_DATA_SUCCESS);
}

static gboolean
gck_secret_collection_real_save (GckSerializable *base, GckSecret *login, guchar **data, gsize *n_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	GckSecret *master;
	GckDataResult res;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	if (!self->data)
		g_return_val_if_reached (FALSE);

	master = gck_secret_data_get_master (self->data);
	if (master == NULL)
		res = gck_secret_textual_write (self, data, n_data);
	else
		res = gck_secret_binary_write (self, master, data, n_data);

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
#endif

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

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

GckSecretItem*
gck_secret_collection_create_item (GckSecretCollection *self, const gchar *identifier)
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

	g_hash_table_replace (self->items, g_strdup (identifier), item);
	return item;
}

void
gck_secret_collection_remove_item (GckSecretCollection *self, GckSecretItem *item)
{
	const gchar *identifier;

	g_return_if_fail (GCK_IS_SECRET_COLLECTION (self));
	g_return_if_fail (GCK_IS_SECRET_ITEM (item));

	identifier = gck_secret_object_get_identifier (GCK_SECRET_OBJECT (item));
	g_return_if_fail (identifier);

	g_hash_table_remove (self->items, identifier);
}

GckSecretData*
gck_secret_collection_unlocked_data (GckSecretCollection *self, GckSession *session)
{
	GckSecretData *sdata = NULL;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), NULL);
	g_return_val_if_fail (GCK_IS_SESSION (session), NULL);

	/*
	 * Look for authenticator objects that this session has access
	 * to, and use those to find the secret data. If a secret data is
	 * found, it should match the one we are tracking in self->data.
	 */

	gck_session_for_each_authenticator (session, GCK_OBJECT (self),
	                                    find_unlocked_secret_data, &sdata);

	return sdata;
}
