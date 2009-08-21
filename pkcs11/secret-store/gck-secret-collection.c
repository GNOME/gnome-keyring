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

#include "gck/gck-authenticator.h"
#include "gck/gck-secret.h"
#include "gck/gck-session.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_FILENAME
};

struct _GckSecretCollection {
	GckSecretObject parent;
	GckSecretData *sdata;
	GHashTable *items;
	gchar *filename;
};

G_DEFINE_TYPE (GckSecretCollection, gck_secret_collection, GCK_TYPE_SECRET_OBJECT);

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

static gboolean
find_unlocked_secret_data (GckAuthenticator *auth, GckObject *object, gpointer user_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (object);
	GckSecretData **result = user_data;
	GckSecretData *sdata;

	g_return_val_if_fail (!*result, FALSE);

	sdata = g_object_get_data (G_OBJECT (auth), "collection-secret-data");
	if (sdata) {
		g_return_val_if_fail (sdata == self->sdata, FALSE);
		*result = sdata;
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
		                           (gpointer*)&self->sdata);
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

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static CK_RV
gck_secret_collection_real_unlock (GckObject *obj, GckAuthenticator *auth)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (obj);
	GckDataResult res;
	GckSecretData *sdata;
	GckSecret *master;

	master = gck_authenticator_get_login (auth);

	/* Already unlocked, make sure pin matches */
	if (self->sdata) {
		if (!gck_secret_equal (gck_secret_data_get_master (self->sdata), master))
			return CKR_PIN_INCORRECT;

		/* Authenticator now tracks our secret data */
		g_object_set_data_full (G_OBJECT (auth), "collection-secret-data",
		                        g_object_ref (self->sdata), g_object_unref);
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
		g_object_set_data_full (G_OBJECT (auth), "collection-secret-data", sdata, g_object_unref);
		track_secret_data (self, sdata);
		return CKR_OK;
	case GCK_DATA_LOCKED:
		g_object_unref (sdata);
		return CKR_PIN_INCORRECT;
	case GCK_DATA_UNRECOGNIZED:
		g_object_unref (sdata);
		g_message ("unrecognized or invalid keyring: %s", self->filename);
		return CKR_FUNCTION_FAILED;
	case GCK_DATA_FAILURE:
		g_object_unref (sdata);
		g_message ("failed to read or parse keyring: %s", self->filename);
		return CKR_GENERAL_ERROR;
	default:
		g_assert_not_reached ();
	}
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
	return gck_secret_collection_unlocked_data (self, session) ? FALSE : TRUE;
}

static void
gck_secret_collection_init (GckSecretCollection *self)
{
	self->items = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
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

	gck_class->unlock = gck_secret_collection_real_unlock;
	gck_class->expose_object = gck_secret_collection_expose;

	secret_class->is_locked = gck_secret_collection_real_is_locked;

	g_object_class_install_property (gobject_class, PROP_FILENAME,
	           g_param_spec_string ("filename", "Filename", "Collection filename (without path)",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
}

#if 0
static gboolean
gck_secret_collection_real_save (GckSerializable *base, GckSecret *login, guchar **data, gsize *n_data)
{
	GckSecretCollection *self = GCK_SECRET_COLLECTION (base);
	GckSecret *master;
	GckDataResult res;

	g_return_val_if_fail (GCK_IS_SECRET_COLLECTION (self), FALSE);
	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (n_data, FALSE);

	if (!self->sdata)
		g_return_val_if_reached (FALSE);

	master = gck_secret_data_get_master (self->sdata);
	if (master == NULL)
		res = gck_secret_textual_write (self, data, n_data);
	else
		res = gck_secret_binary_write (self, master, data, n_data);

	/* TODO: This doesn't transfer knowledge of 'no password' back up */
	return (res == GCK_DATA_SUCCESS);
}

#endif

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

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
	 * found, it should match the one we are tracking in self->sdata.
	 */

	gck_session_for_each_authenticator (session, GCK_OBJECT (self),
	                                    find_unlocked_secret_data, &sdata);

	return sdata;
}

void
gck_secret_collection_unlocked_clear (GckSecretCollection *self)
{
	/*
	 * TODO: This is a tough one to implement. I'm holding off and wondering
	 * if we don't need it, perhaps? As it currently stands, what needs to happen
	 * here is we need to find each and every authenticator that references the
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
