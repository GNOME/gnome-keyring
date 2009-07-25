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

#include "gck-secret-fields.h"
#include "gck-secret-search.h"

#include "pkcs11g.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_FIELDS
};

struct _GckSecretSearch {
	GckObject parent;
	GHashTable *fields;
	GList *managers;
	GList *objects;
};

G_DEFINE_TYPE (GckSecretSearch, gck_secret_search, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static void
manager_gone_away (gpointer user_data, GObject *where_the_object_was)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (user_data);
	GList *l;
	
	g_return_if_fail (self);
	
	l = g_list_find (self->managers, where_the_object_was);
	g_return_if_fail (l != NULL);
	self->managers = g_list_delete_link (self->managers, l);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV
gck_secret_search_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE_PTR attr)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (base);
	
	switch (attr->type) {
	case CKA_G_FIELDS:
		return gck_secret_fields_serialize (attr, self->fields);
	}
	
	return GCK_OBJECT_CLASS (gck_secret_search_parent_class)->get_attribute (base, session, attr);
}


static void
gck_secret_search_init (GckSecretSearch *self)
{
	
}

static GObject*
gck_secret_search_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (G_OBJECT_CLASS (gck_secret_search_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);
	
	g_return_val_if_fail (self->fields, NULL);

	return G_OBJECT (self);
}

static void
gck_secret_search_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                    GParamSpec *pspec)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	switch (prop_id) {
	case PROP_FIELDS:
		g_return_if_fail (!self->fields);
		self->fields = g_value_dup_boxed (value);
		g_return_if_fail (self->fields);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_search_get_property (GObject *obj, guint prop_id, GValue *value, 
                                    GParamSpec *pspec)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	switch (prop_id) {
	case PROP_FIELDS:
		g_return_if_fail (self->fields);
		g_value_set_boxed (value, gck_secret_search_get_fields (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_search_dispose (GObject *obj)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);
	GList *l;
	
	for (l = self->managers; l; l = g_list_next (l))
		g_object_weak_unref (G_OBJECT (l->data), manager_gone_away, self);
	g_list_free (self->managers);
	self->managers = NULL;

	G_OBJECT_CLASS (gck_secret_search_parent_class)->dispose (obj);
}

static void
gck_secret_search_finalize (GObject *obj)
{
	GckSecretSearch *self = GCK_SECRET_SEARCH (obj);

	g_assert (!self->managers);
	
	if (self->fields)
		g_hash_table_destroy (self->fields);
	self->fields = NULL;

	G_OBJECT_CLASS (gck_secret_search_parent_class)->finalize (obj);
}

static void
gck_secret_search_class_init (GckSecretSearchClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	
	gck_secret_search_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->constructor = gck_secret_search_constructor;
	gobject_class->dispose = gck_secret_search_dispose;
	gobject_class->finalize = gck_secret_search_finalize;
	gobject_class->set_property = gck_secret_search_set_property;
	gobject_class->get_property = gck_secret_search_get_property;

	gck_class->get_attribute = gck_secret_search_get_attribute;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GHashTable*
gck_secret_search_get_fields (GckSecretSearch *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_SEARCH (self), NULL);
	return self->fields;
}
