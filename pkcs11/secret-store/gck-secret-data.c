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

#include "gck-secret-data.h"

#include "gck/gck-secret.h"
#include "gck/gck-util.h"

#include "egg/egg-secure-memory.h"

#include <glib/gi18n.h>

struct _GckSecretData {
	GObject parent;
	GHashTable *secrets;
	GckSecret *master;
};

G_DEFINE_TYPE (GckSecretData, gck_secret_data, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gck_secret_data_init (GckSecretData *self)
{
	self->secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
gck_secret_data_finalize (GObject *obj)
{
	GckSecretData *self = GCK_SECRET_DATA (obj);

	if (self->secrets)
		g_hash_table_destroy (self->secrets);
	self->secrets = NULL;

	if (self->master)
		g_object_unref (self->master);
	self->master = NULL;
	
	G_OBJECT_CLASS (gck_secret_data_parent_class)->finalize (obj);
}

static void
gck_secret_data_class_init (GckSecretDataClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gck_secret_data_parent_class = g_type_class_peek_parent (klass);
	gobject_class->finalize = gck_secret_data_finalize;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GckSecret*
gck_secret_data_get_secret (GckSecretData *self, const gchar *identifier)
{
	g_return_val_if_fail (GCK_IS_SECRET_DATA (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	return g_hash_table_lookup (self->secrets, identifier);
}

void
gck_secret_data_set_secret (GckSecretData *self, const gchar *identifier,
                            GckSecret *secret)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (identifier);
	g_return_if_fail (GCK_IS_SECRET (secret));
	g_hash_table_replace (self->secrets, g_strdup (identifier),
	                      g_object_ref (secret));
}

void
gck_secret_data_remove_secret (GckSecretData *self, const gchar *identifier)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (identifier);
	g_hash_table_remove (self->secrets, identifier);
}

GckSecret*
gck_secret_data_get_master (GckSecretData *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_DATA (self), NULL);
	return self->master;
}

void
gck_secret_data_set_master (GckSecretData *self, GckSecret *master)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (!master || GCK_IS_SECRET (master));
	
	if (master)
		g_object_ref (master);
	if (self->master)
		g_object_unref (self->master);
	self->master = master;
}
