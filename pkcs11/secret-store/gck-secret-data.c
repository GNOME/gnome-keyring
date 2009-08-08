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

#include "egg/egg-secure-memory.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
};

struct _GckSecretData {
	GObject parent;
	GHashTable *secrets;
	guint key_iterations;
	guchar *key_salt;
	gsize n_key_salt;
	guchar *key_encryption;
	gsize n_key_encryption;
};

typedef struct _Secret {
	guchar *data;
	gsize n_data;
} Secret;

G_DEFINE_TYPE (GckSecretData, gck_secret_data, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
free_secret (gpointer data)
{
	Secret *secret = data;
	egg_secure_clear (secret->data, secret->n_data);
	egg_secure_free (secret->data);
	g_slice_free (Secret, secret);
}

static Secret*
new_secret (const guchar *data, gsize n_data)
{
	Secret *secret = g_slice_new0 (Secret);
	secret->data = egg_secure_alloc (n_data);
	memcpy (secret->data, data, n_data);
	secret->n_data = n_data;
	return secret;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gck_secret_data_init (GckSecretData *self)
{
	self->secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_secret);
}

static void
gck_secret_data_dispose (GObject *obj)
{
	GckSecretData *self = GCK_SECRET_DATA (obj);

	g_hash_table_remove_all (self->secrets);

	G_OBJECT_CLASS (gck_secret_data_parent_class)->dispose (obj);
}

static void
gck_secret_data_finalize (GObject *obj)
{
	GckSecretData *self = GCK_SECRET_DATA (obj);

	if (self->secrets)
		g_hash_table_destroy (self->secrets);
	self->secrets = NULL;

	gck_secret_data_clear_key (self);
	
	G_OBJECT_CLASS (gck_secret_data_parent_class)->finalize (obj);
}

static void
gck_secret_data_class_init (GckSecretDataClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	
	gck_secret_data_parent_class = g_type_class_peek_parent (klass);
	
	gobject_class->dispose = gck_secret_data_dispose;
	gobject_class->finalize = gck_secret_data_finalize;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

const guchar*
gck_secret_data_get_secret (GckSecretData *self, const gchar *identifier,
                            gsize *n_secret)
{
	Secret *secret;
	
	g_return_val_if_fail (GCK_IS_SECRET_DATA (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	g_return_val_if_fail (n_secret, NULL);
	
	secret = g_hash_table_lookup (self->secrets, identifier);
	if (!secret)
		return NULL;
	*n_secret = secret->n_data;
	return secret->data;
}

void
gck_secret_data_add_secret (GckSecretData *self, const gchar *identifier,
                            const guchar *secret, gsize n_secret)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (identifier);
	g_return_if_fail (!secret || n_secret);
	
	g_hash_table_replace (self->secrets, g_strdup (identifier), 
	                      new_secret (secret, n_secret));
}

void
gck_secret_data_remove_secret (GckSecretData *self, const gchar *identifier)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (identifier);
	
	g_hash_table_remove (self->secrets, identifier);
}


void
gck_secret_data_get_key (GckSecretData *self, const guchar **key,
                         gsize *n_key, const guchar **salt, 
                         gsize *n_salt, guint *iterations)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (key && n_key);
	g_return_if_fail (salt && n_salt);
	g_return_if_fail (iterations);
	
	*key = self->key_encryption;
	*n_key = self->n_key_encryption;
	*salt = self->key_salt;
	*n_salt = self->n_key_salt;
	*iterations = self->key_iterations;
}

void
gck_secret_data_set_key (GckSecretData *self, const guchar *key,
                         gsize n_key, const guchar *salt,
                         gsize n_salt, guint iterations)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (key);
	g_return_if_fail (salt);
	
	egg_secure_free (self->key_encryption);
	self->key_encryption = egg_secure_alloc (n_key);
	memcpy (self->key_encryption, key, n_key);
	self->n_key_encryption = n_key;
	
	g_free (self->key_salt);
	self->key_salt = g_malloc0 (n_salt);
	memcpy (self->key_salt, salt, n_salt);
	self->n_key_salt = n_salt;
	
	self->key_iterations = iterations;
}

void
gck_secret_data_clear_key (GckSecretData *self)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));

	self->key_iterations = 0;
	
	g_free (self->key_salt);
	self->key_salt = NULL;
	self->n_key_salt = 0;
	
	egg_secure_clear (self->key_encryption, self->n_key_encryption);
	egg_secure_free (self->key_encryption);
	self->key_encryption = NULL;
	self->n_key_encryption = 0;
}

gboolean
gck_secret_data_has_key (GckSecretData *self)
{
	g_return_val_if_fail (GCK_IS_SECRET_DATA (self), FALSE);
	return self->key_encryption != NULL;
}
