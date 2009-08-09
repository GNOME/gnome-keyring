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
#include "gck/gck-transaction.h"
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
 * INTERNAL
 */

typedef struct _set_secret_args {
	gchar *identifier;
	GckSecret *old_secret;
} set_secret_args;

static gboolean
complete_set_secret (GckTransaction *transaction, GObject *obj, gpointer user_data)
{
	GckSecretData *self = GCK_SECRET_DATA (obj);
	set_secret_args *args = user_data;

	/* If the transaction failed, revert */
	if (gck_transaction_get_failed (transaction)) {
		if (!args->old_secret) {
			g_hash_table_remove (self->secrets, args->identifier);
		} else {
			g_hash_table_replace (self->secrets, args->identifier, args->old_secret);
			args->identifier = NULL; /* hash table took ownership */
			args->old_secret = NULL; /* ditto */
		}
	}

	/* Free up transaction data */
	g_free (args->identifier);
	if (args->old_secret)
		g_object_unref (args->old_secret);
	g_slice_free (set_secret_args, args);

	return TRUE;
}

static void
begin_set_secret (GckSecretData *self, GckTransaction *transaction,
                  const gchar *identifier, GckSecret *secret)
{
	set_secret_args *args;

	g_assert (GCK_IS_SECRET_DATA (self));
	g_assert (!gck_transaction_get_failed (transaction));
	g_assert (identifier);
	g_assert (GCK_IS_SECRET (secret));

	args = g_slice_new0 (set_secret_args);

	/* Take ownership of the old data, if present */
	if (g_hash_table_lookup_extended (self->secrets, identifier,
	                                  (gpointer*)&args->identifier,
	                                  (gpointer*)&args->old_secret)) {
		if (!g_hash_table_steal (self->secrets, args->identifier))
			g_assert_not_reached ();
	} else {
		args->identifier = g_strdup (identifier);
	}

	/* Replace with our new data */
	g_hash_table_replace (self->secrets, g_strdup (identifier),
	                      g_object_ref (secret));

	/* Track in the transaction */
	gck_transaction_add (transaction, self, complete_set_secret, args);
}

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

const guchar*
gck_secret_data_get_raw (GckSecretData *self, const gchar *identifier,
                         gsize *n_result)
{
	GckSecret *secret;

	g_return_val_if_fail (GCK_IS_SECRET_DATA (self), NULL);
	g_return_val_if_fail (identifier, NULL);
	g_return_val_if_fail (n_result, NULL);

	secret = gck_secret_data_get_secret (self, identifier);
	if (secret == NULL)
		return NULL;

	return gck_secret_get (secret, n_result);
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
gck_secret_data_set_transacted  (GckSecretData *self, GckTransaction *transaction,
                                 const gchar *identifier, GckSecret *secret)
{
	g_return_if_fail (GCK_IS_SECRET_DATA (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (identifier);
	g_return_if_fail (GCK_IS_SECRET (secret));

	begin_set_secret (self, transaction, identifier, secret);
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
