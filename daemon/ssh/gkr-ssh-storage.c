/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-storage.c - Storage of SSH keys

   Copyright (C) 2008 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-ssh-private.h"
#include "gkr-ssh-storage.h"

#include "egg/egg-buffer.h"
#include "common/gkr-crypto.h"
#include "common/gkr-location.h"
#include "common/gkr-location-watch.h"
#include "egg/egg-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"

#include "pkcs11/pkcs11.h"

#include "pk/gkr-pk-privkey.h"
#include "pk/gkr-pk-manager.h"
#include "pk/gkr-pk-util.h"

#include "pkix/gkr-pkix-asn1.h"
#include "pkix/gkr-pkix-der.h"
#include "pkix/gkr-pkix-openssl.h"
#include "pkix/gkr-pkix-pem.h"
#include "pkix/gkr-pkix-types.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib.h>
#include <glib/gi18n.h>

#include <stdarg.h>

typedef struct _GkrSshStoragePrivate GkrSshStoragePrivate;

struct _GkrSshStoragePrivate {
	gkrid specific_load_request;
	GQuark home_location;
	GkrPkIndex *index;
	GkrLocationWatch *watch;
};

#define GKR_SSH_STORAGE_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_SSH_STORAGE, GkrSshStoragePrivate))

G_DEFINE_TYPE(GkrSshStorage, gkr_ssh_storage, GKR_TYPE_PK_STORAGE);

static GQuark PEM_RSA_PRIVATE_KEY;
static GQuark PEM_DSA_PRIVATE_KEY;

static GkrPkIndex* gkr_ssh_storage_index (GkrPkStorage *storage, GQuark unused);

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static GQuark
location_for_storing_private_key (GkrSshStorage *storage, gcry_sexp_t sexp)
{
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (storage);
	const gchar *pref;
	gchar *name;
	GQuark loc = 0;
	int algo, i;
	
	/* What kind of key is it? */
	algo = gkr_crypto_skey_parse (sexp, &algo, NULL, NULL);
	switch (algo) {
	case GCRY_PK_RSA:
		pref = "id_rsa";
		break;
	case GCRY_PK_DSA:
		pref = "id_dsa";
		break;
	default:
		pref = "id_xsa";
		break;
	};
	
	/* Find a file that's unique */
	for (i = 0; i < ~0; i++) {
		name = (i == 0) ? g_strdup (pref) : g_strdup_printf ("%s.%d", pref, i);
		loc = gkr_location_from_child (pv->home_location, name);
		if (!gkr_location_test_file(loc, G_FILE_TEST_EXISTS))
			break;
		g_free (name);
		loc = 0;
	}

	return loc;
}

static GkrPkObject*
prepare_object (GkrSshStorage *storage, GQuark location, gkrconstid digest)
{
	GkrPkManager *manager;
	GkrPkObject *object;
	
	manager = gkr_pk_manager_for_token ();
	object = gkr_pk_manager_find_by_digest (manager, digest);
	
	/* The object already exists just reference it */
	if (object) {
		gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);
		return object;
	} 
	
	object = g_object_new (GKR_TYPE_PK_PRIVKEY, "manager", manager, "location", location, 
	                       "digest", digest, NULL);
	gkr_pk_storage_add_object (GKR_PK_STORAGE (storage), object);

	/* Object was reffed */
	g_object_unref (object);
	return object;
}

static GQuark
public_location_for_private (GQuark loc)
{
	gchar *pstr;
	GQuark ploc;
	
	pstr = g_strdup_printf ("%s.pub", gkr_location_to_string (loc));
	ploc = gkr_location_from_string (pstr);
	g_free (pstr);
	
	return ploc;
}

static gboolean
storage_write_public_key (GkrSshStorage *storage, gcry_sexp_t sexp, 
                          const gchar *comment, GQuark loc, GError **err)
{
	guchar *data;
	gsize n_data;
	gboolean ret;
	
	g_return_val_if_fail (loc, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);

	data = gkr_ssh_storage_write_public_key (sexp, comment, &n_data); 
	if (!data) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, _("Couldn't encode secure shell public key."));
		return FALSE;
	}
	
	/* And write that to disk */ 
	ret = gkr_location_write_file (loc, data, n_data, err);
	g_free (data);
	return ret;
}

static gboolean
store_public_key_for_private (GkrSshStorage *storage, GkrPkObject *priv, GError **err)
{
	gcry_sexp_t sexp, psexp;
	gchar *label;
	gboolean ret;
	GQuark ploc;
	
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (priv), FALSE);
	g_return_val_if_fail (priv->location, FALSE);

	/* Don't have a key to write out :( */
	g_object_get (priv, "gcrypt-sexp", &sexp, NULL);
	if (!sexp)
		return TRUE;
	
	/* Convert to a public key */
	if (!gkr_crypto_skey_private_to_public (sexp, &psexp))
		g_return_val_if_reached (FALSE);
	
	/* And then store that public key next to the private */
	ploc = public_location_for_private (priv->location);
	g_object_get (priv, "orig-label", &label, NULL);
	ret = storage_write_public_key (storage, psexp, label, ploc, err);
	g_free (label);
	gcry_sexp_release (psexp);
	
	return ret;
}

static GkrPkixResult 
load_encrypted_key (GkrSshStorage *storage, gkrid digest, GQuark location, 
                    const gchar *dekinfo, const guchar *data, gsize n_data, 
                    gcry_sexp_t *skey)
{
	GkrPkixResult ret;
	gchar *password;
	guchar *decrypted;
	gsize n_decrypted;
	gboolean res;
	gint l, state;
	
	state = GKR_PK_STORAGE_PASSWD_STATE;
	while (!gkr_async_is_stopping ()) {

		/* Get the password to try */
		if (!gkr_pk_storage_get_load_password (GKR_PK_STORAGE (storage), location,
		                                       digest, GKR_PKIX_PRIVATE_KEY, NULL, 
		                                       &state, &password))
			return GKR_PKIX_SUCCESS;

		decrypted = NULL;
		n_decrypted = 0;
		
		/* Decrypt, this will result in garble if invalid password */	
		res = gkr_pkix_openssl_decrypt_block (dekinfo, password, data, n_data, 
		                                      &decrypted, &n_decrypted);
		egg_secure_free (password);
		
		if (!res)
			return GKR_PKIX_UNRECOGNIZED;
			
		g_assert (decrypted);
		
		/* Unpad the DER data */
		l = gkr_pkix_asn1_element_length (decrypted, n_decrypted);
		if (l > 0)
			n_decrypted = l;
	
		/* Try to parse */
		ret = gkr_pkix_der_read_private_key (decrypted, n_decrypted, skey);
		egg_secure_free (decrypted);

		if (ret != GKR_PKIX_UNRECOGNIZED)
			return ret;
	}
	
	return GKR_PKIX_FAILURE;
}

static void
index_correspending_public_key (GkrSshStorage *storage, GQuark loc, gkrconstid digest, 
                                gchar **comment)
{
 	GError *err = NULL;
	GkrPkixResult res;
	GkrPkIndex *index;
	gcry_sexp_t sexp;
	guchar *data;
	gsize n_data;
	GQuark ploc;
	
	*comment = NULL;

	g_return_if_fail (loc);
	
	ploc = public_location_for_private (loc);
	g_return_if_fail (ploc);
	
	/* Does the file even exist? */
	if (!gkr_location_test_file (ploc, G_FILE_TEST_IS_REGULAR))
		return;
			
	if (!gkr_location_read_file (ploc, &data, &n_data, &err)) {
		g_message ("couldn't read public key file: %s: %s", g_quark_to_string (ploc),
		           err && err->message ? err->message : "");
		g_clear_error (&err);
		return;
	}

	res = gkr_ssh_storage_load_public_key (data, n_data, &sexp, comment);
	g_free (data);
	
	if (res == GKR_PKIX_FAILURE) {
		g_message ("couldn't parse public key file: %s", g_quark_to_string (ploc));
		g_free (*comment);
		*comment = NULL;
		return;
	} else if (res == GKR_PKIX_UNRECOGNIZED) {
		g_message ("invalid secure shell public key file: %s", g_quark_to_string (ploc));
		g_free (*comment);
		*comment = NULL;
		return;
	}

	/* Write key to the indexes */
	index = gkr_ssh_storage_index (GKR_PK_STORAGE (storage), loc);
	if (!gkr_pk_index_has_value (index, digest, GKR_PK_INDEX_PUBLIC_KEY)) {
		data = gkr_pkix_der_write_public_key (sexp, &n_data);
		g_return_if_fail (data != NULL);
		gkr_pk_index_set_binary (index, digest, GKR_PK_INDEX_PUBLIC_KEY, data, n_data);
	}
	
	gcry_sexp_release (sexp);
}

typedef struct _Load {
	GkrSshStorage *storage;
	GQuark location;
	gboolean seen;
	GkrPkixResult result;
} Load;

static void
parsed_pem_block (GQuark type, const guchar *data, gsize n_data,
                  GHashTable *headers, gpointer user_data)
{
	Load *ctx = (Load*)user_data;
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (ctx->storage);
	gcry_sexp_t sexp = NULL;
	GkrPkObject *object;
	const gchar *dekinfo;
	gchar *comment;
	gkrid digest;
	
	/* Only handle SSHv2 private keys */
	if (type != PEM_RSA_PRIVATE_KEY && type != PEM_DSA_PRIVATE_KEY)
		return;
	
	/* Only parse first key in the file */
	if (ctx->seen)
		return;
	
	digest = gkr_id_new_digest (data, n_data);
	ctx->seen = TRUE;
	
	/* If it's encrypted ... */
	dekinfo = gkr_pkix_openssl_get_dekinfo (headers);
	if (dekinfo) {
		/* This key was specifically requested to be loaded */
		if (gkr_id_equals (digest, pv->specific_load_request)) {
			ctx->result = load_encrypted_key (ctx->storage, digest, ctx->location, 
			                                  dekinfo, data, n_data, &sexp);
			
		/* Nobody's asking us to load this key just yet */
		} else {
			ctx->result = GKR_PKIX_SUCCESS;
			sexp = NULL;
		}
		
	/* not encryted, just load the data */
	} else {
		ctx->result = gkr_pkix_der_read_private_key (data, n_data, &sexp);
	}
	
	if (ctx->result != GKR_PKIX_SUCCESS) {
		gkr_id_free (digest);
		return;
	}
	
	/* 
	 * Now that we have a digest, and we know the key parses, let's be helpful
	 * and check whether we have the public key in our indexes. If not, load it up.
	 * It's important that we do this before the private key object is instantiated
	 */
	index_correspending_public_key (ctx->storage, ctx->location, digest, &comment);
	
	if (gkr_id_equals (pv->specific_load_request, digest))
		pv->specific_load_request = NULL;
	
	/* Prepare and setup the object */
	object = prepare_object (ctx->storage, ctx->location, digest);
	if (sexp)
		g_object_set (object, "gcrypt-sexp", sexp, NULL);
	if (comment)
		g_object_set (object, "orig-label", comment, NULL);
	
	g_free (comment);
	gkr_id_free (digest);
}

static gboolean
storage_load_private_key (GkrSshStorage *storage, GQuark loc, GError **err)
{
	Load ctx;
	guchar *data;
	gsize n_data;
	guint num;
	
	g_return_val_if_fail (loc, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	if (!gkr_location_read_file (loc, &data, &n_data, err))
		return FALSE;

	memset (&ctx, 0, sizeof (ctx));
	ctx.storage = storage;
	ctx.location = loc;

	num = gkr_pkix_pem_parse (data, n_data, parsed_pem_block, &ctx);
	
	/* Didn't find any private key there */
	if (num == 0) 
		return TRUE;
	
	if (ctx.result == GKR_PKIX_FAILURE) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, _("Couldn't read secure shell private key: %s"),
		             g_quark_to_string (loc));
		return FALSE;
	} else if (ctx.result == GKR_PKIX_UNRECOGNIZED) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, _("Invalid secure shell private key at: %s"),
		             g_quark_to_string (loc));
		return FALSE;
	}
	
	return TRUE;
}

static gkrid
storage_write_private_key (GkrSshStorage *storage, gcry_sexp_t sexp, 
                           GQuark loc, const gchar *password, GError **err)
{
	GHashTable *headers;
	const gchar *dekinfo;
	GQuark type;
	guchar *data, *encrypted, *result;
	gsize n_data, n_encrypted, n_result;
	gboolean is_priv;
	gkrid digest = NULL;
	int algo;
	
	data = encrypted = result = NULL;
	headers = NULL;
	
	/* What kind of key is it? */
	algo = gkr_crypto_skey_parse (sexp, &algo, &is_priv, NULL);
	g_return_val_if_fail (is_priv == TRUE, NULL);
	g_return_val_if_fail (algo != 0, NULL);

	/* Figure out what kind of BEGIN/END PEM we need */
	if (algo == GCRY_PK_RSA)
		type = PEM_RSA_PRIVATE_KEY;
	else if (algo == GCRY_PK_DSA)
		type = PEM_DSA_PRIVATE_KEY;
	else
		g_return_val_if_reached (NULL); 

	/* Write out the raw key to memory */
	data = gkr_pkix_der_write_private_key (sexp, &n_data);
	g_return_val_if_fail (data, NULL);

	/* Write an encrypted private key */
	if (password) {
		headers = gkr_pkix_pem_headers_new ();
		dekinfo = gkr_pkix_openssl_prep_dekinfo (headers);

		if (!gkr_pkix_openssl_encrypt_block (dekinfo, password, data, n_data,
		                                     &encrypted, &n_encrypted)) {
			g_set_error (err, GKR_PK_STORAGE_ERROR, 0, 
			             _("Couldn't encrypt the SSH key to store it."));
			goto done;
		}
		digest = gkr_id_new_digest (encrypted, n_encrypted);
		result = gkr_pkix_pem_write (encrypted, n_encrypted, type, headers, &n_result);
		g_free (encrypted);
		
	/* Write a non-encrypted private key */
	} else {
		digest = gkr_id_new_digest (data, n_data);
		result = gkr_pkix_pem_write (data, n_data, type, headers, &n_result);
	}
	
	/* Make sure it worked */
	if (!result) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, 
		             _("Couldn't encode the SSH key to store it."));
		gkr_id_free (digest);
		digest = NULL;
		goto done;
	}
	
	/* Now write it to the file */
	if (gkr_location_write_file (loc, result, n_result, err)) {
		gkr_id_free (digest);
		digest = NULL;
	}

done:
	if (headers)
		g_hash_table_destroy (headers);
	egg_secure_free (data);
	g_free (result);
	g_free (encrypted);
	
	return digest;
}

static void
location_load (GkrLocationWatch *watch, GQuark loc, GkrSshStorage *storage)
{
	GError *err = NULL;

	/* We only get notified for private keys */
	if (!storage_load_private_key (storage, loc, &err)) {
		g_message ("couldn't parse data: %s: %s", g_quark_to_string (loc),
		           err && err->message ? err->message : "");
		g_clear_error (&err);
	}
}

static void
location_remove (GkrLocationWatch *watch, GQuark loc, GkrSshStorage *storage)
{
	/* Remove key that is at that location */
 	gkr_pk_storage_clr_objects (GKR_PK_STORAGE (storage), loc);

 	/* We only watch private keys, so try and clear out the public */
	gkr_pk_storage_clr_objects (GKR_PK_STORAGE (storage), 
	                            public_location_for_private (loc));
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void 
gkr_ssh_storage_refresh (GkrPkStorage *storage)
{
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (storage);
 	gkr_location_watch_refresh (pv->watch, FALSE);
}

static gboolean 
gkr_ssh_storage_load (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (storage);
	gboolean ret = FALSE;
		
	g_return_val_if_fail (GKR_IS_PK_OBJECT (obj), FALSE);
	g_return_val_if_fail (obj->storage == storage, FALSE);
	g_return_val_if_fail (obj->location, FALSE);
	g_return_val_if_fail (pv->specific_load_request == NULL, FALSE);
	
	g_object_ref (obj);

	/* Make note of the specific load request */
	pv->specific_load_request = obj->digest;
	
	/* Load a private key from this location */
	if (GKR_IS_PK_PRIVKEY (obj))
		storage_load_private_key (GKR_SSH_STORAGE (storage), obj->location, err);
	
	else
		g_return_val_if_reached (FALSE);
	
	/* See if it was seen */
	if (pv->specific_load_request != NULL) {
		g_set_error (err, GKR_PK_STORAGE_ERROR, 0, "The object was not found at: %s",
		             g_quark_to_string (obj->location));
		pv->specific_load_request = NULL;
		goto done;
	}
	
	/* 
	 * At this point, if we were loading a public key, it should be all loaded, 
	 * including encrypted parts. Write out the public key if needed. 
	 */
	if (GKR_IS_PK_PRIVKEY (obj) && 
	    !gkr_location_test_file (public_location_for_private (obj->location), G_FILE_TEST_EXISTS))
		store_public_key_for_private (GKR_SSH_STORAGE (storage), obj, NULL);

	ret = TRUE;

done:
	g_object_unref (obj);
	return ret;
}

static gboolean 
gkr_ssh_storage_store (GkrPkStorage *stor, GkrPkObject *obj, GError **err)
{
	GkrSshStorage *storage;
	gcry_sexp_t sexp;
	gchar *password;
	gkrid digest;
	gboolean ret;
	GQuark loc;
	
	g_return_val_if_fail (!err || !*err, FALSE);
	g_return_val_if_fail (GKR_IS_SSH_STORAGE (stor), FALSE);
	g_return_val_if_fail (obj->storage == NULL, FALSE);
	g_return_val_if_fail (obj->location == 0, FALSE);
	
	storage = GKR_SSH_STORAGE (stor);
	
	/* We don't yet support storing arbitrary public keys */
	g_return_val_if_fail (GKR_IS_PK_PRIVKEY (obj), FALSE);
	
	/* Pull out the actual part of the key */
	g_object_get (obj, "gcrypt-sexp", &sexp, NULL);
	g_return_val_if_fail (sexp, FALSE);

	/* Find a good location to store this key */
	loc = location_for_storing_private_key (storage, sexp);
	g_return_val_if_fail (loc, FALSE);
		
	/* Get a password for this key, determines whether encrypted or not */
	ret = gkr_pk_storage_get_store_password (stor, loc, obj->digest, GKR_PKIX_PRIVATE_KEY, 
	                                         gkr_pk_object_get_label (obj),
	                                         &password);
	
	/* Prompt for a password was denied */
	if (!ret)
		return TRUE;
		
	/* Store the private key */
	digest = storage_write_private_key (storage, sexp, loc, password, err);
	egg_secure_strfree (password);
	
	if (!digest)
		return FALSE;
	
	/* The object now has a (possibly new) location */
	g_object_set (obj, "location", loc, "storage", stor, "digest", digest, NULL);
	gkr_pk_storage_add_object (stor, obj);
	gkr_id_free (digest);
	
	/* Now store the public key in place if possible */
	return store_public_key_for_private (storage, obj, err);
}

static gboolean 
gkr_ssh_storage_remove (GkrPkStorage *storage, GkrPkObject *obj, GError **err)
{
	GQuark ploc;
	
	g_return_val_if_fail (!err || !*err, FALSE);
	g_return_val_if_fail (GKR_IS_SSH_STORAGE (storage), FALSE);
	g_return_val_if_fail (obj->storage == storage, FALSE);
	g_return_val_if_fail (obj->location, FALSE);
	
	/* Delete the public key along with the private */
	if (GKR_IS_PK_PRIVKEY (obj)) {
		ploc = public_location_for_private (obj->location);
		if (!gkr_location_delete_file (ploc, err))
			return FALSE;
	}
	
	/* Delete the object itself */
	if (!gkr_location_delete_file (obj->location, err))
		return FALSE;
	
	gkr_ssh_storage_refresh (storage);
	return TRUE;
}

static GkrPkIndex* 
gkr_ssh_storage_index (GkrPkStorage *storage, GQuark unused)
{
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (storage);
 	GnomeKeyringAttributeList *attrs;
	
	if (!pv->index) {
		/* Default attributes for our index */
		attrs = gnome_keyring_attribute_list_new ();
		gnome_keyring_attribute_list_append_string (attrs, "purposes", "ssh-authentication");
		
		pv->index = gkr_pk_index_open_login (attrs);
		if (!pv->index)
			pv->index = gkr_pk_index_open_session (attrs);
		
		gnome_keyring_attribute_list_free (attrs);
	}
	
	return pv->index;
}


static void
gkr_ssh_storage_init (GkrSshStorage *storage)
{
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (storage);
 	
	pv->specific_load_request = NULL;
	pv->home_location = gkr_location_from_child (GKR_LOCATION_VOLUME_HOME, ".ssh/");
	
	/* Watch all ~/.ssh/id_?sa* except for *.pub files */
	pv->watch = gkr_location_watch_new (NULL, GKR_LOCATION_VOLUME_HOME, ".ssh", 
	                                    "id_?sa*", "*.pub");
	g_return_if_fail (pv->watch); 

	g_signal_connect (pv->watch, "location-added", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-changed", G_CALLBACK (location_load), storage);
	g_signal_connect (pv->watch, "location-removed", G_CALLBACK (location_remove), storage);
}

static void
gkr_ssh_storage_dispose (GObject *obj)
{
	GkrSshStorage *storage = GKR_SSH_STORAGE (obj);
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (obj);
 	
	g_signal_handlers_disconnect_by_func (pv->watch, location_load, storage);
	g_signal_handlers_disconnect_by_func (pv->watch, location_remove, storage);
	
	if (pv->index)
		g_object_unref (pv->index);
	pv->index = NULL;
 	
	G_OBJECT_CLASS (gkr_ssh_storage_parent_class)->dispose (obj);
}

static void
gkr_ssh_storage_finalize (GObject *obj)
{
 	GkrSshStoragePrivate *pv = GKR_SSH_STORAGE_GET_PRIVATE (obj);
 	
	g_object_unref (pv->watch);
 	pv->watch = NULL;
 	
 	g_assert (pv->index == NULL);
	
	G_OBJECT_CLASS (gkr_ssh_storage_parent_class)->finalize (obj);
}

static void
gkr_ssh_storage_class_init (GkrSshStorageClass *klass)
{
	GkrPkStorageClass *storage_class = GKR_PK_STORAGE_CLASS (klass);
	GObjectClass *gobject_class;
	
	gobject_class = (GObjectClass*)klass;
	gobject_class->dispose = gkr_ssh_storage_dispose;
	gobject_class->finalize = gkr_ssh_storage_finalize;

	storage_class->refresh = gkr_ssh_storage_refresh;
	storage_class->load = gkr_ssh_storage_load;
	storage_class->store = gkr_ssh_storage_store;
	storage_class->remove = gkr_ssh_storage_remove;
	storage_class->index = gkr_ssh_storage_index;
	
	gkr_ssh_storage_parent_class = g_type_class_peek_parent (klass);

	PEM_RSA_PRIVATE_KEY = g_quark_from_static_string ("RSA PRIVATE KEY");
	PEM_DSA_PRIVATE_KEY = g_quark_from_static_string ("DSA PRIVATE KEY");

	g_type_class_add_private (gobject_class, sizeof (GkrSshStoragePrivate));
}

/* -------------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

gboolean
gkr_ssh_storage_initialize (void)
{
	GkrPkStorage *storage;
	
	storage = g_object_new (GKR_TYPE_SSH_STORAGE, NULL);
	gkr_pk_storage_register (storage, FALSE);
	g_object_unref (storage);
	
	return TRUE;
}

GkrPkixResult
gkr_ssh_storage_load_public_key (const guchar *data, gsize n_data, 
                                 gcry_sexp_t *sexp, gchar **comment)
{
	EggBuffer buf;
	const guchar *at;
	guchar *decoded;
	gsize n_decoded;
	gsize offset;
	gchar *val;
	gboolean ret;
	gint state, algo;
	guint save;

	g_return_val_if_fail (data, GKR_PKIX_FAILURE);
	g_return_val_if_fail (sexp, GKR_PKIX_FAILURE);
	
	/* Look for a key line */
	for (;;) {
		/* Eat space at the front */
		while (n_data > 0 && g_ascii_isspace (data[0])) {
			++data;
			--n_data;
		}
	
		/* Not a comment or blank line? Then parse... */
		if (data[0] != '#') 
			break;
		
		/* Skip to the next line */
		at = memchr (data, '\n', n_data);
		if (!at) 
			return GKR_PKIX_UNRECOGNIZED;
		at += 1;
		n_data -= (at - data);
		data = at;
	}

	/* Limit to use only the first line */
	at = memchr (data, '\n', n_data);
	if (at != NULL)
		n_data = at - data;
	
	/* Find the first space */
	at = memchr (data, ' ', n_data);
	if (!at) {
		g_message ("SSH public key missing space");
		return GKR_PKIX_UNRECOGNIZED;
	}
	
	/* Parse the key type */
	val = g_strndup ((gchar*)data, at - data);
	algo = gkr_ssh_proto_keytype_to_algo (val);
	if (!algo) 
		g_message ("Unsupported or unknown SSH key algorithm: %s", val);
	g_free (val);
	if (!algo)
		return GKR_PKIX_UNRECOGNIZED;
	
	/* Skip more whitespace */
	n_data -= (at - data);
	data = at;
	while (n_data > 0 && (data[0] == ' ' || data[0] == '\t')) {
		++data;
		--n_data;
	}

	/* Find the next whitespace, or the end */
	at = memchr (data, ' ', n_data);
	if (at == NULL)
		at = data + n_data;
	
	/* Decode the base64 key */
	save = state = 0;
	decoded = g_malloc (n_data * 3 / 4);
	n_decoded = g_base64_decode_step ((gchar*)data, n_data, decoded, &state, &save);
	
	/* Parse the actual key */
	egg_buffer_init_static (&buf, decoded, n_decoded);
	offset = 0;
	ret = gkr_ssh_proto_read_public (&buf, &offset, sexp, NULL);
	g_free (decoded);
	if (!ret) {
		g_message ("failed to parse base64 part of SSH key");
		return GKR_PKIX_FAILURE;
	}

	/* Skip more whitespace */
	n_data -= (at - data);
	data = at;
	while (n_data > 0 && (data[0] == ' ' || data[0] == '\t')) {
		++data;
		--n_data;
	}
	
	/* If there's data left, its the comment */
	if (comment)
		*comment = n_data ? g_strndup ((gchar*)data, n_data) : NULL;

	return GKR_PKIX_SUCCESS;
}

guchar*
gkr_ssh_storage_write_public_key (gcry_sexp_t sexp, const gchar *comment,
                                  gsize *n_data)
{
	GString *result;
	EggBuffer buffer;
	const gchar *type;
	gchar *encoded;
	gboolean is_priv;
	int algo;
	
	g_return_val_if_fail (n_data, NULL);
	g_return_val_if_fail (sexp, NULL);
	
	result = g_string_sized_new (4096);
	
	if (!gkr_crypto_skey_parse (sexp, &algo, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	g_return_val_if_fail (is_priv == FALSE, NULL);
	g_return_val_if_fail (algo != 0, NULL);
	
	type = gkr_ssh_proto_algo_to_keytype (algo);
	g_return_val_if_fail (type, NULL);
	
	g_string_append (result, type);
	g_string_append_c (result, ' ');
	
	egg_buffer_init_full (&buffer, 4096, (EggBufferAllocator)g_realloc);
	gkr_ssh_proto_write_public (&buffer, algo, sexp);
	
	encoded = g_base64_encode (buffer.buf, buffer.len);
	egg_buffer_uninit (&buffer);
	
	g_return_val_if_fail (encoded, NULL);
	g_string_append (result, encoded);
	
	if (comment) {
		g_string_append_c (result, ' ');
		g_string_append (result, comment);
	}
	
	g_string_append_c (result, '\n');
	
	*n_data = result->len;
	return (guchar*)g_string_free (result, FALSE);
}
