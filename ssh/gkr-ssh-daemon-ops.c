/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-daemon-ops.h - SSH agent operations

   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-ssh-private.h"

#include "common/gkr-buffer.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-crypto.h"

#include "pk/gkr-pk-privkey.h"
#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-session.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include <gcrypt.h>

#include <glib.h>

#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------------
 * SESSION KEYS
 */

static GkrPkSession *ssh_session = NULL;

static void
mark_v1_key (GkrPkPrivkey *key)
{
	/* Track the version of the SSH protocol that this came in on */
	g_object_set_data (G_OBJECT (key), "ssh-protocol-version", GUINT_TO_POINTER (1));
}

static gboolean
check_v1_key (GkrPkPrivkey *key)
{
	return g_object_get_data (G_OBJECT (key), "ssh-protocol-version") == GUINT_TO_POINTER (1);
}

static void
cleanup_session (gpointer unused)
{
	g_return_if_fail (ssh_session);
	g_object_unref (ssh_session);
	ssh_session = NULL;
}

static GkrPkPrivkey*
find_private_key_in_manager (GkrPkManager *manager, const gkrid keyid, guint version)
{
	GkrPkPrivkey *key = NULL;
	GList *l, *objects;
	const guchar *data;
	gsize n_data;

	data = gkr_id_get_raw (keyid, &n_data);
	g_assert (data && n_data);

	objects = gkr_pk_manager_findv (manager, GKR_TYPE_PK_PRIVKEY, 
	                                CKA_ID, data, n_data, NULL);
	
	for (l = objects; l; l = g_list_next (l)) {
		key = GKR_PK_PRIVKEY (objects->data);
		if ((version == 1) != check_v1_key (key))
			continue;
		break;
	}

	g_list_free (objects);
	
	if (l == NULL)
		key = NULL;

	return key;
}

static GkrPkPrivkey*
find_private_key (gcry_sexp_t skey, gboolean global, guint version)
{
	GkrPkPrivkey *key = NULL;
	gkrid keyid;
	
	keyid = gkr_crypto_skey_make_id (skey);
	g_return_val_if_fail (keyid != NULL, NULL);

	/* Search through the session keys */
	if (ssh_session)
		key = find_private_key_in_manager (ssh_session->manager, keyid, version);
		
	/* Search through the global keys */
	if (!key && global) 
		key = find_private_key_in_manager (gkr_pk_manager_for_token (), keyid, version);
	
	gkr_id_free (keyid);
	return key;
}

static void
remove_session_key (GkrPkPrivkey *key)
{
	if (ssh_session) {
		/* This removes ownership of the key */
		if (!gkr_pk_storage_remove (ssh_session->storage, GKR_PK_OBJECT (key), NULL))
			g_return_if_reached ();
	}
}

static void
add_session_key (gcry_sexp_t skey, const gchar *comment, guint version)
{
	GkrPkPrivkey *key, *prev;

	if (!ssh_session) {
		ssh_session = gkr_pk_session_new ();
		gkr_cleanup_register (cleanup_session, NULL);
	}

	prev = find_private_key (skey, FALSE, version);
	if (prev)
		remove_session_key (prev);
	
	key = GKR_PK_PRIVKEY (gkr_pk_privkey_new (ssh_session->manager, 0, skey));
	g_return_if_fail (key != NULL);
	
	if (comment)
		g_object_set (key, "label", comment, NULL);
	
	if (version == 1)
		mark_v1_key (key);
	
	/* This owns the actual key */
	if (!gkr_pk_storage_store (ssh_session->storage, GKR_PK_OBJECT (key), NULL))
		g_return_if_reached ();
	
	g_object_unref (key);
}

static void
get_public_keys (GList *objects, GList** publics, guint version) 
{
	GkrPkPrivkey *key;
	GkrPkPubkey *pub;
	
	for (; objects; objects = g_list_next (objects)) {
		
		if (!GKR_IS_PK_PRIVKEY (objects->data))
			continue;
		key = GKR_PK_PRIVKEY (objects->data);
		
		/* When getting version one keys skip over any that aren't marked that way. */
		if ((version == 1) != check_v1_key (key))
			continue;
		
		pub = GKR_PK_PUBKEY (gkr_pk_privkey_get_public (key));
		if (!pub) {
			g_message ("couldn't find or load public key for private key");
			continue;
		}

		*publics = g_list_prepend (*publics, pub);
	}
}

/* -----------------------------------------------------------------------------
 * OPERATIONS
 */

static gboolean
op_add_identity (GkrBuffer *req, GkrBuffer *resp)
{
	gchar *stype = NULL;
	gchar *comment = NULL;
	gcry_sexp_t key;
	gboolean ret;
	int algo;
	gsize offset;
	
	if (!gkr_buffer_get_string (req, 5, &offset, &stype, (GkrBufferAllocator)g_realloc))
		return FALSE;
		
	algo = gkr_ssh_proto_keytype_to_algo (stype);
	g_free (stype);
	
	if (!algo) {
		g_warning ("unsupported algorithm from SSH: %s", stype);
		return FALSE;
	}
	
	switch (algo) {
	case GCRY_PK_RSA:
		ret = gkr_ssh_proto_read_private_rsa (req, &offset, &key);
		break;
	case GCRY_PK_DSA:
		ret = gkr_ssh_proto_read_private_dsa (req, &offset, &key);
		break;
	default:
		g_assert_not_reached ();
		return FALSE;
	}
	
	if (!ret || !key) {
		g_warning ("couldn't read incoming SSH private key");
		return FALSE;
	}
		
		
	/* TODO: Blinding? See ssh-agent.c */

	/* Get the comment */
	if (!gkr_buffer_get_string (req, offset, &offset, &comment, (GkrBufferAllocator)g_realloc)) {
		gcry_sexp_release (key);
		return FALSE;
	}
		
	add_session_key (key, comment, 2);
	g_free (comment);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;	
}

static gboolean
op_v1_add_identity (GkrBuffer *req, GkrBuffer *resp)
{
	gcry_sexp_t key;
	gboolean ret;
	gsize offset = 5;	
	guint32 unused;
	
	if (!gkr_buffer_get_uint32 (req, offset, &offset, &unused))
		return FALSE;
	
	ret = gkr_ssh_proto_read_private_v1 (req, &offset, &key);
	if (!ret || !key) {
		g_warning ("couldn't read incoming SSH private key");
		return FALSE;		
	}
	
	add_session_key (key, "SSH1 RSA key", 1);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;	
}

static gboolean
op_request_identities (GkrBuffer *req, GkrBuffer *resp)
{
	GList *objects, *pubkeys, *l;
	GkrPkPubkey *pub;
	gsize blobpos;
	
	/* Only find the keys that have usage = ssh */
	objects = gkr_pk_manager_findv (gkr_pk_manager_for_token (), GKR_TYPE_PK_PRIVKEY, 
	                                CKA_GNOME_PURPOSE_SSH_AUTH, CK_TRUE, 0, NULL);
	
	pubkeys = NULL;
	if (ssh_session)
		get_public_keys (ssh_session->manager->objects, &pubkeys, 2);
	get_public_keys (objects, &pubkeys, 2);
	
	g_list_free (objects);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_IDENTITIES_ANSWER);
	gkr_buffer_add_uint32 (resp, g_list_length (pubkeys));
	      
	for (l = pubkeys; l; l = g_list_next (l)) {
		
		pub = GKR_PK_PUBKEY (l->data);
		g_return_val_if_fail (GKR_IS_PK_PUBKEY (pub), FALSE);
		
		/* Add a space for the key blob length */		
		blobpos = resp->len;
		gkr_buffer_add_uint32 (resp, 0);
		
		if (!gkr_ssh_proto_write_public (resp, gkr_pk_pubkey_get_algorithm (pub),
		                                 gkr_pk_pubkey_get_key (pub)))
			return FALSE;
		
		/* Write back the blob length */
		gkr_buffer_set_uint32 (resp, blobpos, (resp->len - blobpos) - 4);
		
		/* And now a per key comment */
		gkr_buffer_add_string (resp, gkr_pk_object_get_label (GKR_PK_OBJECT (pub)));
	}
	
	g_list_free (pubkeys);
	
	return TRUE;
}

static gboolean
op_v1_request_identities (GkrBuffer *req, GkrBuffer *resp)
{
	GList *l, *pubkeys = NULL;
	GkrPkPubkey *pub;
	const gchar *label;
	
	if (ssh_session)
		get_public_keys (ssh_session->manager->objects, &pubkeys, 1);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_RSA_IDENTITIES_ANSWER);
	gkr_buffer_add_uint32 (resp, g_list_length (pubkeys));
	      
	for (l = pubkeys; l; l = g_list_next (l)) {
		
		pub = GKR_PK_PUBKEY (l->data);
		g_return_val_if_fail (GKR_IS_PK_PUBKEY (pub), FALSE);
		
		if (!gkr_ssh_proto_write_public_v1 (resp, gkr_pk_pubkey_get_key (pub)))
			return FALSE;
		
		/* And now a per key comment */
		label = gkr_pk_object_get_label (GKR_PK_OBJECT (pub));
		gkr_buffer_add_string (resp, label ? label : "");
	}
	
	g_list_free (pubkeys);
	return TRUE;
}

static gboolean
make_pkcs1_sign_sexp (int algo, const guchar *hash, gcry_sexp_t *sexp)
{
	gchar *salgo;
	const char *s;
	int i, nalgo;
	gcry_error_t gcry;
	
	nalgo = gcry_md_get_algo_dlen (algo);
	g_return_val_if_fail (nalgo > 0, FALSE);
	
	s = gcry_md_algo_name (algo);
	g_return_val_if_fail (s, FALSE);
	
	salgo = g_alloca (strlen (s) + 1);
	for (i = 0; i < strlen (s); i++)
		salgo[i] = tolower (s[i]);
	salgo[i] = '\0';
	
	gcry = gcry_sexp_build (sexp, NULL, "(data (flags pkcs1) (hash %s %b))",
	                        salgo, nalgo, hash);
	g_return_val_if_fail (gcry == 0, FALSE);
	
	return TRUE;
}

static gboolean
make_raw_sign_exp (int algo, const guchar *hash, gcry_sexp_t *sexp)
{
	int nalgo;
	gcry_mpi_t mpi;
	gcry_error_t gcry;
	
	nalgo = gcry_md_get_algo_dlen (algo);
	g_return_val_if_fail (nalgo > 0, FALSE);
	
	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, hash, nalgo, NULL);
	g_return_val_if_fail (gcry == 0, FALSE);

	gcry = gcry_sexp_build (sexp, NULL, "(data (flags raw) (value %m))", mpi);
	gcry_mpi_release (mpi);

	g_return_val_if_fail (gcry == 0, FALSE);
	return TRUE;
}

static gboolean 
op_sign_request (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	const guchar *data;
	const gchar *salgo;
	gcry_sexp_t s_key, sdata, ssig;
	gsize n_data;
	guint32 flags;
	gsize offset;
	gcry_error_t gcry;
	gboolean ret;
	guint blobpos, sz;
	guchar *hash;
	int algo;
	int halgo, n_algo;
	
	offset = 5;
	
	/* The key packet size */
	if (!gkr_buffer_get_uint32 (req, offset, &offset, &sz))
		return FALSE;

	/* The key itself */
	if (!gkr_ssh_proto_read_public (req, &offset, &s_key, &algo))
		return FALSE;
		
	if (!gkr_buffer_get_byte_array (req, offset, &offset, &data, &n_data) ||
	    !gkr_buffer_get_uint32 (req, offset, &offset, &flags)) {
	    	gcry_sexp_release (s_key);
	    	return FALSE;
	}

	/* Lookup the key */
	key = find_private_key (s_key, TRUE, 2);
	gcry_sexp_release (s_key);
	
	if (!key) {
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		return TRUE;
	}
	
	/* Usually we hash the data with SHA1 */
	if (flags & GKR_SSH_FLAG_OLD_SIGNATURE)
		halgo = GCRY_MD_MD5;
	else
		halgo = GCRY_MD_SHA1;
	
	n_algo = gcry_md_get_algo_dlen (halgo);
	g_return_val_if_fail (n_algo > 0, FALSE);
	
	hash = g_alloca (n_algo);
	g_assert (hash);
	
	gcry_md_hash_buffer (halgo, hash, data, n_data);

	/* Make our data sexpression */
	if (algo == GCRY_PK_RSA)
		ret = make_pkcs1_sign_sexp (halgo, hash, &sdata);
	else
		ret = make_raw_sign_exp (halgo, hash, &sdata);
	if (!ret)
		return FALSE;
		
	s_key = gkr_pk_privkey_get_key (key);
	if (!s_key) {
		g_message ("couldn't get private signing key");
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		return TRUE;
	}
		
	/* Do the magic */
	gcry = gcry_pk_sign (&ssig, sdata, s_key);
	gcry_sexp_release (sdata);

	if (gcry) {
		g_warning ("signing of the data failed: %s", gcry_strerror (gcry));
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		return TRUE;
	}

	gkr_buffer_add_byte (resp, GKR_SSH_RES_SIGN_RESPONSE);
	
	/* Add a space for the sig blob length */		
	blobpos = resp->len;
	gkr_buffer_add_uint32 (resp, 0);
	
	salgo = gkr_ssh_proto_algo_to_keytype (algo);
	g_assert (salgo);
	gkr_buffer_add_string (resp, salgo);

	switch (algo) {
	case GCRY_PK_RSA:
		ret = gkr_ssh_proto_write_signature_rsa (resp, ssig);
		break;

	case GCRY_PK_DSA:
		ret = gkr_ssh_proto_write_signature_dsa (resp, ssig);
		break;

	default:
		g_assert_not_reached ();
	}
			
	gcry_sexp_release (ssig);
	g_return_val_if_fail (ret, FALSE);
	
	/* Write back the blob length */
	gkr_buffer_set_uint32 (resp, blobpos, (resp->len - blobpos) - 4);
	
	return TRUE; 
}

static gboolean
make_decrypt_sexp (gcry_mpi_t mpi, gcry_sexp_t *sexp)
{
	gcry_error_t gcry;
	
	gcry = gcry_sexp_build (sexp, NULL, "(enc-val (flags) (rsa (a %m)))", mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	
	return TRUE;
}

static gboolean 
op_v1_challenge (GkrBuffer *req, GkrBuffer *resp)
{
	guchar session_id[16];
	gcry_error_t gcry;
	gcry_md_hd_t hd = NULL;
	gcry_sexp_t skey;
	gcry_sexp_t splain = NULL;
	gcry_sexp_t sdata = NULL;
	GkrPkPrivkey *key;
	const guchar *hash;
	gcry_mpi_t challenge = NULL;
	guchar *raw = NULL;
	gsize offset, n_raw;
	guint32 resp_type;
	gboolean ret;
	guint i, bits;
	guchar b;
	
	ret = FALSE;
	offset = 5;
	
	if (!gkr_ssh_proto_read_public_v1 (req, &offset, &skey))
		return FALSE;
	
	/* Lookup the key */
	key = find_private_key (skey, TRUE, 1);
	gcry_sexp_release (skey);
	
	/* Read the entire challenge */
	if (!gkr_ssh_proto_read_mpi_v1 (req, &offset, &challenge))
		goto cleanup;
	
	/* Only protocol 1.1 is supported */
	if (req->len <= offset) {
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		ret = TRUE;
		goto cleanup;
	}
		
	/* Read out the session id, raw, unbounded */
	for (i = 0; i < 16; ++i) {
		if (!gkr_buffer_get_byte (req, offset, &offset, &b))
			goto cleanup;
		session_id[i] = b;
	}
		
	/* And the response type */
	if (!gkr_buffer_get_uint32 (req, offset, &offset, &resp_type))
		goto cleanup;
	
	/* Not supported request type */
	if (resp_type != 1) {
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		ret = TRUE;
		goto cleanup;
	}	

	/* Didn't find a key earlier */
	if (!key) {
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		ret = TRUE;
		goto cleanup;
	}

	skey = gkr_pk_privkey_get_key (key);
	if (!skey) {
		g_message ("couldn't get private decryption key");
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		ret = TRUE;
		goto cleanup;
	}
	
	/* Make our data sexpression */
	if (!make_decrypt_sexp (challenge, &sdata))
		return FALSE;

	/* Do the magic */
	gcry = gcry_pk_decrypt (&splain, sdata, skey);

	if (gcry) {
		g_warning ("decryption of the data failed: %s", gcry_strerror (gcry));
		gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
		ret = TRUE;
		goto cleanup;
	}
	
	/* Number of bits in the key */
	bits = gcry_pk_get_nbits (skey);
	g_return_val_if_fail (bits, FALSE);

	/* Get out the value */
	raw = gkr_crypto_sexp_extract_mpi_padded (splain, bits, &n_raw, 
	                                          gkr_crypto_rsa_unpad_pkcs1, "value", NULL);
	g_return_val_if_fail (raw, FALSE);

	/* Now build up a hash of this and the session_id */
	gcry = gcry_md_open (&hd, GCRY_MD_MD5, 0);
	g_return_val_if_fail (gcry == 0, FALSE);
	gcry_md_write (hd, raw, n_raw);
	gcry_md_write (hd, session_id, sizeof (session_id));
	hash = gcry_md_read (hd, 0);
	g_return_val_if_fail (hash, FALSE);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_RSA_RESPONSE);
	gkr_buffer_append (resp, hash, 16);
	
	ret = TRUE;
	
cleanup:
	if (hd)
		gcry_md_close (hd);
	if (challenge)
		gcry_mpi_release (challenge);
	if (sdata)
		gcry_sexp_release (sdata);
	if (splain)
		gcry_sexp_release (splain);
	if (raw)
		g_free (raw);
	
	return ret;
}

static gboolean 
op_remove_identity (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	GkrPkObject *obj;
	gcry_sexp_t skey;
	gsize offset;
	guint sz;
	
	offset = 5;
	
	/* The key packet size */
	if (!gkr_buffer_get_uint32 (req, offset, &offset, &sz))
		return FALSE;

	/* The public key itself */
	if (!gkr_ssh_proto_read_public (req, &offset, &skey, NULL))
		return FALSE;
	
	key = find_private_key (skey, TRUE, 2);
	gcry_sexp_release (skey);

	if (key) {
		obj = GKR_PK_OBJECT (key);
		
		/* 
		 * When the key is just a session key, then remove it
		 * completely. 
		 */ 
		if (ssh_session && obj->manager == ssh_session->manager)
			remove_session_key (key);
			
		/* 
		 * Otherwise lock it so the user gets prompted for 
		 * any passwords again. 
		 */
		else
			gkr_pk_object_lock (obj);
	}
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);

	return TRUE;	
}

static gboolean 
op_v1_remove_identity (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	gcry_sexp_t skey;
	gsize offset;
	
	offset = 5;
	if (!gkr_ssh_proto_read_public_v1 (req, &offset, &skey))
		return FALSE;
	
	key = find_private_key (skey, FALSE, 1);
	gcry_sexp_release (skey);

	if (key)
		remove_session_key (key);
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);

	return TRUE;	
}

static gboolean 
op_remove_all_identities (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	GList *objects, *l, *removes = NULL;
	
	/* Remove all session keys */
	if (ssh_session) {
		for (l = ssh_session->manager->objects; l; l = g_list_next (l)) {
			if (!GKR_IS_PK_PRIVKEY (l->data))
				continue;
			key = GKR_PK_PRIVKEY (l->data);
			if (!check_v1_key (key))
				removes = g_list_prepend (removes, key);
		}

		for (l = removes; l; l = g_list_next (l))
			remove_session_key (GKR_PK_PRIVKEY (l->data));
		g_list_free (removes);
	}
	
	/* And now we lock all private keys with usage = SSH */
	objects = gkr_pk_manager_findv (gkr_pk_manager_for_token (), GKR_TYPE_PK_PRIVKEY, 
	                                CKA_GNOME_PURPOSE_SSH_AUTH, CK_TRUE, 0, NULL);
	
	for (l = objects; l; l = g_list_next (l)) { 
		g_return_val_if_fail (GKR_IS_PK_OBJECT (l->data), FALSE);
		gkr_pk_object_lock (GKR_PK_OBJECT (l->data));
	}
	
	g_list_free (objects);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;
}

static gboolean 
op_v1_remove_all_identities (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	GList *l, *removes = NULL;
	
	if (ssh_session) {
		for (l = ssh_session->manager->objects; l; l = g_list_next (l)) {
			if (!GKR_IS_PK_PRIVKEY (l->data))
				continue;
			key = GKR_PK_PRIVKEY (l->data);
			if (check_v1_key (key))
				removes = g_list_prepend (removes, key);
		}
		
		for (l = removes; l; l = g_list_next (l))
			remove_session_key (GKR_PK_PRIVKEY (l->data));
		g_list_free (removes);
	}
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;
}

static gboolean 
op_not_implemented_success (GkrBuffer *req, GkrBuffer *resp)
{
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;
}
	
static gboolean
op_not_implemented_failure (GkrBuffer *req, GkrBuffer *resp)
{
	gkr_buffer_add_byte (resp, GKR_SSH_RES_FAILURE);
	return TRUE;	
	
}

static gboolean
op_invalid (GkrBuffer *req, GkrBuffer *resp)
{
	/* Invalid request, disconnect immediately */
	return FALSE;
}

const GkrSshOperation gkr_ssh_operations[GKR_SSH_OP_MAX] = {
     op_invalid,                                 /* 0 */
     op_v1_request_identities,                   /* GKR_SSH_OP_REQUEST_RSA_IDENTITIES */
     op_invalid,                                 /* 2 */
     op_v1_challenge,                            /* GKR_SSH_OP_RSA_CHALLENGE */
     op_invalid,                                 /* 4 */
     op_invalid,                                 /* 5 */
     op_invalid,                                 /* 6 */
     op_v1_add_identity,                         /* GKR_SSH_OP_ADD_RSA_IDENTITY */
     op_v1_remove_identity,                      /* GKR_SSH_OP_REMOVE_RSA_IDENTITY */
     op_v1_remove_all_identities,                /* GKR_SSH_OP_REMOVE_ALL_RSA_IDENTITIES */
     op_invalid,                                 /* 10 */     
     op_request_identities,                      /* GKR_SSH_OP_REQUEST_IDENTITIES */
     op_invalid,                                 /* 12 */
     op_sign_request,                            /* GKR_SSH_OP_SIGN_REQUEST */
     op_invalid,                                 /* 14 */     
     op_invalid,                                 /* 15 */     
     op_invalid,                                 /* 16 */     
     op_add_identity,                            /* GKR_SSH_OP_ADD_IDENTITY */
     op_remove_identity,                         /* GKR_SSH_OP_REMOVE_IDENTITY */
     op_remove_all_identities,                   /* GKR_SSH_OP_REMOVE_ALL_IDENTITIES */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY */
     op_not_implemented_failure,                 /* GKR_SSH_OP_REMOVE_SMARTCARD_KEY */
     op_not_implemented_success,                 /* GKR_SSH_OP_LOCK */
     op_not_implemented_success,                 /* GKR_SSH_OP_UNLOCK */
     op_v1_add_identity,                         /* GKR_SSH_OP_ADD_RSA_ID_CONSTRAINED */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_ID_CONSTRAINED */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED */
};
