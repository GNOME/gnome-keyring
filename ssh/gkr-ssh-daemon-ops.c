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

#include "pk/gkr-pk-object-manager.h"
#include "pk/gkr-pk-privkey.h"
#include "pk/gkr-pk-pubkey.h"

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

static gboolean had_session_keys = FALSE;
static GList *ssh_session_keys = NULL;

static void
cleanup_session_keys (gpointer unused)
{
	GList *l;
	for (l = ssh_session_keys; l; l = g_list_next (l))
		g_object_unref (l->data);
	g_list_free (ssh_session_keys);
	ssh_session_keys = NULL;	
}

static GkrPkPrivkey*
find_private_key (gcry_sexp_t s_key, gboolean manager)
{
	GkrPkPrivkey *key = NULL;
	gkrunique keyid;
	const guchar *data;
	gsize n_data;
	GList *l, *objects;
	
	keyid = gkr_crypto_skey_make_id (s_key);
	g_return_val_if_fail (keyid != NULL, NULL);
	
	for (l = ssh_session_keys; l; l = g_list_next (l)) {
		key = GKR_PK_PRIVKEY (l->data);
		if (gkr_unique_equals (keyid, gkr_pk_privkey_get_keyid (key)))
			break;
	}
	
	if (l == NULL)
		key = NULL;
	
	if (!key && manager) {
		data = gkr_unique_get_raw (keyid, &n_data);
		g_assert (data && n_data);
		
		objects = gkr_pk_object_manager_findv (gkr_pk_object_manager_for_token (), GKR_TYPE_PK_PRIVKEY, 
		                                       CKA_ID, data, n_data, NULL);
		if (objects) {
			key = GKR_PK_PRIVKEY (objects->data);
			g_list_free (objects);
		}
	}

	gkr_unique_free (keyid);
	
	return key;
}

static void
remove_session_key (GkrPkPrivkey *key)
{
	GList *link = g_list_find (ssh_session_keys, key);
	if (!link)
		return;
	ssh_session_keys = g_list_remove_link (ssh_session_keys, link);
	g_object_unref (key);
	g_list_free_1 (link);
}

static void
add_session_key (gcry_sexp_t s_key, const gchar *comment)
{
	GkrPkPrivkey *key, *prev;
	
	key = GKR_PK_PRIVKEY (gkr_pk_privkey_new (NULL, 0, s_key));
	g_return_if_fail (key != NULL);
	
	if (comment)
		g_object_set (key, "label", comment, NULL);
	
	prev = find_private_key (s_key, FALSE);
	if (prev)
		remove_session_key (prev);
		
	ssh_session_keys = g_list_prepend (ssh_session_keys, key);
	
	if (!had_session_keys) {
		had_session_keys = TRUE;
		gkr_cleanup_register (cleanup_session_keys, NULL);
	}
}

static void
get_public_keys (GList *privates, GList** publics) 
{
	GkrPkPrivkey *key;
	GkrPkPubkey *pub;
	
	for (; privates; privates = g_list_next (privates)) {
		
		key = GKR_PK_PRIVKEY (privates->data);
		g_return_if_fail (GKR_IS_PK_PRIVKEY (key));
		
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
	
	if (!gkr_buffer_get_string (req, 5, &offset, &stype, g_realloc))
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
	if (!gkr_buffer_get_string (req, offset, &offset, &comment, g_realloc)) {
		gcry_sexp_release (key);
		return FALSE;
	}
		
	add_session_key (key, comment);
	g_free (comment);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_SUCCESS);
	return TRUE;	
}

static gboolean
op_request_identities (GkrBuffer *req, GkrBuffer *resp)
{
	gboolean ret = TRUE;
	GList *objects, *pubkeys, *l;
	GkrPkPubkey *pub;
	const gchar *label;
	
	/* Only find the keys that have usage = ssh */
	objects = gkr_pk_object_manager_findv (gkr_pk_object_manager_for_token (), GKR_TYPE_PK_PRIVKEY, 
	                                       CKA_GNOME_PURPOSE_SSH_AUTH, CK_TRUE, 0, NULL);
	
	pubkeys = NULL;
	get_public_keys (ssh_session_keys, &pubkeys);
	get_public_keys (objects, &pubkeys);
	
	g_list_free (objects);
	
	gkr_buffer_add_byte (resp, GKR_SSH_RES_IDENTITIES_ANSWER);
	gkr_buffer_add_uint32 (resp, g_list_length (pubkeys));
	      
	for (l = pubkeys; l; l = g_list_next (l)) {
		
		pub = GKR_PK_PUBKEY (l->data);
		g_return_val_if_fail (GKR_IS_PK_PUBKEY (pub), FALSE);
		
		if (!gkr_ssh_proto_write_public (resp, gkr_pk_pubkey_get_algorithm (pub),
		                                 gkr_pk_pubkey_get_key (pub)))
			return FALSE;
		
		/* And now a per key comment */
		label = gkr_pk_object_get_label (GKR_PK_OBJECT (pub));
		gkr_buffer_add_string (resp, label ? label : "");
	}
	
	g_list_free (pubkeys);
	
	return ret;
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
	guint blobpos;
	guchar *hash;
	int algo;
	int halgo, n_algo;
	
	offset = 5;
	if (!gkr_ssh_proto_read_public (req, &offset, &s_key, &algo))
		return FALSE;
		
	if (!gkr_buffer_get_byte_array (req, offset, &offset, &data, &n_data) ||
	    !gkr_buffer_get_uint32 (req, offset, &offset, &flags)) {
	    	gcry_sexp_release (s_key);
	    	return FALSE;
	}

	/* Lookup the key */
	key = find_private_key (s_key, TRUE);
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
		g_warning ("couldn't get private signing key");
		return FALSE;
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
op_remove_identity (GkrBuffer *req, GkrBuffer *resp)
{
	GkrPkPrivkey *key;
	gcry_sexp_t skey;
	gsize offset;
	
	offset = 5;
	if (!gkr_ssh_proto_read_public (req, &offset, &skey, NULL))
		return FALSE;
	
	key = find_private_key (skey, FALSE);
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
	
	while (ssh_session_keys != NULL) {
		key = GKR_PK_PRIVKEY (ssh_session_keys->data);
		g_assert (GKR_IS_PK_PRIVKEY (key));	
		remove_session_key (key);
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
     op_not_implemented_failure,                 /* GKR_SSH_OP_REQUEST_RSA_IDENTITIES */
     op_invalid,                                 /* 2 */
     op_not_implemented_failure,                 /* GKR_SSH_OP_RSA_CHALLENGE */
     op_invalid,                                 /* 4 */
     op_invalid,                                 /* 5 */
     op_invalid,                                 /* 6 */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_RSA_IDENTITY */
     op_not_implemented_failure,                 /* GKR_SSH_OP_REMOVE_RSA_IDENTITY */
     op_not_implemented_success,                 /* GKR_SSH_OP_REMOVE_ALL_RSA_IDENTITIES */
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
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_RSA_ID_CONSTRAINED */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_ID_CONSTRAINED */
     op_not_implemented_failure,                 /* GKR_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED */
};
