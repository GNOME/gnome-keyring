/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-openssl.c - OpenSSL compatibility functionality

   Copyright (C) 2007 Stefan Walter

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

#include "gkr-pkix-openssl.h"

#include "common/gkr-crypto.h"
#include "common/gkr-secure-memory.h"

#include <gcrypt.h>
#include <libtasn1.h>

#include <glib.h>

const static struct {
	const gchar *desc;
	int algo;
	int mode;
} openssl_algos[] = {
	{ "DES-ECB", GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB },
	{ "DES-CFB64", GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB },
	{ "DES-CFB", GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CFB },
	/* DES-CFB1 */
	/* DES-CFB8 */
	/* DESX-CBC */
	/* DES-EDE */
	/* DES-EDE-CBC */
	/* DES-EDE-ECB */
	/* DES-EDE-CFB64 DES-EDE-CFB */
	/* DES-EDE-CFB1 */
	/* DES-EDE-CFB8 */
	/* DES-EDE-OFB */
	/* DES-EDE3 */ 
	{ "DES-EDE3-ECB", GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB }, 
	{ "DES-EDE3-CFB64", GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CFB },
	{ "DES-EDE3-CFB", GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CFB },
	/* DES-EDE3-CFB1 */
	/* DES-EDE3-CFB8 */
	{ "DES-OFB", GCRY_CIPHER_DES, GCRY_CIPHER_MODE_OFB },
	{ "DES-EDE3-OFB", GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OFB },
	{ "DES-CBC", GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC },
	{ "DES-EDE3-CBC", GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC },
	/* RC2-ECB */
	/* RC2-CBC */
	/* RC2-40-CBC */
	/* RC2-64-CBC */
	/* RC2-CFB64    RC2-CFB */
	/* RC2-OFB */
	{ "RC4", GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM },
	{ "RC4-40", GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM },
	{ "IDEA-ECB", GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_ECB },
	{ "IDEA-CFB64", GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_CFB },
	{ "IDEA-OFB", GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_OFB },
	{ "IDEA-CBC", GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_CBC },
	{ "BF-ECB", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB },
	{ "BF-CBC", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CBC },
	{ "BF-CFB64", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB },
	{ "BF-CFB", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_CFB },
	{ "BF-OFB", GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_OFB },
	{ "CAST5-ECB", GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB },
	{ "CAST5-CBC", GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CBC },
	{ "CAST5-CFB64", GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CFB },
	{ "CAST5-CFB", GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CFB },
	{ "CAST5-OFB", GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_OFB },
	/* RC5-32-12-16-CBC */ 
	/* RC5-32-12-16-ECB */
	/* RC5-32-12-16-CFB64  RC5-32-12-16-CFB */
	/* RC5-32-12-16-OFB */
	{ "AES-128-ECB", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB },
	{ "AES-128-CBC", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC },
	/* AES-128-CFB1 */
	/* AES-128-CFB8	*/
	{ "AES-128-CFB128", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB },
	{ "AES-128-CFB", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CFB },
	{ "AES-128-OFB", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_OFB },
	{ "AES-128-CTR", GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR },
	{ "AES-192-ECB", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB },
	{ "AES-192-CBC", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC },
	/* AES-192-CFB1 */
	/* AES-192-CFB8 */
	{ "AES-192-CFB128", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB },
	{ "AES-192-CFB", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB },
	{ "AES-192-OFB", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB },
	{ "AES-192-CTR", GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR },
	{ "AES-256-ECB", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB },
	{ "AES-256-CBC", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC },
	/* AES-256-CFB1 */
	/* AES-256-CFB8 */
	{ "AES-256-CFB128", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB },
	{ "AES-256-CFB", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB },
	{ "AES-256-OFB", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB },
	{ "AES-256-CTR", GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR },
	/* CAMELLIA-128-ECB */
	/* CAMELLIA-128-CBC */
	/* CAMELLIA-128-CFB1 */
	/* CAMELLIA-128-CFB8 */
	/* CAMELLIA-128-CFB128   CAMELLIA-128-CFB */
	/* CAMELLIA-128-OFB */
	/* CAMELLIA-192-ECB */
	/* CAMELLIA-192-CBC */
	/* CAMELLIA-192-CFB1 */
	/* CAMELLIA-192-CFB8 */
	/* CAMELLIA-192-CFB128   CAMELLIA-192-CFB */
	/* CAMELLIA-192_OFB */
	/* CAMELLIA-256-ECB */
	/* CAMELLIA-256-CBC */
	/* CAMELLIA-256-CFB1 */
	/* CAMELLIA-256-CFB8 */
	/* CAMELLIA-256-CFB128   CAMELLIA-256-CFB */
	/* CAMELLIA-256-OFB */
};

#define N_OPENSSL_ALGOS   (sizeof (openssl_algos) / sizeof (openssl_algos[0]))
static GQuark openssl_quarks[N_OPENSSL_ALGOS] = { 0, };
static gboolean openssl_quarks_inited = FALSE;

int
gkr_pkix_openssl_parse_algo (const char *name, int *mode)
{
	GQuark q;
	int i;
	
	if (!openssl_quarks_inited) {
		for (i = 0; i < N_OPENSSL_ALGOS; ++i)
			openssl_quarks[i] = g_quark_from_static_string (openssl_algos[i].desc);
		openssl_quarks_inited = TRUE;
	}
	
	q = g_quark_try_string (name);
	if (q) {
		for (i = 0; i < N_OPENSSL_ALGOS; ++i) {
			if (q == openssl_quarks[i]) {
				*mode = openssl_algos[i].mode;
				return openssl_algos[i].algo;
			}
		}
	}
	
	return 0;
}

static gboolean
parse_dekinfo (const gchar *dek, int *algo, int *mode, guchar **iv)
{
	gboolean success = FALSE;
	gchar **parts = NULL;
	gcry_error_t gcry;
	gsize ivlen, len;
	
	parts = g_strsplit (dek, ",", 2);
	if (!parts || !parts[0] || !parts[1]) 
		goto done;
		
	/* Parse the algorithm name */
	*algo = gkr_pkix_openssl_parse_algo (parts[0], mode);
	if (!*algo)
		goto done;
	
	/* Make sure this is usable */
	gcry = gcry_cipher_test_algo (*algo);
	if (gcry)
		goto done;

	/* Parse the IV */
	ivlen = len = gcry_cipher_get_algo_blklen (*algo);
	*iv = g_malloc (ivlen);
	
	if (!gkr_crypto_hex_decode (parts[1], strlen(parts[1]), *iv, &len)) {
		g_free (*iv);
		goto done;
	}
	
	if (ivlen != len) {
		g_free (*iv);
		goto done;
	}
		
	success = TRUE;

done:
	g_strfreev (parts);
	return success;
}

GkrPkixResult
gkr_pkix_openssl_decrypt_block (const gchar *dekinfo, const gchar *password, 
                                const guchar *data, gsize n_data, 
                                guchar **decrypted, gsize *n_decrypted)
{
	gcry_cipher_hd_t ch;
	guchar *key = NULL;
	guchar *iv = NULL;
	int gcry, ivlen;
	int algo = 0;
	int mode = 0;
	
	if (!parse_dekinfo (dekinfo, &algo, &mode, &iv))
		return GKR_PKIX_UNRECOGNIZED;
		
	ivlen = gcry_cipher_get_algo_blklen (algo);

	/* We assume the iv is at least as long as at 8 byte salt */
	g_return_val_if_fail (ivlen >= 8, FALSE);
	
	/* IV is already set from the DEK info */
	if (!gkr_crypto_generate_symkey_simple (algo, GCRY_MD_MD5, password, 
	                                        iv, 8, 1, &key, NULL)) {
		g_free (iv);
		return GKR_PKIX_FAILURE;
	}
	
	/* TODO: Use secure memory */
	gcry = gcry_cipher_open (&ch, algo, mode, 0);
	g_return_val_if_fail (!gcry, GKR_PKIX_FAILURE);
		
	gcry = gcry_cipher_setkey (ch, key, gcry_cipher_get_algo_keylen (algo));
	g_return_val_if_fail (!gcry, GKR_PKIX_UNRECOGNIZED);
	gkr_secure_free (key);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (ch, iv, ivlen);
	g_return_val_if_fail (!gcry, GKR_PKIX_UNRECOGNIZED);
	g_free (iv);
	
	/* Allocate output area */
	*n_decrypted = n_data;
	*decrypted = gkr_secure_alloc (n_data);

	gcry = gcry_cipher_decrypt (ch, *decrypted, *n_decrypted, (void*)data, n_data);
	if (gcry) {
		gkr_secure_free (*decrypted);
		g_return_val_if_reached (GKR_PKIX_FAILURE);
	}
	
	gcry_cipher_close (ch);
	
	return GKR_PKIX_SUCCESS;
}
