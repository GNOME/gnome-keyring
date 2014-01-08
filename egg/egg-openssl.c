/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-openssl.c - OpenSSL compatibility functionality

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "egg-hex.h"
#include "egg-openssl.h"
#include "egg-secure-memory.h"
#include "egg-symkey.h"

#include <gcrypt.h>

#include <glib.h>

#include <ctype.h>
#include <string.h>

EGG_SECURE_DECLARE (openssl);

static const struct {
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

/* ------------------------------------------------------------------------- */

int
egg_openssl_parse_algo (const char *name, int *mode)
{
	static GQuark openssl_quarks[G_N_ELEMENTS(openssl_algos)] = { 0, };
	static gsize openssl_quarks_inited = 0;
	GQuark q;
	int i;

	if (g_once_init_enter (&openssl_quarks_inited)) {
		for (i = 0; i < G_N_ELEMENTS(openssl_algos); ++i)
			openssl_quarks[i] = g_quark_from_static_string (openssl_algos[i].desc);
		g_once_init_leave (&openssl_quarks_inited, 1);
	}

	q = g_quark_try_string (name);
	if (q) {
		for (i = 0; i < G_N_ELEMENTS(openssl_algos); ++i) {
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
	*algo = egg_openssl_parse_algo (parts[0], mode);
	if (!*algo)
		goto done;

	/* Make sure this is usable */
	gcry = gcry_cipher_test_algo (*algo);
	if (gcry)
		goto done;

	/* Parse the IV */
	ivlen = gcry_cipher_get_algo_blklen (*algo);

	*iv = egg_hex_decode (parts[1], strlen(parts[1]), &len);
	if (!*iv || ivlen != len) {
		g_free (*iv);
		goto done;
	}

	success = TRUE;

done:
	g_strfreev (parts);
	return success;
}

guchar *
egg_openssl_decrypt_block (const gchar *dekinfo,
                           const gchar *password,
                           gssize n_password,
                           GBytes *data,
                           gsize *n_decrypted)
{
	gcry_cipher_hd_t ch;
	guchar *key = NULL;
	guchar *iv = NULL;
	int gcry, ivlen;
	int algo = 0;
	int mode = 0;
	guchar *decrypted;

	if (!parse_dekinfo (dekinfo, &algo, &mode, &iv))
		return FALSE;

	ivlen = gcry_cipher_get_algo_blklen (algo);

	/* We assume the iv is at least as long as at 8 byte salt */
	g_return_val_if_fail (ivlen >= 8, FALSE);

	/* IV is already set from the DEK info */
	if (!egg_symkey_generate_simple (algo, GCRY_MD_MD5, password,
	                                 n_password, iv, 8, 1, &key, NULL)) {
		g_free (iv);
		return NULL;
	}

	gcry = gcry_cipher_open (&ch, algo, mode, 0);
	g_return_val_if_fail (!gcry, NULL);

	gcry = gcry_cipher_setkey (ch, key, gcry_cipher_get_algo_keylen (algo));
	g_return_val_if_fail (!gcry, NULL);
	egg_secure_free (key);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (ch, iv, ivlen);
	g_return_val_if_fail (!gcry, NULL);
	g_free (iv);

	/* Allocate output area */
	*n_decrypted = g_bytes_get_size (data);
	decrypted = egg_secure_alloc (*n_decrypted);

	gcry = gcry_cipher_decrypt (ch, decrypted, *n_decrypted,
	                            g_bytes_get_data (data, NULL),
	                            g_bytes_get_size (data));
	if (gcry) {
		egg_secure_free (decrypted);
		g_return_val_if_reached (NULL);
	}

	gcry_cipher_close (ch);

	return decrypted;
}

guchar *
egg_openssl_encrypt_block (const gchar *dekinfo,
                           const gchar *password,
                           gssize n_password,
                           GBytes *data,
                           gsize *n_encrypted)
{
	gsize n_overflow, n_batch, n_padding;
	gcry_cipher_hd_t ch;
	guchar *key = NULL;
	guchar *iv = NULL;
	guchar *padded = NULL;
	int gcry, ivlen;
	int algo = 0;
	int mode = 0;
	gsize n_data;
	guchar *encrypted;
	const guchar *dat;

	if (!parse_dekinfo (dekinfo, &algo, &mode, &iv))
		g_return_val_if_reached (NULL);

	ivlen = gcry_cipher_get_algo_blklen (algo);

	/* We assume the iv is at least as long as at 8 byte salt */
	g_return_val_if_fail (ivlen >= 8, NULL);

	/* IV is already set from the DEK info */
	if (!egg_symkey_generate_simple (algo, GCRY_MD_MD5, password,
	                                        n_password, iv, 8, 1, &key, NULL))
		g_return_val_if_reached (NULL);

	gcry = gcry_cipher_open (&ch, algo, mode, 0);
	g_return_val_if_fail (!gcry, NULL);

	gcry = gcry_cipher_setkey (ch, key, gcry_cipher_get_algo_keylen (algo));
	g_return_val_if_fail (!gcry, NULL);
	egg_secure_free (key);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (ch, iv, ivlen);
	g_return_val_if_fail (!gcry, NULL);
	g_free (iv);

	dat = g_bytes_get_data (data, &n_data);

	/* Allocate output area */
	n_overflow = (n_data % ivlen);
	n_padding = n_overflow ? (ivlen - n_overflow) : 0;
	n_batch = n_data - n_overflow;
	*n_encrypted = n_data + n_padding;
	encrypted = g_malloc0 (*n_encrypted);

	g_assert (*n_encrypted % ivlen == 0);
	g_assert (*n_encrypted >= n_data);
	g_assert (*n_encrypted == n_batch + n_overflow + n_padding);

	/* Encrypt everything but the last bit */
	gcry = gcry_cipher_encrypt (ch, encrypted, n_batch, dat, n_batch);
	if (gcry) {
		g_free (encrypted);
		g_return_val_if_reached (NULL);
	}

	/* Encrypt the padded block */
	if (n_overflow) {
		padded = egg_secure_alloc (ivlen);
		memset (padded, 0, ivlen);
		memcpy (padded, dat + n_batch, n_overflow);
		gcry = gcry_cipher_encrypt (ch, encrypted + n_batch, ivlen, padded, ivlen);
		egg_secure_free (padded);
		if (gcry) {
			g_free (encrypted);
			g_return_val_if_reached (NULL);
		}
	}

	gcry_cipher_close (ch);
	return encrypted;
}

const gchar*
egg_openssl_get_dekinfo (GHashTable *headers)
{
	const gchar *val;
	if (!headers)
		return NULL;
	val = g_hash_table_lookup (headers, "Proc-Type");
	if (!val || strcmp (val, "4,ENCRYPTED") != 0)
		return NULL;
	val = g_hash_table_lookup (headers, "DEK-Info");
	g_return_val_if_fail (val, NULL);
	return val;
}

const gchar*
egg_openssl_prep_dekinfo (GHashTable *headers)
{
	gchar *dekinfo, *hex;
	gsize ivlen;
	guchar *iv;

	/* Create the iv */
	ivlen = gcry_cipher_get_algo_blklen (GCRY_CIPHER_3DES);
	g_return_val_if_fail (ivlen, NULL);
	iv = g_malloc (ivlen);
	gcry_create_nonce (iv, ivlen);

	/* And encode it into the string */
	hex = egg_hex_encode (iv, ivlen);
	g_return_val_if_fail (hex, NULL);
	dekinfo = g_strdup_printf ("DES-EDE3-CBC,%s", hex);
	g_free (hex);
	g_free (iv);

	g_hash_table_insert (headers, g_strdup ("DEK-Info"), (void*)dekinfo);
	g_hash_table_insert (headers, g_strdup ("Proc-Type"), g_strdup ("4,ENCRYPTED"));

	return dekinfo;
}
