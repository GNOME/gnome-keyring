/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-prompt-tool.c - Handles gui authentication for the keyring daemon.

   Copyright (C) 2009 Stefan Walter

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

#include "gkd-prompt-util.h"

#include "egg/egg-dh.h"
#include "egg/egg-hex.h"
#include "egg/egg-secure-memory.h"

void
gkd_prompt_util_encode_mpi (GKeyFile *key_file, const gchar *section,
                            const gchar *field, gcry_mpi_t mpi)
{
	gcry_error_t gcry;
	guchar *data;
	gsize n_data;

	g_return_if_fail (key_file);
	g_return_if_fail (section);
	g_return_if_fail (field);
	g_return_if_fail (mpi);

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_HEX, NULL, 0, &n_data, mpi);
	g_return_if_fail (gcry == 0);

	data = g_malloc0 (n_data + 1);

	/* Write into buffer */
	gcry = gcry_mpi_print (GCRYMPI_FMT_HEX, data, n_data, &n_data, mpi);
	g_return_if_fail (gcry == 0);

	g_key_file_set_value (key_file, section, field, (gchar*)data);
	g_free (data);
}

void
gkd_prompt_util_encode_hex (GKeyFile *key_file, const gchar *section,
                            const gchar *field, gconstpointer data, gsize n_data)
{
	gchar *value;

	g_return_if_fail (key_file);
	g_return_if_fail (section);
	g_return_if_fail (field);

	value = egg_hex_encode (data, n_data);
	g_key_file_set_value (key_file, section, field, value);
	g_free (value);
}

gpointer
gkd_prompt_util_decode_hex (GKeyFile *key_file, const gchar *section,
                            const gchar *field, gsize *n_result)
{
	gpointer result = NULL;
	gchar *data;

	g_return_val_if_fail (key_file, NULL);
	g_return_val_if_fail (section, NULL);
	g_return_val_if_fail (field, NULL);
	g_return_val_if_fail (n_result, NULL);

	data = g_key_file_get_value (key_file, section, field, NULL);
	if (data != NULL)
		result = egg_hex_decode (data, -1, n_result);
	g_free (data);
	return result;
}

gboolean
gkd_prompt_util_decode_mpi (GKeyFile *key_file, const gchar *section,
                            const gchar *field, gcry_mpi_t *mpi)
{
	gcry_error_t gcry;
	gchar *data;

	g_return_val_if_fail (key_file, FALSE);
	g_return_val_if_fail (section, FALSE);
	g_return_val_if_fail (field, FALSE);
	g_return_val_if_fail (mpi, FALSE);

	data = g_key_file_get_value (key_file, section, field, NULL);
	if (data == NULL)
		return FALSE;

	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_HEX, data, 0, NULL);
	g_free (data);

	return (gcry == 0);
}

gboolean
gkd_prompt_util_mpi_to_key (gcry_mpi_t mpi, gpointer *key, gsize *n_key)
{
	gcry_error_t gcry;
	guchar *buffer;
	gsize n_buffer;

	g_return_val_if_fail (mpi, FALSE);
	g_return_val_if_fail (key, FALSE);
	g_return_val_if_fail (n_key, FALSE);

	/* Write the key out to raw data */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n_buffer, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	buffer = egg_secure_alloc (n_buffer);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, n_buffer, &n_buffer, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Allocate memory for hashed key */
	g_assert (16 == gcry_md_get_algo_dlen (GCRY_MD_MD5));
	*key = egg_secure_alloc (16);
	*n_key = 16;

	/* Use that as the input to derive a key for 128-bit AES */
	gcry_md_hash_buffer (GCRY_MD_MD5, *key, buffer, n_buffer);

	egg_secure_free (buffer);
	return TRUE;
}

gpointer
gkd_prompt_util_encrypt_text (gpointer key, gsize n_key, gpointer iv, gsize n_iv,
                              const gchar *text, gsize *n_result)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	guchar* padded;
	guchar* result;
	gsize n_text;
	gsize pos;

	g_return_val_if_fail (key, NULL);
	g_return_val_if_fail (n_key == 16, NULL);
	g_return_val_if_fail (iv, NULL);
	g_return_val_if_fail (n_iv == 16, NULL);

	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		return NULL;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Allocate memory for the operation */
	n_text = strlen (text) + 1;
	*n_result = ((n_text + 15) / 16) * 16;
	padded = egg_secure_alloc (*n_result);
	result = g_malloc0 (*n_result);

	/* Setup the padding */
	memset (padded, 0, *n_result);
	memcpy (padded, text, n_text);

	for (pos = 0; pos < *n_result; pos += 16) {
		gcry = gcry_cipher_encrypt (cih, result + pos, 16, padded + pos, 16);
		g_return_val_if_fail (gcry == 0, NULL);
	}

	gcry_cipher_close (cih);

	egg_secure_clear (padded, *n_result);
	egg_secure_free (padded);
	return result;
}

gchar*
gkd_prompt_util_decrypt_text (gpointer key, gsize n_key, gpointer iv, gsize n_iv,
                              gpointer data, gsize n_data)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	gchar *result;
	gsize pos;

	g_return_val_if_fail (key, NULL);
	g_return_val_if_fail (n_key == 16, NULL);

	if (n_iv != 16) {
		g_warning ("prompt response has iv of wrong length");
		return NULL;
	}

	if (n_data % 16 != 0) {
		g_warning ("prompt response encrypted password of wrong length");
		return NULL;
	}

	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		return NULL;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (gcry == 0, NULL);

	/* Allocate memory for the result */
	result = egg_secure_alloc (n_data);

	for (pos = 0; pos < n_data; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, result + pos, 16, (guchar*)data + pos, 16);
		g_return_val_if_fail (gcry == 0, NULL);
	}

	gcry_cipher_close (cih);

	if (!g_utf8_validate (result, -1, NULL)) {
		egg_secure_free (result);
		return NULL;
	}

	return result;
}
