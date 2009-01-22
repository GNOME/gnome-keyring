/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-crypto.c - common crypto functionality

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

#include "gkr-crypto.h"

#include "egg/egg-secure-memory.h"

#include <glib.h>

#include <gcrypt.h>

#include <ctype.h>
#include <stdarg.h>

/* -----------------------------------------------------------------------------
 * UTILITIES
 */
 
static gboolean gcrypt_initialized = FALSE;

static void
log_handler (gpointer unused, int unknown, const gchar *msg, va_list va)
{
	/* TODO: Figure out additional arguments */
	g_logv ("gcrypt", G_LOG_LEVEL_MESSAGE, msg, va);
}

static int 
no_mem_handler (gpointer unused, size_t sz, unsigned int unknown)
{
	/* TODO: Figure out additional arguments */
	g_error ("couldn't allocate %lu bytes of memory", 
	         (unsigned long int)sz);
	return 0;
}

static void
fatal_handler (gpointer unused, int unknown, const gchar *msg)
{
	/* TODO: Figure out additional arguments */
	g_log ("gcrypt", G_LOG_LEVEL_ERROR, "%s", msg);
}

void
gkr_crypto_setup (void)
{
	unsigned seed;

	if (gcrypt_initialized)
		return;
		
	gcry_check_version (LIBGCRYPT_VERSION);
	gcry_set_log_handler (log_handler, NULL);
	gcry_set_outofcore_handler (no_mem_handler, NULL);
	gcry_set_fatalerror_handler (fatal_handler, NULL);
	gcry_set_allocation_handler ((gcry_handler_alloc_t)g_malloc, 
	                             (gcry_handler_alloc_t)egg_secure_alloc, 
	                             egg_secure_check, 
	                             (gcry_handler_realloc_t)egg_secure_realloc, 
	                             egg_secure_free);
	                             
	gcrypt_initialized = TRUE;
	
	gcry_create_nonce (&seed, sizeof (seed));
	srand (seed);
}

/* -----------------------------------------------------------------------------
 * MPI HELPERS
 */
 
static gcry_sexp_t
sexp_get_childv (gcry_sexp_t sexp, va_list va)
{
	gcry_sexp_t at = NULL;
	gcry_sexp_t child;
	const char *name;
	
	for(;;) {
		name = va_arg (va, const char*);
		if (!name)
			break;

		child = gcry_sexp_find_token (at ? at : sexp, name, 0);
		gcry_sexp_release (at);
		at = child;
		if (at == NULL)
			break;
	}
	
	va_end (va);

	return at;
}
 
gboolean
gkr_crypto_sexp_extract_mpi (gcry_sexp_t sexp, gcry_mpi_t *mpi, ...)
{
	gcry_sexp_t at = NULL;
	va_list va;
	
	g_assert (sexp);
	g_assert (mpi);
	
	va_start (va, mpi);
	at = sexp_get_childv (sexp, va);
	va_end (va);
	
	*mpi = NULL;
	if (at)
		*mpi = gcry_sexp_nth_mpi (at ? at : sexp, 1, GCRYMPI_FMT_USG);
	if (at)
		gcry_sexp_release (at);

	return (*mpi) ? TRUE : FALSE;
}

static gboolean
print_mpi_aligned (gcry_mpi_t mpi, guchar *block, gsize n_block)
{
	gcry_error_t gcry;
	gsize offset, len;
	
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	if (n_block < len)
		return FALSE;
	
	offset = n_block - len;
	memset (block, 0, offset);
	
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, block + offset, len, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);
	g_return_val_if_fail (len == n_block - offset, FALSE);
	
	return TRUE;
}

guchar*
gkr_crypto_sexp_extract_mpi_padded (gcry_sexp_t sexp, guint bits, gsize *n_data, 
                                    GkrCryptoPadding padfunc, ...)
{
	gcry_sexp_t at = NULL;
	gcry_mpi_t mpi;
	va_list va;
	guchar *padded, *data;
	gsize n_padded;
	
	g_assert (sexp);
	g_assert (n_data);
	g_assert (padfunc);
	g_assert (bits);
	
	va_start (va, padfunc);
	at = sexp_get_childv (sexp, va);
	va_end (va);
	
	if (!at)
		return NULL;

	/* Parse out the MPI */
	mpi = gcry_sexp_nth_mpi (at ? at : sexp, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release (at);
	
	if (!mpi)
		return NULL;
	
	/* Do we need to unpad the data? */
	n_padded = (bits + 7) / 8;
	data = NULL;
	
	/* Extract it aligned into this buffer */
	padded = g_malloc0 (n_padded);
	if (print_mpi_aligned (mpi, padded, n_padded))
		data = (padfunc) (bits, padded, n_padded, n_data);
	g_free (padded);
	
	gcry_mpi_release (mpi);
	return data;	
}

gboolean
gkr_crypto_sexp_extract_mpi_aligned (gcry_sexp_t sexp, guchar* block, gsize n_block, ...)
{
	gcry_sexp_t at = NULL;
	gboolean ret;
	gcry_mpi_t mpi;
	va_list va;
	
	g_assert (sexp);
	g_assert (block);
	g_assert (n_block);
	
	va_start (va, n_block);
	at = sexp_get_childv (sexp, va);
	va_end (va);
	
	if (!at)
		return FALSE;

	/* Parse out the MPI */
	mpi = gcry_sexp_nth_mpi (at ? at : sexp, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release (at);
	
	if (!mpi)
		return FALSE;

	ret = print_mpi_aligned (mpi, block, n_block);
	gcry_mpi_release (mpi);
	return ret;
}
                                                         
void
gkr_crypto_sexp_dump (gcry_sexp_t sexp)
{
	gsize len;
	gchar *buf;
	
	len = gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	buf = g_malloc (len);
	gcry_sexp_sprint (sexp, GCRYSEXP_FMT_ADVANCED, buf, len);
	g_printerr ("%s", buf);
	g_free (buf);
}

#define PUBLIC_KEY "public-key"
#define PUBLIC_KEY_L 10
#define PRIVATE_KEY "private-key"
#define PRIVATE_KEY_L 11

gboolean
gkr_crypto_skey_parse (gcry_sexp_t s_key, int *algorithm, gboolean *is_priv, 
                       gcry_sexp_t *numbers)
{
	gboolean ret = FALSE;
	gcry_sexp_t child = NULL;
	gchar *str = NULL;
  	const gchar *data;
  	gsize n_data;
  	gboolean priv;
  	int algo;

	data = gcry_sexp_nth_data (s_key, 0, &n_data);
	if (!data) 
		goto done;

	if (n_data == PUBLIC_KEY_L && strncmp (data, PUBLIC_KEY, PUBLIC_KEY_L) == 0)
		priv = FALSE;
	else if (n_data == PRIVATE_KEY_L && strncmp (data, PRIVATE_KEY, PRIVATE_KEY_L) == 0)
		priv = TRUE;
	else
		goto done;

	child = gcry_sexp_nth (s_key, 1);
	if (!child)
		goto done;
		
	data = gcry_sexp_nth_data (child, 0, &n_data);
	if (!data)
		goto done;
		
	str = g_alloca (n_data + 1);
	memcpy (str, data, n_data);
	str[n_data] = 0;
	
	algo = gcry_pk_map_name (str);
	if (!algo)
		goto done;

	/* Yay all done */
	if (algorithm)
		*algorithm = algo;
	if (numbers) {
		*numbers = child;
		child = NULL;
	}
	if (is_priv)
		*is_priv = priv;

	ret = TRUE;
	
done:
	gcry_sexp_release (child);
	return ret;
}

gkrid
gkr_crypto_skey_make_id (gcry_sexp_t s_key)
{
	guchar hash[20];
	
	g_return_val_if_fail (s_key != NULL, NULL);
	
	if (!gcry_pk_get_keygrip (s_key, hash))
		g_return_val_if_reached (NULL);
	
	return gkr_id_new (hash, sizeof (hash));
}

static gcry_sexp_t
rsa_numbers_to_public (gcry_sexp_t rsa)
{
	gcry_sexp_t pubkey = NULL;
	gcry_mpi_t n, e;
	gcry_error_t gcry;
	
	n = e = NULL;
	
	gkr_crypto_sexp_dump (rsa);
	
	if (!gkr_crypto_sexp_extract_mpi (rsa, &n, "n", NULL) || 
	    !gkr_crypto_sexp_extract_mpi (rsa, &e, "e", NULL))
	    	goto done;
	    	
	gcry = gcry_sexp_build (&pubkey, NULL, "(public-key (rsa (n %m) (e %m)))",
	                        n, e);
	if (gcry)
		goto done;
	g_assert (pubkey);
	
done:
	gcry_mpi_release (n);
	gcry_mpi_release (e);

	/* This should have worked */
	g_return_val_if_fail (pubkey != NULL, NULL);
	return pubkey;
}

static gcry_sexp_t
dsa_numbers_to_public (gcry_sexp_t dsa)
{
	gcry_mpi_t p, q, g, y;
	gcry_sexp_t pubkey = NULL;
	gcry_error_t gcry;
	
	p = q = g = y = NULL;
	
	if (!gkr_crypto_sexp_extract_mpi (dsa, &p, "p", NULL) || 
	    !gkr_crypto_sexp_extract_mpi (dsa, &q, "q", NULL) ||
	    !gkr_crypto_sexp_extract_mpi (dsa, &g, "g", NULL) ||
	    !gkr_crypto_sexp_extract_mpi (dsa, &y, "y", NULL))
	    	goto done;
	    	
	gcry = gcry_sexp_build (&pubkey, NULL, "(public-key (dsa (p %m) (q %m) (g %m) (y %m)))",
	                        p, q, g, y);
	if (gcry)
		goto done;
	g_assert (pubkey);
	
done:
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);

	/* This should have worked */	
	g_return_val_if_fail (pubkey != NULL, NULL);
	return pubkey;
}

gboolean
gkr_crypto_skey_private_to_public (gcry_sexp_t privkey, gcry_sexp_t *pubkey)
{
	gcry_sexp_t numbers;
	int algorithm;

	if (!gkr_crypto_skey_parse (privkey, &algorithm, NULL, &numbers))
		g_return_val_if_reached (FALSE);
		
	switch (algorithm) {
	case GCRY_PK_RSA:
		*pubkey = rsa_numbers_to_public (numbers);
		break;
	case GCRY_PK_DSA:
		*pubkey = dsa_numbers_to_public (numbers);
		break;
	default:
		g_return_val_if_reached (FALSE);
	} 
	
	gcry_sexp_release (numbers);
	return *pubkey ? TRUE : FALSE;
}

/* -------------------------------------------------------------------
 * RSA PADDING
 */

guchar*
gkr_crypto_rsa_pad_raw (guint n_modulus, const guchar* raw,
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x00 0x00 ... 0x?? 0x?? 0x?? ...
         *   padding               data
         */

	total = n_modulus / 8;
	n_pad = total - n_raw;
	if (n_pad < 0) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	memset (padded, 0x00, n_pad);
	memcpy (padded + n_pad, raw, n_raw);
	
	*n_padded = total;
	return padded;
}

guchar*
gkr_crypto_rsa_pad_one (guint n_modulus, const guchar* raw, 
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x01 0xFF 0xFF ... 0x00 0x?? 0x?? 0x?? ...
         *      type  padding              data
         */

	total = n_modulus / 8;
	n_pad = total - 3 - n_raw;
	if (n_pad < 8) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	padded[1] = 1; /* Block type */
	memset (padded + 2, 0xff, n_pad);
	memcpy (padded + 3 + n_pad, raw, n_raw); 
	
	*n_padded = total;
	return padded;
}

static void
fill_random_nonzero (guchar *data, gsize n_data)
{
	guchar *rnd;
	guint n_zero, i, j;
	
	gcry_randomize (data, n_data, GCRY_STRONG_RANDOM);

	/* Find any zeros in random data */
	n_zero = 0;
	for (i = 0; i < n_data; ++i) {
		if (data[i] == 0x00)
			++n_zero;
	}

	while (n_zero > 0) {
		rnd = gcry_random_bytes (n_zero, GCRY_STRONG_RANDOM);
		n_zero = 0;
		for (i = 0, j = 0; i < n_data; ++i) {
			if (data[i] != 0x00)
				continue;
				
			/* Use some of the replacement data */
			data[i] = rnd[j];
			++j;
			
			/* It's zero again :( */
			if (data[i] == 0x00)
				n_zero++;
		}
		
		gcry_free (rnd);
	}
}

guchar*
gkr_crypto_rsa_pad_two (guint n_modulus, const guchar* raw, 
                        gsize n_raw, gsize *n_padded)
{
	gint total, n_pad;
	guchar *padded;

	/*
	 * 0x00 0x01 0x?? 0x?? ... 0x00 0x?? 0x?? 0x?? ...
         *      type  padding              data
         */

	total = n_modulus / 8;
	n_pad = total - 3 - n_raw;
	if (n_pad < 8) /* minumum padding */
		return NULL;

	padded = g_new0 (guchar, total);
	padded[1] = 2; /* Block type */
	fill_random_nonzero (padded + 2, n_pad);
	memcpy (padded + 3 + n_pad, raw, n_raw); 
	
	*n_padded = total;
	return padded;
}

static guchar*
unpad_rsa_pkcs1 (guchar bt, guint n_modulus, const guchar* padded,
                 gsize n_padded, gsize *n_raw)
{ 
	const guchar *at;
	guchar *raw;
	
	/* The absolute minimum size including padding */
	g_return_val_if_fail (n_modulus / 8 >= 3 + 8, NULL);
	
	if (n_padded != n_modulus / 8)
		return NULL;
		
	/* Check the header */
	if (padded[0] != 0x00 || padded[1] != bt)
		return NULL;
	
	/* The first zero byte after the header */
	at = memchr (padded + 2, 0x00, n_padded - 2);
	if (!at)
		return NULL;
		
	++at;
	*n_raw = n_padded - (at - padded);
	raw = g_new0 (guchar, *n_raw);
	memcpy (raw, at, *n_raw);
	return raw;
}

guchar*
gkr_crypto_rsa_unpad_pkcs1 (guint bits, const guchar *padded,
                            gsize n_padded, gsize *n_raw)
{
	/* Further checks are done later */
	g_return_val_if_fail (n_padded > 2, NULL);
	return unpad_rsa_pkcs1 (padded[1], bits, padded, n_padded, n_raw);
}

guchar* 
gkr_crypto_rsa_unpad_one (guint bits, const guchar *padded, 
                          gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x01, bits, padded, n_padded, n_raw);
}

guchar* 
gkr_crypto_rsa_unpad_two (guint bits, const guchar *padded, 
                          gsize n_padded, gsize *n_raw)
{
	return unpad_rsa_pkcs1 (0x02, bits, padded, n_padded, n_raw);
}
