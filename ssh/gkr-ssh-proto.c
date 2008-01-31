/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-proto.c - SSH agent protocol helpers

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
#include "common/gkr-crypto.h"

#include <gcrypt.h>

#include <glib.h>

int
gkr_ssh_proto_keytype_to_algo (const gchar *salgo)
{
	g_return_val_if_fail (salgo, 0);
	if (strcmp (salgo, "ssh-rsa") == 0)
		return GCRY_PK_RSA;
	else if (strcmp (salgo, "ssh-dss") == 0)
		return GCRY_PK_DSA;
	return 0;
}

const gchar*
gkr_ssh_proto_algo_to_keytype (int algo)
{
	g_return_val_if_fail (algo, NULL);
	if (algo == GCRY_PK_RSA)
		return "ssh-rsa";
	else if (algo == GCRY_PK_DSA)
		return "ssh-dss";
	return NULL;	
}

gboolean
gkr_ssh_proto_read_mpi (GkrBuffer *req, gsize *offset, gcry_mpi_t *mpi)
{
	const guchar *data;
	gsize len;
	gcry_error_t gcry;
	
	if (!gkr_buffer_get_byte_array (req, *offset, offset, &data, &len))
		return FALSE;
		
	gcry = gcry_mpi_scan (mpi, GCRYMPI_FMT_USG, data, len, NULL);
	if (gcry)
		return FALSE;
		
	return TRUE;
}

gboolean
gkr_ssh_proto_write_mpi (GkrBuffer *resp, gcry_mpi_t mpi, int format)
{
	guchar *buf;
	size_t len;
  	gcry_error_t gcry;

	/* Get the size */
	gcry = gcry_mpi_print (format, NULL, 0, &len, mpi);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Make a space for it in the buffer */
	buf = gkr_buffer_add_byte_array_empty (resp, len);
	if (!buf)
		return FALSE;

	/* Write in directly to buffer */
	gcry = gcry_mpi_print (format, buf, len, &len, mpi);	
	g_return_val_if_fail (gcry == 0, FALSE);

	return TRUE;
}

gboolean
gkr_ssh_proto_read_public (GkrBuffer *req, gsize *offset, gcry_sexp_t *key, int *algo)
{
	gboolean ret;
	gchar *stype;
	guint sz;
	int alg;
	
	/* The key packet size */
	if (!gkr_buffer_get_uint32 (req, *offset, offset, &sz))
		return FALSE;
	
	/* The string algorithm */
	if (!gkr_buffer_get_string (req, *offset, offset, &stype, (GkrBufferAllocator)g_realloc))
		return FALSE;
	
	alg = gkr_ssh_proto_keytype_to_algo (stype);
	g_free (stype);
	
	if (!alg) {
		g_warning ("unsupported algorithm from SSH: %s", stype);
		return FALSE;
	}
	
	switch (alg) {
	case GCRY_PK_RSA:
		ret = gkr_ssh_proto_read_public_rsa (req, offset, key);
		break;
	case GCRY_PK_DSA:
		ret = gkr_ssh_proto_read_public_dsa (req, offset, key);
		break;
	default:
		g_assert_not_reached ();
		return FALSE;
	}
	
	if (!ret) {
		g_warning ("couldn't read incoming SSH private key");
		return FALSE;
	}
	
	if (algo)
		*algo = alg;
	return TRUE;
}

#define SEXP_PRIVATE_RSA  \
	"(private-key"   \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)"     \
	"    (d %m)"     \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (u %m)))"

gboolean
gkr_ssh_proto_read_private_rsa (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp)
{
	gcry_mpi_t n, e, d, p, q, u;
	gcry_mpi_t tmp;
	int gcry;
	
	if (!gkr_ssh_proto_read_mpi (req, offset, &n) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &e) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &d) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &u) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &p) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &q))
	    	return FALSE;
	
	/* Fix up the incoming key so gcrypt likes it */    	
	if (gcry_mpi_cmp (p, q) > 0) {
		/* P shall be smaller then Q!  Swap primes.  iqmp becomes u.  */
		tmp = p;
		p = q;
		q = tmp;
	} else {
    		/* U needs to be recomputed.  */
		gcry_mpi_invm (u, p, q);
	}

	gcry = gcry_sexp_build (sexp, NULL, SEXP_PRIVATE_RSA, n, e, d, p, q, u);
	if (gcry) {
		g_warning ("couldn't parse incoming private RSA key: %s", gcry_strerror (gcry));
		return FALSE;
	}

	gcry_mpi_release (n);
	gcry_mpi_release (e);
	gcry_mpi_release (d);
	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (u);
		
	return TRUE;
}

#define SEXP_PUBLIC_RSA  \
	"(public-key"    \
	"  (rsa"         \
	"    (n %m)"     \
	"    (e %m)))"
	
gboolean
gkr_ssh_proto_read_public_rsa (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp)
{
	gcry_mpi_t n, e;
	int gcry;
	
	if (!gkr_ssh_proto_read_mpi (req, offset, &e) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &n))
	    	return FALSE;

	gcry = gcry_sexp_build (sexp, NULL, SEXP_PUBLIC_RSA, n, e);
	if (gcry) {
		g_warning ("couldn't parse incoming public RSA key: %s", gcry_strerror (gcry));
		return FALSE;
	}

	gcry_mpi_release (n);
	gcry_mpi_release (e);
		
	return TRUE;
}

#define SEXP_PRIVATE_DSA \
	"(private-key"   \
	"  (dsa"         \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (g %m)"     \
	"    (y %m)"     \
	"    (x %m)))"
	
gboolean
gkr_ssh_proto_read_private_dsa (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp)
{
	gcry_mpi_t p, q, g, y, x;
	int gcry;
	
	if (!gkr_ssh_proto_read_mpi (req, offset, &p) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &q) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &g) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &y) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &x))
	    	return FALSE;

	gcry = gcry_sexp_build (sexp, NULL, SEXP_PRIVATE_DSA, p, q, g, y, x);
	if (gcry) {
		g_warning ("couldn't parse incoming DSA key: %s", gcry_strerror (gcry));
		return FALSE;
	}

	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
	gcry_mpi_release (x);
		
	return TRUE;
}

#define SEXP_PUBLIC_DSA  \
	"(public-key"    \
	"  (dsa"         \
	"    (p %m)"     \
	"    (q %m)"     \
	"    (g %m)"     \
	"    (y %m)))"
	
gboolean
gkr_ssh_proto_read_public_dsa (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp)
{
	gcry_mpi_t p, q, g, y;
	int gcry;
	
	if (!gkr_ssh_proto_read_mpi (req, offset, &p) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &q) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &g) ||
	    !gkr_ssh_proto_read_mpi (req, offset, &y))
	    	return FALSE;

	gcry = gcry_sexp_build (sexp, NULL, SEXP_PUBLIC_DSA, p, q, g, y);
	if (gcry) {
		g_warning ("couldn't parse incoming public DSA key: %s", gcry_strerror (gcry));
		return FALSE;
	}

	gcry_mpi_release (p);
	gcry_mpi_release (q);
	gcry_mpi_release (g);
	gcry_mpi_release (y);
		
	return TRUE;
}

gboolean
gkr_ssh_proto_write_public (GkrBuffer *resp, int algo, gcry_sexp_t key)
{
	gboolean ret = FALSE;
	gsize blobpos;
	const gchar *salgo;
	
	/* Add a space for the key blob length */		
	blobpos = resp->len;
	gkr_buffer_add_uint32 (resp, 0);

	salgo = gkr_ssh_proto_algo_to_keytype (algo);
	g_assert (salgo);
	gkr_buffer_add_string (resp, salgo);
		
	switch (algo) {
	case GCRY_PK_RSA:
		ret = gkr_ssh_proto_write_public_rsa (resp, key);
		break;
			
	case GCRY_PK_DSA:
		ret = gkr_ssh_proto_write_public_dsa (resp, key);
		break;
		
	default:
		g_return_val_if_reached (FALSE);
		break;
	}
		
	/* Write back the blob length */
	gkr_buffer_set_uint32 (resp, blobpos, (resp->len - blobpos) - 4);

	return ret;
}

gboolean
gkr_ssh_proto_write_public_rsa (GkrBuffer *resp, gcry_sexp_t key)
{
	gcry_mpi_t mpi;
	gboolean ret;
	
	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "rsa", "e", NULL);
	g_return_val_if_fail (ret, FALSE);

	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);
	
	if (!ret)
		return ret;

	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "rsa", "n", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);
	
	return ret;
}

gboolean
gkr_ssh_proto_write_public_dsa (GkrBuffer *resp, gcry_sexp_t key)
{
	gcry_mpi_t mpi;
	gboolean ret;

	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "dsa", "p", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);
	
	if (!ret)
		return ret;

	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "dsa", "q", NULL);
	g_return_val_if_fail (ret, FALSE);

	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);

	if (!ret)
		return ret;
		
	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "dsa", "g", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);
	
	if (!ret)
		return ret;
			
	ret = gkr_crypto_sexp_extract_mpi (key, &mpi, "dsa", "y", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_STD);
	gcry_mpi_release (mpi);
	
	return ret;
}

gboolean
gkr_ssh_proto_write_signature_rsa (GkrBuffer *resp, gcry_sexp_t ssig)
{
	gboolean ret;
	gcry_mpi_t mpi;
	
	ret = gkr_crypto_sexp_extract_mpi (ssig, &mpi, "rsa", "s", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	ret = gkr_ssh_proto_write_mpi (resp, mpi, GCRYMPI_FMT_USG);
	gcry_mpi_release (mpi);
	
	return ret;
}

gboolean
gkr_ssh_proto_write_signature_dsa (GkrBuffer *resp, gcry_sexp_t ssig)
{
	guchar buffer[GKR_SSH_DSA_SIGNATURE_PADDING * 2];
	gboolean ret;

	ret = gkr_crypto_sexp_extract_mpi_aligned (ssig, buffer, GKR_SSH_DSA_SIGNATURE_PADDING, 
	                                           "dsa", "r", NULL);
	g_return_val_if_fail (ret, FALSE);

	ret = gkr_crypto_sexp_extract_mpi_aligned (ssig, buffer + GKR_SSH_DSA_SIGNATURE_PADDING, 
	                                           GKR_SSH_DSA_SIGNATURE_PADDING, "dsa", "s", NULL);
	g_return_val_if_fail (ret, FALSE);
	
	return gkr_buffer_add_byte_array (resp, buffer, sizeof (buffer));
}

