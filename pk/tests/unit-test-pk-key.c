/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pk-key.c: Test public and private keys

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

#include "run-auto-test.h"

#include "common/gkr-crypto.h"

#include "pk/gkr-pk-index.h"
#include "pk/gkr-pk-object.h"
#include "pk/gkr-pk-object-manager.h"
#include "pk/gkr-pk-pubkey.h"
#include "pk/gkr-pk-privkey.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"

#include "pkix/gkr-pkix-der.h"

#include <glib.h>
#include <memory.h>
#include <gcrypt.h>

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void)
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void)
 * 
 * Tests be run in the order specified here.
 */

static GkrPkObjectManager *manager = NULL;

static GkrPkObject *privkey_1 = NULL;
static GkrPkObject *privkey_3 = NULL;
static GkrPkObject *pubkey_1 = NULL;

void unit_setup_keys (void)
{
	gkr_crypto_setup ();
	
	/* Our own object manager */
	manager = gkr_pk_object_manager_instance_for_client (1232); 
}

void unit_test_create_keys (CuTest* cu)
{
	GkrPkixResult res;
	gcry_sexp_t sexp;
	gchar *data;
	gsize n_data;
	
	if (!g_file_get_contents ("test-data/privkey-1.key", &data, &n_data, NULL))
		g_error ("couldn't read privkey-1.key");
	res = gkr_pkix_der_read_private_key ((const guchar*)data, n_data, &sexp);
	g_assert (res == GKR_PKIX_SUCCESS);
	
	privkey_1 = gkr_pk_privkey_new (manager, 0, sexp);
	g_assert (GKR_IS_PK_PRIVKEY (privkey_1));
	
	/* Should automatically create a public key */
	pubkey_1 = GKR_PK_OBJECT (gkr_pk_privkey_get_public (GKR_PK_PRIVKEY (privkey_1)));
	if (!pubkey_1)
		g_error ("couldn't get public key");
		
	if (!g_file_get_contents ("test-data/privkey-3.key", &data, &n_data, NULL))
		g_error ("couldn't read privkey-3.key");
	res = gkr_pkix_der_read_private_key ((const guchar*)data, n_data, &sexp);
	g_assert (res == GKR_PKIX_SUCCESS);
	
	privkey_3 = gkr_pk_privkey_new (manager, 0, sexp);
	g_assert (GKR_IS_PK_PRIVKEY (privkey_3));
}

#include "check-attribute.c"
		 
void unit_test_privkey_static (CuTest *cu)
{
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_TOKEN, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_PRIVATE, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_DECRYPT, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_SENSITIVE, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_SIGN, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_SIGN_RECOVER, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_WRAP_WITH_TRUSTED, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_DERIVE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_EXTRACTABLE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_UNWRAP, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_GNOME_PURPOSE_SSH_AUTH, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_ALWAYS_SENSITIVE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_LOCAL, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_NEVER_EXTRACTABLE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, privkey_1, CKA_ALWAYS_AUTHENTICATE, CK_FALSE);
	
	CHECK_ULONG_ATTRIBUTE (cu, privkey_1, CKA_CLASS, CKO_PRIVATE_KEY);
	CHECK_ULONG_ATTRIBUTE (cu, privkey_1, CKA_KEY_TYPE, CKK_RSA);
	CHECK_ULONG_ATTRIBUTE (cu, privkey_1, CKA_KEY_GEN_MECHANISM, CK_UNAVAILABLE_INFORMATION);
}

void unit_test_pubkey_static (CuTest *cu)
{
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_TOKEN, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_PRIVATE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_ENCRYPT, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_SENSITIVE, CK_FALSE);
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_EXTRACTABLE, CK_TRUE);
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_VERIFY, CK_TRUE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_VERIFY_RECOVER, CK_TRUE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_ALWAYS_AUTHENTICATE, CK_FALSE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_DERIVE, CK_FALSE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_WRAP, CK_FALSE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_WRAP_WITH_TRUSTED, CK_FALSE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_TRUSTED, CK_FALSE); 
	CHECK_BOOL_ATTRIBUTE (cu, pubkey_1, CKA_LOCAL, CK_FALSE); 

	CHECK_ULONG_ATTRIBUTE (cu, pubkey_1, CKA_CLASS, CKO_PUBLIC_KEY);
	CHECK_ULONG_ATTRIBUTE (cu, pubkey_1, CKA_KEY_TYPE, CKK_RSA);
	CHECK_ULONG_ATTRIBUTE (cu, pubkey_1, CKA_MODULUS_BITS, 2048);
}

void unit_test_privkey_related (CuTest *cu)
{
	GkrPkObject *obj;
	gkrconstid keyid;
	gkrconstid pubid;
	
	keyid = gkr_pk_privkey_get_keyid (GKR_PK_PRIVKEY (privkey_1));
	CuAssert (cu, "No key id returned from private key", keyid != NULL);
	
	obj = gkr_pk_object_manager_find_by_id (manager, GKR_TYPE_PK_PUBKEY, keyid);
	CuAssert (cu, "No matching public key object found in manager", GKR_IS_PK_PUBKEY (obj));
	
	pubid = gkr_pk_pubkey_get_keyid (GKR_PK_PUBKEY (obj));
	CuAssert (cu, "No key id returned from public key", pubid != NULL);
	
	CuAssert (cu, "private and public key ids do not match", gkr_id_equals (keyid, pubid));
}

void unit_test_privkey_rsa_create (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	gcry_sexp_t skey;
	gcry_mpi_t mpi;
	GkrPkObject *object;
	GArray *attrs;
	CK_RV ret;
	
	attrs = gkr_pk_attributes_new ();

	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_PRIVATE_KEY);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_KEY_TYPE;
	gkr_pk_attribute_set_ulong (&attr, CKK_RSA);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_MODULUS; 
	if (gkr_pk_object_get_attribute (privkey_1, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_PUBLIC_EXPONENT; 
	if (gkr_pk_object_get_attribute (privkey_1, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);
	
	skey = gkr_pk_privkey_get_key (GKR_PK_PRIVKEY (privkey_1));
	CuAssert (cu, "private key has no internal key", skey != NULL);

	attr.type = CKA_PRIVATE_EXPONENT;
	if (!gkr_crypto_sexp_extract_mpi (skey, &mpi, "private-key", "d", NULL))
		g_assert (FALSE);
	gkr_pk_attribute_set_mpi (&attr, mpi);
	gcry_mpi_release (mpi);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_PRIME_1;
	if (!gkr_crypto_sexp_extract_mpi (skey, &mpi, "private-key", "p", NULL))
		g_assert (FALSE);
	gkr_pk_attribute_set_mpi (&attr, mpi);
	gcry_mpi_release (mpi);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_PRIME_2;
	if (!gkr_crypto_sexp_extract_mpi (skey, &mpi, "private-key", "q", NULL))
		g_assert (FALSE);
	gkr_pk_attribute_set_mpi (&attr, mpi);
	gcry_mpi_release (mpi);
	gkr_pk_attributes_append (attrs, &attr);
	
	/* Now try with a proper set of attributes */
	ret = gkr_pk_object_create (manager, attrs, &object);
	CuAssert (cu, "Private key creation failed", ret == CKR_OK);
	CuAssert (cu, "Returned invalid object", GKR_IS_PK_PRIVKEY (object));
	
	gkr_pk_attributes_free (attrs);
	
	/* Free the private key */
	g_object_unref (object);
}

void unit_test_pubkey_rsa_create (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	GkrPkObject *object;
	GArray *attrs;
	CK_RV ret;
	
	attrs = gkr_pk_attributes_new ();

	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_PUBLIC_KEY);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_KEY_TYPE;
	gkr_pk_attribute_set_ulong (&attr, CKK_RSA);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_MODULUS; 
	if (gkr_pk_object_get_attribute (privkey_1, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_PUBLIC_EXPONENT; 
	if (gkr_pk_object_get_attribute (privkey_1, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);
	
	/* Now try with a proper set of attributes */
	ret = gkr_pk_object_create (manager, attrs, &object);
	CuAssert (cu, "Public key creation failed", ret == CKR_OK);
	CuAssert (cu, "Returned invalid object", GKR_IS_PK_PUBKEY (object));
	
	gkr_pk_attributes_free (attrs);
	
	/* Free the private key */
	g_object_unref (object);
}

void unit_test_privkey_dsa_create (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	gcry_sexp_t skey;
	gcry_mpi_t mpi;
	GkrPkObject *object;
	GArray *attrs;
	CK_RV ret;
	
	attrs = gkr_pk_attributes_new ();

	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_PRIVATE_KEY);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_KEY_TYPE;
	gkr_pk_attribute_set_ulong (&attr, CKK_DSA);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_PRIME; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_SUBPRIME; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_BASE; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);
	
	skey = gkr_pk_privkey_get_key (GKR_PK_PRIVKEY (privkey_3));
	CuAssert (cu, "private key has no internal key", skey != NULL);

	attr.type = CKA_VALUE;
	if (!gkr_crypto_sexp_extract_mpi (skey, &mpi, "private-key", "x", NULL))
		g_assert (FALSE);
	gkr_pk_attribute_set_mpi (&attr, mpi);
	gcry_mpi_release (mpi);
	gkr_pk_attributes_append (attrs, &attr);
	
	/* Now try with a proper set of attributes */
	ret = gkr_pk_object_create (manager, attrs, &object);
	CuAssert (cu, "Private key creation failed", ret == CKR_OK);
	CuAssert (cu, "Returned invalid object", GKR_IS_PK_PRIVKEY (object));
	
	gkr_pk_attributes_free (attrs);
	
	/* Free the private key */
	g_object_unref (object);
}

void unit_test_pubkey_dsa_create (CuTest *cu)
{
	CK_ATTRIBUTE attr;
	GkrPkObject *object;
	GArray *attrs;
	gcry_sexp_t skey;
	gcry_mpi_t mpi;
	CK_RV ret;
	
	attrs = gkr_pk_attributes_new ();

	memset (&attr, 0, sizeof (attr));
	attr.type = CKA_CLASS;
	gkr_pk_attribute_set_ulong (&attr, CKO_PUBLIC_KEY);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_KEY_TYPE;
	gkr_pk_attribute_set_ulong (&attr, CKK_DSA);
	gkr_pk_attributes_append (attrs, &attr);
	
	attr.type = CKA_PRIME; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_SUBPRIME; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	attr.type = CKA_BASE; 
	if (gkr_pk_object_get_attribute (privkey_3, &attr) != CKR_OK)
		g_assert (FALSE);
	gkr_pk_attributes_append (attrs, &attr);

	skey = gkr_pk_privkey_get_key (GKR_PK_PRIVKEY (privkey_3));
	CuAssert (cu, "private key has no internal key", skey != NULL);

	attr.type = CKA_VALUE;
	if (!gkr_crypto_sexp_extract_mpi (skey, &mpi, "private-key", "y", NULL))
		g_assert (FALSE);
	gkr_pk_attribute_set_mpi (&attr, mpi);
	gcry_mpi_release (mpi);
	gkr_pk_attributes_append (attrs, &attr);
		
	/* Now try with a proper set of attributes */
	ret = gkr_pk_object_create (manager, attrs, &object);
	CuAssert (cu, "Public key creation failed", ret == CKR_OK);
	CuAssert (cu, "Returned invalid object", GKR_IS_PK_PUBKEY (object));
	
	gkr_pk_attributes_free (attrs);
	
	/* Free the private key */
	g_object_unref (object);
}
