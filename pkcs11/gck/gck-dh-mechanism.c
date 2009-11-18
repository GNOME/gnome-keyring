/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "gck-attributes.h"
#include "gck-crypto.h"
#include "gck-dh-mechanism.h"
#include "gck-dh-private-key.h"
#include "gck-dh-public-key.h"
#include "gck-session.h"

#include "egg/egg-dh.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-secure-memory.h"

CK_RV
gck_dh_mechanism_generate (GckSession *session, CK_ATTRIBUTE_PTR pub_atts,
                           CK_ULONG n_pub_atts, CK_ATTRIBUTE_PTR priv_atts,
                           CK_ULONG n_priv_atts, GckObject **pub_key,
                           GckObject **priv_key)
{
	gcry_mpi_t prime = NULL;
	gcry_mpi_t base = NULL;
	gcry_mpi_t pub = NULL;
	gcry_mpi_t priv = NULL;
	gcry_error_t gcry;
	guchar *buffer, *id;
	gsize n_buffer, n_id;
	GckManager *manager;
	GckModule *module;
	gulong bits;

	g_return_val_if_fail (GCK_IS_SESSION (session), CKR_GENERAL_ERROR);
	g_return_val_if_fail (pub_key, CKR_GENERAL_ERROR);
	g_return_val_if_fail (priv_key, CKR_GENERAL_ERROR);

	if (!gck_attributes_find_mpi (pub_atts, n_pub_atts, CKA_PRIME, &prime) ||
	    !gck_attributes_find_mpi (pub_atts, n_pub_atts, CKA_BASE, &base)) {
		gcry_mpi_release (prime);
		gcry_mpi_release (base);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	gck_attributes_consume (pub_atts, n_pub_atts, CKA_PRIME, CKA_BASE, G_MAXULONG);

	if (!gck_attributes_find_ulong (priv_atts, n_priv_atts, CKA_VALUE_BITS, &bits))
		bits = gcry_mpi_get_nbits (prime);

	gck_attributes_consume (priv_atts, n_priv_atts, CKA_VALUE_BITS, G_MAXULONG);

	/* The private key must be less than or equal to prime */
	if (bits > gcry_mpi_get_nbits (prime)) {
		gcry_mpi_release (prime);
		gcry_mpi_release (base);
		return CKR_TEMPLATE_INCONSISTENT;
	}

	if (!egg_dh_gen_pair (prime, base, bits, &priv, &pub)) {
		gcry_mpi_release (prime);
		gcry_mpi_release (base);
		return CKR_FUNCTION_FAILED;
	}

	/* Write the public key out to raw data, so we can use it for an ID */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n_buffer, pub);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	buffer = g_malloc (n_buffer);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, n_buffer, &n_buffer, pub);
	g_return_val_if_fail (gcry == 0, CKR_GENERAL_ERROR);
	if (n_buffer < 16) {
		n_id = n_buffer;
		id = g_memdup (buffer, n_id);
	} else {
		n_id = 16;
		id = g_memdup (buffer + (n_buffer - 16), n_id);
	}

	manager = gck_manager_for_template (pub_atts, n_pub_atts, session);
	module = gck_session_get_module (session);

	*pub_key = GCK_OBJECT (gck_dh_public_key_new (module, manager, prime, base,
	                                              pub, id, n_id));

	id = g_memdup (id, n_id);
	prime = gcry_mpi_copy (prime);
	base = gcry_mpi_copy (base);

	*priv_key = GCK_OBJECT (gck_dh_private_key_new (module, manager, prime, base,
	                                                priv, id, n_id));

	gck_attributes_consume (pub_atts, n_pub_atts, CKA_PRIME, CKA_BASE, G_MAXULONG);

	g_free (buffer);
	return CKR_OK;
}

static gpointer
prepare_and_truncate_secret (gcry_mpi_t secret, CK_ATTRIBUTE_PTR attrs,
                             CK_ULONG n_attrs, gsize *n_value)
{
	CK_ULONG length = 0;
	CK_KEY_TYPE type;
	gcry_error_t gcry;
	guchar *value;
	gsize offset = 0;

	g_assert (n_value);

	/* What length should we truncate to? */
	if (!gck_attributes_find_ulong (attrs, n_attrs, CKA_VALUE_LEN, &length)) {
		if (gck_attributes_find_ulong (attrs, n_attrs, CKA_KEY_TYPE, &type))
			length = gck_crypto_secret_key_length (type);
	}

	/* Write out the secret */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, n_value, secret);
	g_return_val_if_fail (gcry == 0, NULL);
	if (*n_value < length)
		offset = length - *n_value;
	value = egg_secure_alloc (*n_value + offset);
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, value + offset, *n_value, n_value, secret);
	g_return_val_if_fail (gcry == 0, NULL);

	if (length != 0 && length < *n_value) {
		offset = *n_value - length;
		memmove (value, value + offset, length);
		*n_value = length;
	}

	return value;
}

CK_RV
gck_dh_mechanism_derive (GckSession *session, CK_MECHANISM_PTR mech, GckObject *base,
                         CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, GckObject **derived)
{
	gcry_mpi_t peer = NULL;
	gcry_mpi_t prime;
	gcry_mpi_t priv;
	gcry_mpi_t secret;
	gcry_error_t gcry;
	CK_ATTRIBUTE attr;
	GArray *array;
	gboolean ret;
	gsize n_value;
	gpointer value;
	CK_RV rv;

	g_return_val_if_fail (GCK_IS_DH_PRIVATE_KEY (base), CKR_GENERAL_ERROR);

	if (mech->ulParameterLen && mech->pParameter) {
		gcry = gcry_mpi_scan (&peer, GCRYMPI_FMT_USG, mech->pParameter,
		                      mech->ulParameterLen, NULL);
		if (gcry != 0)
			peer = NULL;
	}

	if (peer == NULL)
		return CKR_MECHANISM_PARAM_INVALID;

	prime = gck_dh_key_get_prime (GCK_DH_KEY (base));
	priv = gck_dh_private_key_get_value (GCK_DH_PRIVATE_KEY (base));
	ret = egg_dh_gen_secret (peer, priv, prime, &secret);
	gcry_mpi_release (peer);

	if (ret != TRUE)
		return CKR_FUNCTION_FAILED;

	value = prepare_and_truncate_secret (secret, attrs, n_attrs, &n_value);
	g_return_val_if_fail (value, CKR_GENERAL_ERROR);
	gcry_mpi_release (secret);

	/* Now setup the attributes with our new value */
	array = g_array_new (FALSE, FALSE, sizeof (CK_ATTRIBUTE));

	/* Prepend the value */
	attr.type = CKA_VALUE;
	attr.pValue = value;
	attr.ulValueLen = n_value;
	g_array_append_val (array, attr);

	/* Add the remainder of the attributes */
	g_array_append_vals (array, attrs, n_attrs);

	/* Now create an object with these attributes */
	rv = gck_session_create_object_for_attributes (session, (CK_ATTRIBUTE_PTR)array->data,
	                                               array->len, derived);

	egg_secure_free (value);
	g_array_free (array, TRUE);

	return rv;
}
