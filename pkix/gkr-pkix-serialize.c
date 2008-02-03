
#include "config.h"

#include "gkr-pkix-asn1.h"
#include "gkr-pkix-der.h"
#include "gkr-pkix-serialize.h"
#include "gkr-pkix-types.h"

#include "common/gkr-crypto.h"
#include "common/gkr-location.h"
#include "common/gkr-secure-memory.h"

#include <glib/gi18n.h>

#include <stdlib.h>

/* -----------------------------------------------------------------------------
 * QUARK DEFINITIONS
 */

static GQuark OID_PKIX1_RSA;
static GQuark OID_PKIX1_DSA;
static GQuark OID_PKCS12_PBE_3DES_SHA1;

static void
init_quarks (void)
{
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)
 
	QUARK (OID_PKIX1_RSA, "1.2.840.113549.1.1.1");
	QUARK (OID_PKIX1_DSA, "1.2.840.10040.4.1");
	QUARK (OID_PKCS12_PBE_3DES_SHA1, "1.2.840.113549.1.12.1.3");
	
	#undef QUARK
}

/* ----------------------------------------------------------------------------
 * PUBLIC FUNCTIONS
 */

gboolean
gkr_pkix_serialize_to_location (GQuark type, gpointer what, const gchar *password, 
                                GQuark location, GError **err)
{
	gboolean ret;
	gchar *path;
	guchar *data;
	gsize n_data;
	
	data = gkr_pkix_serialize_to_data (type, what, password, &n_data);
	g_return_val_if_fail (data, FALSE);
	
	path = gkr_location_to_path (location);
	if (!path) {
		g_free (data);
		g_set_error (err, G_FILE_ERROR, G_FILE_ERROR_NODEV, "%s",  
		             _("The disk or drive this file is located on is not present"));
		return FALSE;
	}
	
	ret = g_file_set_contents (path, (const gchar*)data, n_data, err);
	g_free (path);
	g_free (data);
	
	return ret;
}

guchar*
gkr_pkix_serialize_to_data (GQuark type, gpointer what, const gchar *password, 
                            gsize *n_data)
{
	if (type == GKR_PKIX_CERTIFICATE) 
		return gkr_pkix_serialize_certificate ((ASN1_TYPE)what, n_data);
	
	else if (type == GKR_PKIX_PUBLIC_KEY)
		return gkr_pkix_serialize_public_key ((gcry_sexp_t)what, n_data);
		
	else if (type == GKR_PKIX_PRIVATE_KEY)
		return gkr_pkix_serialize_private_key_pkcs8 ((gcry_sexp_t)what, password, n_data);
		
	g_return_val_if_reached (NULL);
}

guchar*           
gkr_pkix_serialize_certificate (ASN1_TYPE asn, gsize *n_data)
{
	g_return_val_if_fail (asn, NULL);
	g_return_val_if_fail (n_data, NULL);
	return gkr_pkix_der_write_certificate (asn, n_data);
}

guchar*
gkr_pkix_serialize_public_key (gcry_sexp_t skey, gsize *n_data)
{
	g_return_val_if_fail (skey, NULL);
	g_return_val_if_fail (n_data, NULL);
	return gkr_pkix_der_write_public_key (skey, n_data);
}

static gcry_cipher_hd_t
prepare_and_encode_pkcs8_cipher (ASN1_TYPE asn, const gchar *password, gsize *n_block)
{
	ASN1_TYPE asn1_params;
	gcry_cipher_hd_t cih;
	guchar salt[8];
	gcry_error_t gcry;
	guchar *key, *iv, *portion;
	gsize n_key, n_portion;
	int iterations, res;
	
	init_quarks ();

	/* Make sure the encryption algorithm works */
	g_return_val_if_fail (gcry_cipher_algo_info (OID_PKCS12_PBE_3DES_SHA1, 
			                                     GCRYCTL_TEST_ALGO, NULL, 0), NULL);

	/* The encryption algorithm */
	if(!gkr_pkix_asn1_write_oid (asn, "encryptionAlgorithm.algorithm", 
	                             OID_PKCS12_PBE_3DES_SHA1))
		g_return_val_if_reached (NULL); 

	/* Randomize some input for the password based secret */
	iterations = 1000 + (int) (1000.0 * rand () / (RAND_MAX + 1.0));
	gcry_create_nonce (salt, sizeof (salt));

	/* Allocate space for the key and iv */
	n_key = gcry_cipher_get_algo_keylen (GCRY_CIPHER_3DES);
	*n_block = gcry_cipher_get_algo_blklen (GCRY_MD_SHA1);
	g_return_val_if_fail (n_key && *n_block, NULL);
		
	if (!gkr_crypto_generate_symkey_pkcs12 (GCRY_CIPHER_3DES, GCRY_MD_SHA1, 
	                                        password, salt, sizeof (salt),
	                                        iterations, &key, &iv))
		g_return_val_if_reached (NULL);

	/* Now write out the parameters */	
	res = asn1_create_element (gkr_pkix_asn1_get_pkix_asn1type (),
	                           "PKIX1.pkcs-12-PbeParams", &asn1_params);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	if (!gkr_pkix_asn1_write_value (asn1_params, "salt", salt, sizeof (salt)))
		g_return_val_if_reached (NULL);
	if (!gkr_pkix_asn1_write_uint (asn1_params, "iterations", iterations))
		g_return_val_if_reached (NULL);
	portion = gkr_pkix_asn1_encode (asn1_params, "", &n_portion, NULL);
	g_return_val_if_fail (portion, NULL); 
	
	if (!gkr_pkix_asn1_write_value (asn, "encryptionAlgorithm.parameters", portion, n_portion))
		g_return_val_if_reached (NULL);
	g_free (portion);
	
	/* Now make a cipher that matches what we wrote out */
	gcry = gcry_cipher_open (&cih, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	g_return_val_if_fail (cih, NULL);
	
	gcry_cipher_setiv (cih, iv, *n_block);
	gcry_cipher_setkey (cih, key, n_key);
	
	gkr_secure_free (iv);
	gkr_secure_free (key);
	asn1_delete_structure (&asn1_params);
	
	return cih;
}

static guchar*
encode_pkcs8_private_key (gcry_sexp_t skey, gsize *n_data)
{
	ASN1_TYPE asn;
	int res, algorithm;
	gboolean is_priv;
	GQuark oid;
	guchar *params, *key, *data;
	gsize n_params, n_key;
	
	init_quarks ();

	/* Parse and check that the key is for real */
	if (!gkr_crypto_skey_parse (skey, &algorithm, &is_priv, NULL))
		g_return_val_if_reached (NULL);
	g_return_val_if_fail (is_priv == TRUE, NULL);
	
	res = asn1_create_element (gkr_pkix_asn1_get_pkix_asn1type (), 
	                           "PKIX1.pkcs-8-PrivateKeyInfo", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	/* Write out the version */
	if (!gkr_pkix_asn1_write_uint (asn, "version", 1))
		g_return_val_if_reached (NULL);
	
	/* Per algorithm differences */
	switch (algorithm)
	{
	/* RSA gets encoded in a standard simple way */
	case GCRY_PK_RSA:
		oid = OID_PKIX1_RSA;
		params = NULL;
		n_params = 0;
		key = gkr_pkix_der_write_private_key_rsa (skey, &n_key);
		break;
		
	/* DSA gets incoded with the params seperate */
	case GCRY_PK_DSA:
		oid = OID_PKIX1_DSA;
		key = gkr_pkix_der_write_private_key_dsa_part (skey, &n_key);
		params = gkr_pkix_der_write_private_key_dsa_params (skey, &n_params);
		break;
		
	default:
		g_warning ("trying to serialize unsupported private key algorithm: %d", algorithm);
		return NULL;
	};
	
	/* Write out the algorithm */
	if (!gkr_pkix_asn1_write_oid (asn, "privateKeyAlgorithm.algorithm", oid))
		g_return_val_if_reached (NULL);

	/* Write out the parameters */
	if (!gkr_pkix_asn1_write_value (asn, "privateKeyAlgorithm.parameters", params, n_params))
		g_return_val_if_reached (NULL);
	gkr_secure_free (params);
	
	/* Write out the key portion */
	if (!gkr_pkix_asn1_write_value (asn, "privateKey", key, n_key))
		g_return_val_if_reached (NULL);
	gkr_secure_free (key);
	
	/* Add an empty attributes field */
	if (!gkr_pkix_asn1_write_value (asn, "attributes", NULL, 0))
		g_return_val_if_reached (NULL);
	
	data = gkr_pkix_asn1_encode (asn, "", n_data, NULL);
	g_return_val_if_fail (data, NULL); 
	
	asn1_delete_structure (&asn);
	
	return data;
}

guchar*
gkr_pkix_serialize_private_key_pkcs8 (gcry_sexp_t skey, const gchar *password, 
                                      gsize *n_data)
{
	gcry_error_t gcry;
	gcry_cipher_hd_t cih;
	ASN1_TYPE asn;
	int res;
	guchar *key, *data; 
	gsize n_key, block = 0;

	/* Encode the key in normal pkcs8 fashion */
	key = encode_pkcs8_private_key (skey, &n_key);
	
	/* If no encryption then just return that */
	if(!password || !password[0]) {
		*n_data = n_key;
		return key;
	}
	
	res = asn1_create_element (gkr_pkix_asn1_get_pkix_asn1type (), 
	                           "PKIX1.pkcs-8-EncryptedPrivateKeyInfo", &asn);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	/* Create a and write out a cipher used for encryption */
	cih = prepare_and_encode_pkcs8_cipher (asn, password, &block);
	g_return_val_if_fail (cih, NULL);
	
	/* Pad the block of data */
	if(block > 1) {
		gsize pad;
		guchar *padded;
		
		pad = block - (n_key % block);
		if (pad == 0)
			pad = block;
		padded = g_realloc (key, n_key + pad);
		memset (padded + n_key, pad, pad);
		key = padded;
		n_key += pad;
	}
	
	gcry = gcry_cipher_encrypt (cih, key, n_key, NULL, 0);
	g_return_val_if_fail (gcry == 0, NULL);
	
	gcry_cipher_close (cih);
	
	res = asn1_write_value (asn, "encryptedData", key, n_key);
	g_return_val_if_fail (res == ASN1_SUCCESS, NULL);
	
	data = gkr_pkix_asn1_encode (asn, "", n_data, NULL);
	g_return_val_if_fail (data, NULL); 

	asn1_delete_structure (&asn);
	
	return data;
}
