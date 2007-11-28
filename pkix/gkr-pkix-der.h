#ifndef GKRPKIXDER_H_
#define GKRPKIXDER_H_

#include <glib.h>
#include <gcrypt.h>

#include "gkr-pkix-parser.h"

/* -----------------------------------------------------------------------------
 * PRIVATE KEYS 
 */
 
GkrParseResult  gkr_pkix_der_read_private_key_rsa       (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrParseResult  gkr_pkix_der_read_private_key_dsa       (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrParseResult  gkr_pkix_der_read_private_key_dsa_parts (const guchar *keydata, gsize n_keydata,
							 const guchar *params, gsize n_params, 
                                                         gcry_sexp_t *s_key);

GkrParseResult  gkr_pkix_der_read_private_key           (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);
                                                         
/* -----------------------------------------------------------------------------
 * PUBLIC KEYS
 */

GkrParseResult  gkr_pkix_der_read_public_key_rsa        (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrParseResult  gkr_pkix_der_read_public_key_dsa        (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

GkrParseResult  gkr_pkix_der_read_public_key            (const guchar *data, gsize n_data, 
                                                         gcry_sexp_t *s_key);

guchar*         gkr_pkix_der_write_public_key_rsa       (gcry_sexp_t s_key, gsize *len);

guchar*         gkr_pkix_der_write_public_key_dsa       (gcry_sexp_t s_key, gsize *len);

guchar*         gkr_pkix_der_write_public_key           (gcry_sexp_t s_key, gsize *len);

/* -----------------------------------------------------------------------------
 * CERTIFICATES
 */

GkrParseResult  gkr_pkix_der_read_certificate           (const guchar *data, gsize n_data, 
                                                         ASN1_TYPE *asn1);
                                                         
GkrParseResult  gkr_pkix_der_read_basic_constraints     (const guchar *data, gsize n_data, 
                                                         gboolean *is_ca, guint *path_len);

/* -----------------------------------------------------------------------------
 * CIPHERS
 */
 
GkrParseResult     gkr_pkix_der_read_cipher                 (GkrPkixParser *parser, GQuark oid_scheme, 
                                                             const gchar *password, const guchar *data, 
                                                             gsize n_data, gcry_cipher_hd_t *cih);

GkrParseResult     gkr_pkix_der_read_cipher_pkcs5_pbe       (GkrPkixParser *parser, int cipher_algo, 
                                                             int cipher_mode, int hash_algo, 
		                                             const gchar *password, const guchar *data, 
		                                             gsize n_data, gcry_cipher_hd_t *cih);

GkrParseResult     gkr_pkix_der_read_cipher_pkcs5_pbes2     (GkrPkixParser *parser, const gchar *password, 
                                                             const guchar *data, gsize n_data, 
                                                             gcry_cipher_hd_t *cih);

GkrParseResult     gkr_pkix_der_read_cipher_pkcs12_pbe      (GkrPkixParser *parser, int cipher_algo, 
                                                             int cipher_mode, const gchar *password,
                                                             const guchar *data, gsize n_data, 
                                                             gcry_cipher_hd_t *cih);

#endif /*GKRPKIXDER_H_*/
