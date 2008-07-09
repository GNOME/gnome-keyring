#ifndef GKRPKIXSERIALIZE_H_
#define GKRPKIXSERIALIZE_H_

#include <glib.h>

#include <gcrypt.h>
#include <libtasn1.h>

gboolean          gkr_pkix_serialize_to_location        (GQuark type, gpointer what, 
                                                         const gchar *password, 
                                                         GQuark location, GError **err);

guchar*           gkr_pkix_serialize_to_data            (GQuark type, gpointer what, 
                                                         const gchar *password, 
                                                         gsize *n_data);

const gchar*      gkr_pkix_serialize_get_extension      (GQuark type);

guchar*           gkr_pkix_serialize_certificate        (ASN1_TYPE asn, gsize *n_data);

guchar*           gkr_pkix_serialize_public_key         (gcry_sexp_t skey, gsize *n_data);

guchar*           gkr_pkix_serialize_private_key_pkcs8  (gcry_sexp_t skey, const gchar *password, 
                                                         gsize *n_data);

#endif /*GKRPKIXSERIALIZE_H_*/
