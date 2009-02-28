#ifndef GCKSSHOPENSSH_H_
#define GCKSSHOPENSSH_H_

#include <glib.h>

#include <gcrypt.h>

#include "gck/gck-data-types.h"

GckDataResult         gck_ssh_openssh_parse_public_key                   (const guchar *data, 
                                                                          gsize n_data,
                                                                          gcry_sexp_t *sexp, 
                                                                          gchar **comment);

GckDataResult         gck_ssh_openssh_parse_private_key                  (const guchar *data, 
                                                                          gsize n_data,
                                                                          const gchar *password,
                                                                          gssize n_password,
                                                                          gcry_sexp_t *sexp);

gchar*                gck_ssh_openssh_digest_private_key                 (const guchar *data,
                                                                          gsize n_data);

#endif /* GCKSSHOPENSSH_H_ */
