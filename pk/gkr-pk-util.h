#ifndef GKRPKUTIL_H_
#define GKRPKUTIL_H_

#include <glib.h>
#include <gcrypt.h>

#include "common/gkr-unique.h"

#include "pkcs11/pkcs11.h"

typedef enum {
	GKR_PK_DATA_UNKNOWN = 0,
	GKR_PK_DATA_BOOL,
	GKR_PK_DATA_ULONG,
	GKR_PK_DATA_DATE,
	GKR_PK_DATA_BYTES
} GkrPkDataType;

GkrPkDataType      gkr_pk_attribute_data_type             (CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE_PTR   gkr_pk_attribute_new                   (CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE_PTR   gkr_pk_attribute_dup                   (const CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_free                  (gpointer attr);

void               gkr_pk_attribute_copy                  (CK_ATTRIBUTE_PTR dest, const CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_steal                 (CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_clear                 (CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_set_invalid           (CK_ATTRIBUTE_PTR attr);

void               gkr_pk_attribute_set_data              (CK_ATTRIBUTE_PTR attr, gconstpointer value,
                                                           gsize n_value);

void               gkr_pk_attribute_set_string            (CK_ATTRIBUTE_PTR attr, const gchar *str);

void               gkr_pk_attribute_set_unique            (CK_ATTRIBUTE_PTR attr, gkrconstunique uni);

void               gkr_pk_attribute_set_boolean           (CK_ATTRIBUTE_PTR attr, gboolean value);

void               gkr_pk_attribute_set_date              (CK_ATTRIBUTE_PTR attr, time_t time);

void               gkr_pk_attribute_set_uint              (CK_ATTRIBUTE_PTR attr, guint value);

void               gkr_pk_attribute_set_mpi               (CK_ATTRIBUTE_PTR attr, gcry_mpi_t mpi);

#define            gkr_pk_attribute_array_new()           (g_array_new (0, 1, sizeof (CK_ATTRIBUTE)))
 
gpointer           gkr_pk_attribute_array_find            (const GArray* attrs, CK_ATTRIBUTE_TYPE type);

void               gkr_pk_attribute_array_free            (GArray *attrs);


#endif /*GKRPKUTIL_H_*/
