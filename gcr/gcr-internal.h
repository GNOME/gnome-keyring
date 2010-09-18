#ifndef GCR_INTERNAL_H_
#define GCR_INTERNAL_H_

#include "gcr.h"

#include <glib.h>

#include <gck/gck.h>

void              _gcr_initialize                  (void);

GList*            _gcr_get_pkcs11_modules          (void);

GckSlot*          _gcr_slot_for_storing_trust      (GError **error);

#ifdef WITH_TESTS

void              _gcr_set_test_pkcs11_modules     (GList *modules);

void              _gcr_set_test_trust_slot         (const gchar *uri);

#endif

#endif /* GCR_INTERNAL_H_ */
