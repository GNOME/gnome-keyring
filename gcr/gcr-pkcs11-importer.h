/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#if !defined (__GCR_H_INSIDE__) && !defined (GCR_COMPILATION)
#error "Only <gcr/gcr.h> can be included directly."
#endif

#ifndef __GCR_PKCS11_IMPORTER_H__
#define __GCR_PKCS11_IMPORTER_H__

#include "gcr-importer.h"

G_BEGIN_DECLS

#define GCR_TYPE_PKCS11_IMPORTER               (_gcr_pkcs11_importer_get_type ())
#define GCR_PKCS11_IMPORTER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_PKCS11_IMPORTER, GcrPkcs11Importer))
#define GCR_PKCS11_IMPORTER_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_PKCS11_IMPORTER, GcrPkcs11ImporterClass))
#define GCR_IS_PKCS11_IMPORTER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_PKCS11_IMPORTER))
#define GCR_IS_PKCS11_IMPORTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_PKCS11_IMPORTER))
#define GCR_PKCS11_IMPORTER_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_PKCS11_IMPORTER, GcrPkcs11ImporterClass))

typedef struct _GcrPkcs11Importer GcrPkcs11Importer;
typedef struct _GcrPkcs11ImporterClass GcrPkcs11ImporterClass;
typedef struct _GcrPkcs11ImporterPrivate GcrPkcs11ImporterPrivate;

struct _GcrPkcs11Importer {
	GObject parent;

	/*< private >*/
	GcrPkcs11ImporterPrivate *pv;
};

struct _GcrPkcs11ImporterClass {
	GObjectClass parent_class;
};

GType                     _gcr_pkcs11_importer_get_type        (void);

GcrImporter *             _gcr_pkcs11_importer_new             (GckSlot *slot);

void                      _gcr_pkcs11_importer_queue           (GcrPkcs11Importer *self,
                                                                GckAttributes *attrs);

GckSlot *                 _gcr_pkcs11_importer_get_slot        (GcrPkcs11Importer *self);

GList *                   _gcr_pkcs11_importer_get_imported    (GcrPkcs11Importer *self);

G_END_DECLS

#endif /* __GCR_PKCS11_IMPORTER_H__ */
