/*
 * gnome-keyring
 *
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

#ifndef __GCR_SECRET_EXCHANGE_H__
#define __GCR_SECRET_EXCHANGE_H__

#include "gcr.h"

#include <glib-object.h>

G_BEGIN_DECLS

#define GCR_TYPE_SECRET_EXCHANGE               (gcr_secret_exchange_get_type ())
#define GCR_SECRET_EXCHANGE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_SECRET_EXCHANGE, GcrSecretExchange))
#define GCR_SECRET_EXCHANGE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_SECRET_EXCHANGE, GcrSecretExchangeClass))
#define GCR_IS_SECRET_EXCHANGE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_SECRET_EXCHANGE))
#define GCR_IS_SECRET_EXCHANGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_SECRET_EXCHANGE))
#define GCR_SECRET_EXCHANGE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_SECRET_EXCHANGE, GcrSecretExchangeClass))

typedef struct _GcrSecretExchange GcrSecretExchange;
typedef struct _GcrSecretExchangeClass GcrSecretExchangeClass;
typedef struct _GcrSecretExchangePrivate GcrSecretExchangePrivate;

struct _GcrSecretExchange {
	GObject parent;

	/*< private >*/
	GcrSecretExchangePrivate *pv;
};

struct _GcrSecretExchangeClass {
	GObjectClass parent_class;
};

/* Caller side functions */

GType               gcr_secret_exchange_get_type        (void);

GcrSecretExchange * gcr_secret_exchange_new             (void);

gchar *             gcr_secret_exchange_begin           (GcrSecretExchange *self);

gboolean            gcr_secret_exchange_receive         (GcrSecretExchange *self,
                                                         const gchar *exchange);

gchar *             gcr_secret_exchange_send            (GcrSecretExchange *self,
                                                         const gchar *secret,
                                                         gssize secret_len);

const gchar *       gcr_secret_exchange_get_secret      (GcrSecretExchange *self,
                                                         gsize *secret_len);

G_END_DECLS

#endif /* __GCR_SECRET_EXCHANGE_H__ */
