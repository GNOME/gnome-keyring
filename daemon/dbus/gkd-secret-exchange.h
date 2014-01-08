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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __GKD_SECRET_EXCHANGE_H__
#define __GKD_SECRET_EXCHANGE_H__

#include <glib-object.h>

#include "gkd-secret-prompt.h"
#include "gkd-secret-types.h"

#define GKD_TYPE_SECRET_EXCHANGE               (gkd_secret_exchange_get_type ())
#define GKD_SECRET_EXCHANGE(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKD_TYPE_SECRET_EXCHANGE, GkdSecretExchange))
#define GKD_SECRET_EXCHANGE_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKD_TYPE_SECRET_EXCHANGE, GkdSecretExchangeClass))
#define GKD_IS_SECRET_EXCHANGE(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKD_TYPE_SECRET_EXCHANGE))
#define GKD_IS_SECRET_EXCHANGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKD_TYPE_SECRET_EXCHANGE))
#define GKD_SECRET_EXCHANGE_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKD_TYPE_SECRET_EXCHANGE, GkdSecretExchangeClass))

typedef struct _GkdSecretExchangeClass GkdSecretExchangeClass;

GType               gkd_secret_exchange_get_type              (void) G_GNUC_CONST;

GkdSecretExchange * gkd_secret_exchange_new                   (GkdSecretService *service,
                                                               const gchar *caller);

GkdSecretSecret *   gkd_secret_exchange_take_last_secret      (GkdSecretExchange *self);

#endif /* __GKD_SECRET_EXCHANGE_H__ */
