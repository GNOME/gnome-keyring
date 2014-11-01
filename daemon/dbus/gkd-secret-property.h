/*
 * gnome-keyring
 *
 * Copyright (C) 2009 Stefan Walter
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
 */

#ifndef __GKD_SECRET_PROPERTY_H__
#define __GKD_SECRET_PROPERTY_H__

#include "gkd-secret-types.h"

#include <gck/gck.h>

#include <gio/gio.h>

gboolean               gkd_secret_property_get_type               (const gchar *property,
                                                                   CK_ATTRIBUTE_TYPE *type);

GVariant *             gkd_secret_property_append_variant         (const GckAttribute *attr);

GVariant *             gkd_secret_property_append_all             (GckAttributes *attrs);

gboolean               gkd_secret_property_parse_variant          (GVariant *variant,
                                                                   const gchar *property,
                                                                   GckBuilder *builder);

gboolean               gkd_secret_property_parse_fields           (GVariant *variant,
                                                                   GckBuilder *builder);

gboolean               gkd_secret_property_parse_all              (GVariant *variant,
                                                                   const gchar *interface,
                                                                   GckBuilder *builder);

#endif /* __GKD_SECRET_PROPERTY_H__ */
