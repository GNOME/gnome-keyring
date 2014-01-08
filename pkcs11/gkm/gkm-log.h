/*
 * gnome-keyring
 *
 * Copyright (C) 2008 Stefan Walter
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

#ifndef GKM_LOG_H_
#define GKM_LOG_H_

#include <glib.h>

#include "pkcs11/pkcs11.h"

const gchar*          gkm_log_rv                                  (CK_RV rv);

const gchar*          gkm_log_attr_type                           (CK_ATTRIBUTE_TYPE type);

#endif /* GKM_LOG_H_ */
