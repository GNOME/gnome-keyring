/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Collabora Ltd
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

#ifndef EGG_BYTE_ARRAY_H_
#define EGG_BYTE_ARRAY_H_

#include <glib.h>

guint      egg_byte_array_hash    (gconstpointer v);

gboolean   egg_byte_array_equal   (gconstpointer v1, gconstpointer v2);

#endif /* EGG_BYTE_ARRAY_H_ */
