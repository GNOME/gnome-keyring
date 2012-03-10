/*
 * Copyright © 2009, 2010 Codethink Limited
 * Copyright © 2011 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the licence, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Ryan Lortie <desrt@desrt.ca>
 *         Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __EGG_BYTES_H__
#define __EGG_BYTES_H__

#include <glib.h>

/**
 * EggBytes:
 *
 * A simple refcounted data type representing an immutable byte sequence
 * from an unspecified origin.
 *
 * The purpose of a #EggBytes is to keep the memory region that it holds
 * alive for as long as anyone holds a reference to the bytes.  When
 * the last reference count is dropped, the memory is released. Multiple
 * unrelated callers can use byte data in the #EggBytes without coordinating
 * their activities, resting assured that the byte data will not change or
 * move while they hold a reference.
 *
 * A #EggBytes can come from many different origins that may have
 * different procedures for freeing the memory region.  Examples are
 * memory from g_malloc(), from memory slices, from a #GMappedFile or
 * memory from other allocators.
 *
 * #EggBytes work well as keys in #GHashTable. Use egg_bytes_equal() and
 * egg_bytes_hash() as parameters to g_hash_table_new() or g_hash_table_new_full().
 * #EggBytes can also be used as keys in a #GTree by passing the egg_bytes_compare()
 * function to g_tree_new().
 *
 * The data pointed to by this bytes must not be modified. For a mutable
 * array of bytes see #GByteArray. Use egg_bytes_unref_to_array() to create a
 * mutable array for a #EggBytes sequence. To create an immutable #EggBytes from
 * a mutable #GByteArray, use the g_byte_array_free_to_bytes() function.
 *
 * Since: 2.32
 **/

typedef struct _EggBytes EggBytes;

EggBytes *        egg_bytes_new                     (gconstpointer   data,
                                                 gsize           size);

EggBytes *        egg_bytes_new_take                (gpointer        data,
                                                 gsize           size);

EggBytes *        egg_bytes_new_static              (gconstpointer   data,
                                                 gsize           size);

EggBytes *        egg_bytes_new_with_free_func      (gconstpointer   data,
                                                 gsize           size,
                                                 GDestroyNotify  free_func,
                                                 gpointer        user_data);

EggBytes *        egg_bytes_new_from_bytes          (EggBytes         *bytes,
                                                 goffset         offset,
                                                 gsize           length);

gconstpointer   egg_bytes_get_data                (EggBytes         *bytes);

gsize           egg_bytes_get_size                (EggBytes         *bytes);

EggBytes *        egg_bytes_ref                     (EggBytes         *bytes);

void            egg_bytes_unref                   (gpointer        bytes);

GByteArray *    egg_bytes_unref_to_array          (EggBytes         *bytes);

gpointer        egg_bytes_try_steal_and_unref     (EggBytes         *bytes,
                                                 GDestroyNotify  free_func,
                                                 gsize          *size);

guint           egg_bytes_hash                    (gconstpointer   bytes);

gboolean        egg_bytes_equal                   (gconstpointer   bytes1,
                                                 gconstpointer   bytes2);

gint            egg_bytes_compare                 (gconstpointer   bytes1,
                                                 gconstpointer   bytes2);

#endif /* __EGG_BYTES_H__ */
