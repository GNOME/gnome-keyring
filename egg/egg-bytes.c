/*
 * Copyright © 2009, 2010 Codethink Limited
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
 */

#include "config.h"

#include "egg-bytes.h"

#include <glib.h>

#include <string.h>

struct _EggBytes
{
  gconstpointer data;
  gsize size;
  gint ref_count;
  GDestroyNotify free_func;
  gpointer user_data;
};

/**
 * egg_bytes_new:
 * @data: (array length=size): the data to be used for the bytes
 * @size: the size of @data
 *
 * Creates a new #EggBytes from @data.
 *
 * @data is copied.
 *
 * Returns: (transfer full): a new #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_new (gconstpointer data,
             gsize         size)
{
  return egg_bytes_new_take (g_memdup (data, size), size);
}

/**
 * egg_bytes_new_take:
 * @data: (transfer full) (array length=size): the data to be used for the bytes
 * @size: the size of @data
 *
 * Creates a new #EggBytes from @data.
 *
 * After this call, @data belongs to the bytes and may no longer be
 * modified by the caller.  g_free() will be called on @data when the
 * bytes is no longer in use. Because of this @data must have been created by
 * a call to g_malloc(), g_malloc0() or g_realloc() or by one of the many
 * functions that wrap these calls (such as g_new(), g_strdup(), etc).
 *
 * Returns: (transfer full): a new #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_new_take (gpointer data,
                  gsize    size)
{
  return egg_bytes_new_with_free_func (data, size, g_free, data);
}


/**
 * egg_bytes_new_static:
 * @data: (array length=size): the data to be used for the bytes
 * @size: the size of @data
 *
 * Creates a new #EggBytes from static data.
 *
 * @data must be static (ie: never modified or freed).
 *
 * Returns: (transfer full): a new #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_new_static (gconstpointer data,
                    gsize         size)
{
  return egg_bytes_new_with_free_func (data, size, NULL, NULL);
}

/**
 * egg_bytes_new_with_free_func:
 * @data: (array length=size): the data to be used for the bytes
 * @size: the size of @data
 * @free_func: the function to call to release the data
 * @user_data: data to pass to @free_func
 *
 * Creates a #EggBytes from @data.
 *
 * When the last reference is dropped, @free_func will be called with the
 * @user_data argument.
 *
 * @data must not be modified after this call is made until @free_func has
 * been called to indicate that the bytes is no longer in use.
 *
 * Returns: (transfer full): a new #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_new_with_free_func (gconstpointer  data,
                            gsize          size,
                            GDestroyNotify free_func,
                            gpointer       user_data)
{
  EggBytes *bytes;

  bytes = g_slice_new (EggBytes);
  bytes->data = data;
  bytes->size = size;
  bytes->free_func = free_func;
  bytes->user_data = user_data;
  bytes->ref_count = 1;

  return (EggBytes *)bytes;
}

/**
 * egg_bytes_new_from_bytes:
 * @bytes: a #EggBytes
 * @offset: offset which subsection starts at
 * @length: length of subsucsection
 *
 * Creates a #EggBytes which is a subsection of another #EggBytes.
 *
 * A reference to @bytes will be held by the newly created #EggBytes until
 * the byte data is no longer needed.
 *
 * Returns: (transfer full): a new #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_new_from_bytes (EggBytes  *bytes,
                        goffset  offset,
                        gsize    length)
{
  g_return_val_if_fail (bytes != NULL, NULL);
  g_return_val_if_fail (offset <= bytes->size, NULL);
  g_return_val_if_fail (offset + length <= bytes->size, NULL);

  return egg_bytes_new_with_free_func ((gchar *)bytes->data + offset, length,
                                     egg_bytes_unref, egg_bytes_ref (bytes));
}

/**
 * egg_bytes_get_data:
 * @bytes: a #EggBytes
 *
 * Get the byte data in the #EggBytes. This data should not be modified.
 *
 * This function will always return the same pointer for a given #EggBytes.
 *
 * Returns: a pointer to the byte data
 *
 * Since: 2.32
 */
gconstpointer
egg_bytes_get_data (EggBytes *bytes)
{
  g_return_val_if_fail (bytes != NULL, NULL);
  return bytes->data;
}

/**
 * egg_bytes_get_size:
 * @bytes: a #EggBytes
 *
 * Get the size of the byte data in the #EggBytes.
 *
 * This function will always return the same value for a given #EggBytes.
 *
 * Returns: the size
 *
 * Since: 2.32
 */
gsize
egg_bytes_get_size (EggBytes *bytes)
{
  g_return_val_if_fail (bytes != NULL, 0);
  return bytes->size;
}


/**
 * egg_bytes_ref:
 * @bytes: a #EggBytes
 *
 * Increase the reference count on @bytes.
 *
 * Returns: (transfer full): the #EggBytes
 *
 * Since: 2.32
 */
EggBytes *
egg_bytes_ref (EggBytes *bytes)
{
  g_return_val_if_fail (bytes != NULL, NULL);

  g_atomic_int_inc (&bytes->ref_count);

  return bytes;
}

/**
 * egg_bytes_unref:
 * @bytes: (transfer full) (type GLib.Bytes): a #EggBytes
 *
 * Releases a reference on @bytes.  This may result in the bytes being
 * freed.
 *
 * Since: 2.32
 */
void
egg_bytes_unref (gpointer bytes)
{
  EggBytes *bytes_ = bytes;

  g_return_if_fail (bytes_ != NULL);

  if (g_atomic_int_dec_and_test (&bytes_->ref_count))
    {
      if (bytes_->free_func != NULL)
        bytes_->free_func (bytes_->user_data);
      g_slice_free (EggBytes, bytes);
    }
}

/**
 * egg_bytes_equal:
 * @bytes1: (type GLib.Bytes): a pointer to a #EggBytes
 * @bytes2: (type GLib.Bytes): a pointer to a #EggBytes to compare with @bytes1
 *
 * Compares the two #EggBytes values being pointed to and returns
 * %TRUE if they are equal.
 *
 * This function can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using non-%NULL #EggBytes pointers as keys in a #GHashTable.
 *
 * Returns: %TRUE if the two keys match.
 *
 * Since: 2.32
 */
gboolean
egg_bytes_equal (gconstpointer bytes1,
               gconstpointer bytes2)
{
  const EggBytes *b1 = bytes1;
  const EggBytes *b2 = bytes2;

  g_return_val_if_fail (bytes1 != NULL, FALSE);
  g_return_val_if_fail (bytes2 != NULL, FALSE);

  return b1->size == b2->size &&
         memcmp (b1->data, b2->data, b1->size) == 0;
}

/**
 * egg_bytes_hash:
 * @bytes: (type GLib.Bytes): a pointer to a #EggBytes key
 *
 * Creates an integer hash code for the byte data in the #EggBytes.
 *
 * This function can be passed to g_hash_table_new() as the @key_equal_func
 * parameter, when using non-%NULL #EggBytes pointers as keys in a #GHashTable.
 *
 * Returns: a hash value corresponding to the key.
 *
 * Since: 2.32
 */
guint
egg_bytes_hash (gconstpointer bytes)
{
  const EggBytes *a = bytes;
  const signed char *p, *e;
  guint32 h = 5381;

  g_return_val_if_fail (bytes != NULL, 0);

  for (p = (signed char *)a->data, e = (signed char *)a->data + a->size; p != e; p++)
    h = (h << 5) + h + *p;

  return h;
}

/**
 * egg_bytes_compare:
 * @bytes1: (type GLib.Bytes): a pointer to a #EggBytes
 * @bytes2: (type GLib.Bytes): a pointer to a #EggBytes to compare with @bytes1
 *
 * Compares the two #EggBytes values.
 *
 * This function can be passed to g_tree_new() when using non-%NULL #EggBytes
 * pointers as keys in a #GTree.
 *
 * Returns: a negative value if bytes2 is lesser, a positive value if bytes2 is
 *          greater, and zero if bytes2 is equal to bytes1
 *
 * Since: 2.32
 */
gint
egg_bytes_compare (gconstpointer bytes1,
                 gconstpointer bytes2)
{
  const EggBytes *b1 = bytes1;
  const EggBytes *b2 = bytes2;
  gint ret;

  g_return_val_if_fail (bytes1 != NULL, 0);
  g_return_val_if_fail (bytes2 != NULL, 0);

  ret = memcmp (b1->data, b2->data, MIN (b1->size, b2->size));
  if (ret == 0 && b1->size != b2->size)
      ret = b1->size < b2->size ? -1 : 1;
  return ret;
}

/**
 * egg_bytes_unref_to_array:
 * @bytes: (transfer full): a #EggBytes
 *
 * Unreferences the bytes, and returns a new mutable #GByteArray containing
 * the same byte data.
 *
 * As an optimization, the byte data is transferred to the array without copying
 * if: this was the last reference to bytes and bytes was created with
 * egg_bytes_new(), egg_bytes_new_take() or g_byte_array_free_to_bytes(). In all
 * other cases the data is copied.
 *
 * Returns: (transfer full): a new mutable #GByteArray containing the same byte data
 *
 * Since: 2.32
 */
GByteArray *
egg_bytes_unref_to_array (EggBytes *bytes)
{
  GByteArray *result = NULL;
#if 0
  gpointer data;
  gsize size;
#endif

  g_return_val_if_fail (bytes != NULL, NULL);

#if 0
  data = egg_bytes_try_steal_and_unref (bytes, NULL, &size);
  if (data != NULL)
    {
      /*
       * Optimal path: if this is was the last reference, then we can have
       * the GByteArray assume the data from this EggBytes without copying.
       */
      result = g_byte_array_new_take (data, size);
    }
  else
#endif
    {
      /*
       * Copy: Non g_malloc (or compatible) allocator, or static memory,
       * so we have to copy, and then unref.
       */
      result = g_byte_array_append (g_byte_array_new (), bytes->data, bytes->size);
      egg_bytes_unref (bytes);
    }

  return result;
}

/*
 * The behavior of this function with regards to references cannot be easily
 * modeled by most gobject-introspection consumers, so we use (skip).
 */

/**
 * egg_bytes_try_steal_and_unref: (skip)
 * @bytes: a #EggBytes
 * @free_func: the function data is freed with, or %NULL for default
 * @size: location to return the length of the data
 *
 * This is an advanced function, and seldom used.
 *
 * Try to take ownership of the data in the byte array. This is only successful
 * if this is the last reference and @free_func matches the function that would
 * have been used to free the data. This is to demonstrate that the caller
 * is aware of the how the data in the #EggBytes was allocated. If %NULL is passed
 * for @free_func this represents the standard Glib allocation routines.
 *
 * You should use %NULL instead of passing g_free() for @free_func. This is
 * because the actual address of g_free() varies depending on how the calling
 * application and library was linked.
 *
 * If the attempt to take ownership of the byte data is successful according to
 * the above criteria, then the data is returned and @size is set to the length
 * of the data. The #EggBytes is unreferenced and is no longer valid.
 *
 * If the attempt to take ownership of the byte data is unsuccessful, %NULL is
 * returned. The #EggBytes is not unreferenced, and the caller must unreference
 * the #EggBytes elsewhere.
 *
 * It is always incorrect to ignore the return value from this function.
 *
 * Returns: the stolen data, or %NULL if attempt failed
 *
 * Since: 2.32
 */
gpointer
egg_bytes_try_steal_and_unref (EggBytes         *bytes,
                             GDestroyNotify  free_func,
                             gsize          *size)
{
  gpointer result;

  g_return_val_if_fail (bytes != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);

  if (free_func == NULL)
    free_func = g_free;
  if (bytes->free_func != free_func)
    return NULL;

  /* Are we the only reference? */
  if (g_atomic_int_get (&bytes->ref_count) == 1)
    {
      *size = bytes->size;
      result = (gpointer)bytes->data;
      g_slice_free (EggBytes, bytes);
      return result;
    }

  return NULL;
}
