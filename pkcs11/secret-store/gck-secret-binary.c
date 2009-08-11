/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-secret-binary.c - The binary encrypted format of a keyring

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007, 2009 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Alexander Larsson <alexl@redhat.com>
   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gck-secret-binary.h"
#include "gck-secret-collection.h"
#include "gck-secret-compat.h"
#include "gck-secret-fields.h"
#include "gck-secret-item.h"

#include "egg/egg-buffer.h"
#include "egg/egg-symkey.h"
#include "egg/egg-secure-memory.h"

#include "gck/gck-secret.h"

#include <glib.h>

#include <gcrypt.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* -----------------------------------------------------------------------------
 * DECLARATIONS
 */

#define LOCK_ON_IDLE_FLAG (1<<0)

typedef struct {
	/* unencrypted: */
	guint32 id;
	gchar *identifier;
	guint32 type;

	/* encrypted: */
	char *display_name;
	char *secret;
	time_t ctime;
	time_t mtime;
	GHashTable *attributes;
	GList *acl;
} ItemInfo;

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

/* -----------------------------------------------------------------------------
 * BUFFER UTILITY FUNCTIONS
 */

static gboolean
buffer_get_bytes (EggBuffer *buffer, gsize offset, gsize *next_offset, 
                  guchar *out, gsize n_bytes)
{
	if (buffer->len < n_bytes || offset > buffer->len - n_bytes) 
		return FALSE;
	memcpy (out, buffer->buf + offset, n_bytes);
	*next_offset = offset + n_bytes;
	return TRUE;
}

static gboolean
buffer_add_time (EggBuffer *buffer, glong time)
{
	guint64 val = time;
	return egg_buffer_add_uint32 (buffer, ((val >> 32) & 0xffffffff)) && 
	       egg_buffer_add_uint32 (buffer, (val & 0xffffffff));
}

static gboolean
buffer_get_time (EggBuffer *buffer, gsize offset, gsize *next_offset, glong *time)
{
	guint32 a, b;
	guint64 val;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &a) || 
	    !egg_buffer_get_uint32 (buffer, offset, &offset, &b))
		return FALSE;

	val = ((guint64)a) << 32 | b;
	*next_offset = offset;
	*time = (time_t) val;
	return TRUE;
}

static gboolean
buffer_add_utf8_string (EggBuffer *buffer, const char *str)
{
	if (str && !g_utf8_validate (str, -1, NULL))
		return FALSE;
	return egg_buffer_add_string (buffer, str);
}

static gboolean
buffer_get_utf8_string (EggBuffer *buffer, gsize offset, gsize *next_offset,
                        char **str_ret)
{
	gsize len;
	char *str;
	
	if (!egg_buffer_get_string (buffer, offset, &offset, &str, 
	                            (EggBufferAllocator)g_realloc))
		return FALSE;
	len = str ? strlen (str) : 0;

	if (str != NULL) {
		if (!g_utf8_validate (str, len, NULL)) {
			g_free (str);
			return FALSE;
		}
	}

	if (next_offset != NULL) {
		*next_offset = offset;
	}
	if (str_ret != NULL) {
		*str_ret = str;
	} else {
		g_free (str);
	}
	return TRUE;
}

static gboolean
buffer_get_raw_secret (EggBuffer *buffer, gsize offset, gsize *next_offset,
                       guchar **secret, gsize *n_secret)
{
	const guchar* ptr;
	if (!egg_buffer_get_byte_array (buffer, offset, next_offset, &ptr, n_secret))
		return FALSE;

	if (ptr == NULL || *n_secret == 0) {
		*secret = NULL;
		*n_secret = 0;
		return TRUE;
	}

	*secret = egg_secure_alloc (*n_secret + 1);
	memcpy (*secret, ptr, *n_secret);
	(*secret)[*n_secret] = 0;
	return TRUE;
}

static void
buffer_add_attribute (EggBuffer *buffer, GHashTable *attributes, const gchar *key)
{
	guint32 number;
	
	buffer_add_utf8_string (buffer, key);
	
	/* 
	 * COMPATIBILITY:
	 * 
	 * Our new Secrets API doesn't support integer attributes. However, to have 
	 * compatibility with old keyring code reading this file, we need to set 
	 * the uint32 type attribute appropriately where expected. 
	 * 
	 * If there's an extra compat-uint32 attribute and the name of this attribute
	 * is contained in that list, then write as a uint32.
	 */
	
	/* Determine if it's a uint32 compatible value, and store as such if it is */
	if (gck_secret_fields_get_compat_uint32 (attributes, key, &number)) {
		egg_buffer_add_uint32 (buffer, 1);
		egg_buffer_add_uint32 (buffer, number);

	/* A normal string attribute */
	} else {
		egg_buffer_add_uint32 (buffer, 0);
		buffer_add_utf8_string (buffer, gck_secret_fields_get (attributes, key));
	}
}

static void
buffer_add_hashed_attribute (EggBuffer *buffer, GHashTable *attributes, const gchar *key)
{
	guint32 number;
	gchar *value;

	buffer_add_utf8_string (buffer, key);

	/* See comments in buffer_add_attribute. */

	/* Determine if it's a uint32 compatible value, and store as such if it is */
	if (gck_secret_fields_get_compat_hashed_uint32 (attributes, key, &number)) {
		egg_buffer_add_uint32 (buffer, 1);
		egg_buffer_add_uint32 (buffer, number);

	/* A standard string attribute */
	} else {
		if (!gck_secret_fields_get_compat_hashed_string (attributes, key, &value))
			g_return_if_reached ();
		egg_buffer_add_uint32 (buffer, 0);
		buffer_add_utf8_string (buffer, value);
		g_free (value);
	}
}

static gboolean
buffer_add_attributes (EggBuffer *buffer, GHashTable *attributes, gboolean hashed)
{
	GList *names, *l;
	
	g_assert (buffer);
	
	if (attributes == NULL) {
		egg_buffer_add_uint32 (buffer, 0);
	} else {
		names = gck_secret_fields_get_names (attributes);
		egg_buffer_add_uint32 (buffer, g_list_length (names));
		for (l = names; l; l = g_list_next (l)) {
			if (hashed)
				buffer_add_hashed_attribute (buffer, attributes, l->data);
			else
				buffer_add_attribute (buffer, attributes, l->data);
		}
		g_list_free (names);
	}
	
	return !egg_buffer_has_error (buffer);
}

static gboolean
buffer_get_attributes (EggBuffer *buffer, gsize offset, gsize *next_offset,
                       GHashTable **attributes_out, gboolean hashed)
{
	guint32 list_size;
	GHashTable *attributes;
	char *name;
	guint32 type;
	char *str;
	guint32 val;
	int i;

	attributes = NULL;
	
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &list_size))
		goto bail;

	attributes = gck_secret_fields_new ();
	for (i = 0; i < list_size; i++) {
		if (!buffer_get_utf8_string (buffer, offset, &offset, &name))
			goto bail;
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &type)) {
			g_free (name);
			goto bail;
		}
		switch (type) {
		case 0: /* A string */
			if (!buffer_get_utf8_string (buffer, offset, &offset, &str)) {
				g_free (name);
				goto bail;
			}
			if (hashed)
				gck_secret_fields_add_compat_hashed_string (attributes, name, str);
			else
				gck_secret_fields_add (attributes, name, str);
			g_free (name);
			g_free (str);
			break;
		case 1: /* A uint32 */
			if (!egg_buffer_get_uint32 (buffer, offset, &offset, &val)) {
				g_free (name);
				goto bail;
			}
			if (hashed)
				gck_secret_fields_add_compat_hashed_uint32 (attributes, name, val);
			else
				gck_secret_fields_add_compat_uint32 (attributes, name, val);
			g_free (name);
			break;
		default:
			g_free (name);
			goto bail;
		}
	}
	
	*attributes_out = attributes;
	*next_offset = offset;
	
	return TRUE;
	
bail:
	g_hash_table_unref (attributes);
	return FALSE;
}

static gboolean
convert_to_integer (const gchar *string, guint32 *result)
{
	gchar *end;
	*result = strtoul (string, &end, 10);
	return *end == 0;
}

/* -----------------------------------------------------------------------------
 * BINARY ENCRYPTED FILE FORMAT
 */

static gboolean
encrypt_buffer (EggBuffer *buffer, GckSecret *master,
		guchar salt[8], int iterations)
{
	const gchar *password;
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key, *iv;
	gsize n_password;
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	g_assert (16 == gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128));
	g_assert (16 == gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES128));
	
	password = gck_secret_get_password (master, &n_password);
	if (!egg_symkey_generate_simple (GCRY_CIPHER_AES128, GCRY_MD_SHA256, 
	                                 password, n_password, salt, 8, iterations, &key, &iv))
		return FALSE;

	gerr = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gerr) {
		g_warning ("couldn't create aes cipher context: %s", 
			   gcry_strerror (gerr));
		egg_secure_free (key);
		g_free (iv);
		return FALSE;
	}

	/* 16 = 128 bits */
	gerr = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (!gerr, FALSE);
	egg_secure_free (key);

	/* 16 = 128 bits */
	gerr = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (!gerr, FALSE);
	g_free (iv);

	for (pos = 0; pos < buffer->len; pos += 16) {
		/* In place encryption */
		gerr = gcry_cipher_encrypt (cih, buffer->buf + pos, 16, NULL, 0);
		g_return_val_if_fail (!gerr, FALSE);
	}

	gcry_cipher_close (cih);
	
	return TRUE;
}

static gboolean
decrypt_buffer (EggBuffer *buffer, GckSecret *master,
		guchar salt[8], int iterations)
{
	const gchar *password;
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key, *iv;
        gsize n_password;
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	g_assert (16 == gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128));
	g_assert (16 == gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES128));
	
	password = gck_secret_get_password (master, &n_password);
	if (!egg_symkey_generate_simple (GCRY_CIPHER_AES128, GCRY_MD_SHA256, 
	                                 password, n_password, salt, 8, iterations, &key, &iv))
		return FALSE;
	
	gerr = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gerr) {
		g_warning ("couldn't create aes cipher context: %s", 
			   gcry_strerror (gerr));
		egg_secure_free (key);
		g_free (iv);
		return FALSE;
	}

	/* 16 = 128 bits */
	gerr = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (!gerr, FALSE);
	egg_secure_free (key);

	/* 16 = 128 bits */
	gerr = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (!gerr, FALSE);
	g_free (iv);

	for (pos = 0; pos < buffer->len; pos += 16) {
		/* In place encryption */
		gerr = gcry_cipher_decrypt (cih, buffer->buf + pos, 16, NULL, 0);
		g_return_val_if_fail (!gerr, FALSE);
	}

	gcry_cipher_close (cih);
	
	return TRUE;
}

static gboolean
verify_decrypted_buffer (EggBuffer *buffer)
{
        guchar digest[16];
	
	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), 0);
	
	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, 
			     (guchar*)buffer->buf + 16, buffer->len - 16);
	
	return memcmp (buffer->buf, digest, 16) == 0;
}

static gboolean 
generate_acl_data (EggBuffer *buffer, GList *acl)
{
	GList *l;
	GckSecretAccess *ac;
	
	egg_buffer_add_uint32 (buffer, g_list_length (acl));

	for (l = acl; l != NULL; l = l->next) {
		ac = l->data;
		
		egg_buffer_add_uint32 (buffer, ac->types_allowed);
		if (!buffer_add_utf8_string (buffer, ac->display_name) || 
		    !buffer_add_utf8_string (buffer, ac->pathname))
			return FALSE;

		/* Reserved: */
		if (!buffer_add_utf8_string (buffer, NULL))
			return FALSE;

		egg_buffer_add_uint32 (buffer, 0);
	}
	
	return TRUE;
}

static gboolean
generate_encrypted_data (EggBuffer *buffer, GckSecretCollection *collection)
{
	GckSecretObject *obj;
	GckSecretItem *item;
	GList *items, *l;
	GHashTable *attributes;
	const gchar *label;
	GckSecret *secret;
	const gchar *password;
	gsize n_password;
	GList *acl;
	int i;
	
	/* Make sure we're using non-pageable memory */
	egg_buffer_set_allocator (buffer, egg_secure_realloc);
	
	items = gck_secret_collection_get_items (collection);
	for (l = items; l && !egg_buffer_has_error(buffer); l = g_list_next (l)) {
		item = GCK_SECRET_ITEM (l->data);
		obj = GCK_SECRET_OBJECT (l->data);
		
		label = gck_secret_object_get_label (obj);
		buffer_add_utf8_string (buffer, label);

		secret = gck_secret_item_get_secret (item);
		password = NULL;
		if (secret != NULL)
			password = gck_secret_get_password (secret, &n_password);
		/* TODO: Need to support binary secrets somehow */
		buffer_add_utf8_string (buffer, password);

		if (!buffer_add_time (buffer, gck_secret_object_get_created (obj)) || 
		    !buffer_add_time (buffer, gck_secret_object_get_modified (obj)))
			break;

		/* reserved: */
		if (!buffer_add_utf8_string (buffer, NULL))
			break;
		for (i = 0; i < 4; i++)
			egg_buffer_add_uint32 (buffer, 0);

		attributes = gck_secret_item_get_fields (item);
		if (!buffer_add_attributes (buffer, attributes, FALSE))
			break;

		acl = g_object_get_data (G_OBJECT (item), "compat-acl");
		if (!generate_acl_data (buffer, acl))
			break;
	}
	
	g_list_free (items);
	
	/* Iteration completed prematurely == fail */
	return (l == NULL); 
}

static gboolean
generate_hashed_items (GckSecretCollection *collection, EggBuffer *buffer)
{
	GHashTable *attributes;
	const gchar *value;
	GList *items, *l;
	guint32 id, type;
	
	items = gck_secret_collection_get_items (collection);
	egg_buffer_add_uint32 (buffer, g_list_length (items));

	for (l = items; l; l = g_list_next (l)) {
		
		value = gck_secret_object_get_identifier (l->data);
		if (!convert_to_integer (value, &id))
			continue;
		egg_buffer_add_uint32 (buffer, id);
		
		attributes = gck_secret_item_get_fields (l->data);
		value = g_hash_table_lookup (attributes, "gkr:item-type");
		type = gck_secret_compat_parse_item_type (value);
		egg_buffer_add_uint32 (buffer, type);
		
		buffer_add_attributes (buffer, attributes, TRUE);
	}
	
	g_list_free (items);
	return !egg_buffer_has_error (buffer);
}

GckDataResult 
gck_secret_binary_write (GckSecretCollection *collection, GckSecret *master,
                         guchar **data, gsize *n_data)
{
	GckSecretObject *obj;
	EggBuffer to_encrypt;
        guchar digest[16];
        EggBuffer buffer;
        gint hash_iterations;
        gint lock_timeout;
        guchar salt[8];
	guint flags;
	int i;

	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), GCK_DATA_FAILURE);
	
	egg_buffer_init_full (&buffer, 256, g_realloc);
	obj = GCK_SECRET_OBJECT (collection);
	
	/* Prepare the keyring for encryption */
	hash_iterations = 1000 + (int) (1000.0 * rand() / (RAND_MAX + 1.0));
	gcry_create_nonce (salt, sizeof (salt));
		
	egg_buffer_append (&buffer, (guchar*)KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN);
	egg_buffer_add_byte (&buffer, 0); /* Major version */
	egg_buffer_add_byte (&buffer, 0); /* Minor version */
	egg_buffer_add_byte (&buffer, 0); /* crypto (0 == AEL) */
	egg_buffer_add_byte (&buffer, 0); /* hash (0 == MD5) */

	buffer_add_utf8_string (&buffer, gck_secret_object_get_label (obj));
	buffer_add_time (&buffer, gck_secret_object_get_modified (obj));
	buffer_add_time (&buffer, gck_secret_object_get_created (obj));
	
	flags = 0;
	if (g_object_get_data (G_OBJECT (collection), "lock-on-idle")) 
		flags |= 1;
	egg_buffer_add_uint32 (&buffer, flags);
	
	lock_timeout = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (collection), "lock-on-idle"));
	egg_buffer_add_uint32 (&buffer, lock_timeout);
	egg_buffer_add_uint32 (&buffer, hash_iterations);
	egg_buffer_append (&buffer, salt, 8);

	/* Reserved: */
	for (i = 0; i < 4; i++)
		egg_buffer_add_uint32 (&buffer, 0);

	/* Hashed items: */
	generate_hashed_items (collection, &buffer);

	/* Encrypted data. Use non-pageable memory */
	egg_buffer_init_full (&to_encrypt, 4096, egg_secure_realloc);
	
	egg_buffer_append (&to_encrypt, (guchar*)digest, 16); /* Space for hash */

	if (!generate_encrypted_data (&to_encrypt, collection)) {
		egg_buffer_uninit (&to_encrypt);
		egg_buffer_uninit (&buffer);
		return GCK_DATA_FAILURE;
	}

	/* Pad with zeros to multiple of 16 bytes */
	while (to_encrypt.len % 16 != 0)
		egg_buffer_add_byte (&to_encrypt, 0);

	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, 
			     (guchar*)to_encrypt.buf + 16, to_encrypt.len - 16);
	memcpy (to_encrypt.buf, digest, 16);
	
	if (!encrypt_buffer (&to_encrypt, master, salt, hash_iterations)) {
		egg_buffer_uninit (&buffer);
		egg_buffer_uninit (&to_encrypt);
		return GCK_DATA_FAILURE;
	}
	
	if (egg_buffer_has_error (&to_encrypt) || egg_buffer_has_error (&buffer)) {
		egg_buffer_uninit (&buffer);
		egg_buffer_uninit (&to_encrypt);
		return GCK_DATA_FAILURE;
	}

	egg_buffer_add_uint32 (&buffer, to_encrypt.len);
	egg_buffer_append (&buffer, to_encrypt.buf, to_encrypt.len);
	egg_buffer_uninit (&to_encrypt);
	*data = egg_buffer_uninit_steal (&buffer, n_data);
	
	return GCK_DATA_SUCCESS;
}

static gboolean
decode_acl (EggBuffer *buffer, gsize offset, gsize *offset_out, GList **out)
{
	GList *acl;
	guint32 num_acs;
	guint32 x, y;
	int i;
	GckSecretAccess *ac;
	char *name, *path, *reserved;
	
	acl = NULL;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &num_acs))
		return FALSE;
	for (i = 0; i < num_acs; i++) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &x)) {
			goto bail;
		}
		if (!buffer_get_utf8_string (buffer, offset, &offset, &name)) {
			goto bail;
		}
		if (!buffer_get_utf8_string (buffer, offset, &offset, &path)) {
			g_free (name);
			goto bail;
		}
		reserved = NULL;
		if (!buffer_get_utf8_string (buffer, offset, &offset, &reserved)) {
			g_free (name);
			g_free (path);
			goto bail;
		}
		g_free (reserved);
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &y)) {
			g_free (name);
			g_free (path);
			goto bail;
		}

		ac = g_new0 (GckSecretAccess, 1);
		ac->display_name = name;
		ac->pathname = path;
		ac->types_allowed = x;
		
		acl = g_list_prepend (acl, ac);
	}

	*offset_out = offset;
	*out = g_list_reverse (acl);
	return TRUE;
	
bail:
	gck_secret_compat_acl_free (acl);
	return FALSE;
}

static void 
remove_unavailable_item (gpointer key, gpointer dummy, gpointer user_data)
{
	/* Called to remove items from a keyring that no longer exist */
	
	GckSecretCollection *collection = user_data;
	GckSecretItem *item;
	
	g_assert (GCK_IS_SECRET_COLLECTION (collection));
	
	item = gck_secret_collection_get_item (collection, key);
	if (item != NULL)
		gck_secret_collection_remove_item (collection, item);
}

static void
setup_item_from_info (GckSecretItem *item, gboolean locked, ItemInfo *info)
{
	GckSecretObject *obj = GCK_SECRET_OBJECT (item);
	GckSecret *secret;
	const gchar *type;
	
	gck_secret_object_set_label (obj, info->display_name);
	gck_secret_object_set_created (obj, info->ctime);
	gck_secret_object_set_modified (obj, info->mtime);
	
	type = gck_secret_compat_format_item_type (info->type);
	gck_secret_fields_add (info->attributes, "gkr:item-type", type);
	gck_secret_item_set_fields (item, info->attributes);

	if (locked) {
		g_object_set_data (G_OBJECT (item), "compat-acl", NULL);
		gck_secret_item_set_secret (item, NULL);
		
	} else {
		secret = gck_secret_new_from_password (info->secret);
		gck_secret_item_set_secret (item, secret);
		g_object_unref (secret);
		g_object_set_data_full (G_OBJECT (item), "compat-acl", info->acl, gck_secret_compat_acl_free);
		info->acl = NULL;
	}
}

static void
free_item_info (ItemInfo *info)
{
	g_free (info->identifier);
	g_free (info->display_name);
	egg_secure_free (info->secret);
	g_hash_table_unref (info->attributes);
	gck_secret_compat_acl_free (info->acl);
}

gint
gck_secret_binary_read (GckSecretCollection *collection, GckSecret *master,
                        const guchar *data, gsize n_data)
{
	gsize offset;
	guchar major, minor, crypto, hash;
	guint32 flags;
	guint32 lock_timeout;
	time_t mtime, ctime;
	char *display_name;
	gsize n_secret;
	int i, j;
	guint32 tmp;
	guint32 num_items;
	guint32 crypto_size;
	guint32 hash_iterations;
	guchar salt[8];
	ItemInfo *items;
	const gchar *password;
	GckSecretObject *obj;
	EggBuffer to_decrypt = EGG_BUFFER_EMPTY;
	GckDataResult res = GCK_DATA_FAILURE;
	GHashTable *checks = NULL;
	GckSecretItem *item;
	EggBuffer buffer;
	char *reserved;
	gchar *identifier;
	GList *l, *iteml;

	display_name = NULL;
	items = 0;
	obj = GCK_SECRET_OBJECT (collection);

	/* The buffer we read from */
	egg_buffer_init_static (&buffer, data, n_data);

	if (buffer.len < KEYRING_FILE_HEADER_LEN || 
	    memcmp (buffer.buf, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		egg_buffer_uninit (&buffer);
		return GCK_DATA_UNRECOGNIZED;
	}
	
	offset = KEYRING_FILE_HEADER_LEN;
	major = buffer.buf[offset++];
	minor = buffer.buf[offset++];
	crypto = buffer.buf[offset++];
	hash = buffer.buf[offset++];

	if (major != 0 || minor != 0 || crypto != 0 || hash != 0) {
		egg_buffer_uninit (&buffer);
		return GCK_DATA_UNRECOGNIZED;
	}
	
	/* We're decrypting this, so use secure memory */
	egg_buffer_set_allocator (&to_decrypt, egg_secure_realloc);

	if (!buffer_get_utf8_string (&buffer, offset, &offset, &display_name) || 
	    !buffer_get_time (&buffer, offset, &offset, &ctime) ||		
	    !buffer_get_time (&buffer, offset, &offset, &mtime) ||
	    !egg_buffer_get_uint32 (&buffer, offset, &offset, &flags) ||
	    !egg_buffer_get_uint32 (&buffer, offset, &offset, &lock_timeout) ||
	    !egg_buffer_get_uint32 (&buffer, offset, &offset, &hash_iterations) ||
	    !buffer_get_bytes (&buffer, offset, &offset, salt, 8))
		goto bail;
	
	for (i = 0; i < 4; i++) {
		if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &tmp))
			goto bail;
	}

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &num_items))
		goto bail;

	items = g_new0 (ItemInfo, num_items);

	for (i = 0; i < num_items; i++) {
		if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &items[i].id) ||
		    !egg_buffer_get_uint32 (&buffer, offset, &offset, &items[i].type) ||
		    !buffer_get_attributes (&buffer, offset, &offset, &items[i].attributes, TRUE))
			goto bail;
		identifier = g_strdup_printf ("%u", items[i].id);
	}

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &crypto_size))
		goto bail;

	/* Make the crypted part is the right size */
	if (crypto_size % 16 != 0)
		goto bail;
	
	/* Copy the data into to_decrypt into non-pageable memory */
	egg_buffer_init_static (&to_decrypt, buffer.buf + offset, crypto_size);

	if (master != NULL) {
		
		if (!decrypt_buffer (&to_decrypt, master, salt, hash_iterations))
			goto bail;
		if (!verify_decrypted_buffer (&to_decrypt)) {
			res = GCK_DATA_LOCKED;
			goto bail;
		} else {
			offset += 16; /* Skip hash */
			for (i = 0; i < num_items; i++) {
				if (!buffer_get_utf8_string (&buffer, offset, &offset,
				                             &items[i].display_name)) {
					goto bail;
				}
				if (!buffer_get_raw_secret (&buffer, offset, &offset,
				                            (guchar**)(&items[i].secret), &n_secret)) {
					goto bail;
				}
				/* We don't support binary secrets yet, skip */
				if (!g_utf8_validate ((gchar*)items[i].secret, n_secret, NULL)) {
					g_message ("discarding item with unsupported non-textual secret: %s", 
					           items[i].display_name);
					free (items[i].display_name);
					free (items[i].secret);
					continue;
				}
				if (!buffer_get_time (&buffer, offset, &offset, &items[i].ctime) ||
				    !buffer_get_time (&buffer, offset, &offset, &items[i].mtime)) 
					goto bail;
				reserved = NULL;
				if (!buffer_get_utf8_string (&buffer, offset, &offset, &reserved))
					goto bail;
				g_free (reserved);
				for (j = 0; j < 4; j++) {
					guint32 tmp;
					if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &tmp))
						goto bail;
				}
				if (items[i].attributes)
					g_hash_table_unref (items[i].attributes);
				if (!buffer_get_attributes (&buffer, offset, &offset, &items[i].attributes, FALSE))
					goto bail;
				if (!decode_acl (&buffer, offset, &offset, &items[i].acl))
					goto bail;
			}
		}
	}

	/* Correctly read all data, possibly including the decrypted data.
	 * Now update the keyring and items: */

	gck_secret_object_set_label (obj, display_name);
	gck_secret_object_set_modified (obj, mtime);
	gck_secret_object_set_created (obj, ctime);
	g_object_set_data (G_OBJECT (collection), "lock-on-idle", GINT_TO_POINTER (!!(flags & LOCK_ON_IDLE_FLAG)));
	g_object_set_data (G_OBJECT (collection), "lock-timeout", GINT_TO_POINTER (lock_timeout));
	
	/* Build a Hash table where we can track ids we haven't yet seen */
	checks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	iteml = gck_secret_collection_get_items (collection);
	for (l = iteml; l; l = g_list_next (l))
		g_hash_table_insert (checks, g_strdup (gck_secret_object_get_identifier (l->data)), "unused");
	g_list_free (iteml);

	for (i = 0; i < num_items; i++) {
		
		/* We've seen this id */
		g_hash_table_remove (checks, items[i].identifier);
		
		item = gck_secret_collection_get_item (collection, items[i].identifier);
		if (item == NULL)
			item = gck_secret_collection_create_item (collection, items[i].identifier);
		
		setup_item_from_info (item, password == NULL, &items[i]);
	}
	
	g_hash_table_foreach (checks, remove_unavailable_item, collection);
	res = GCK_DATA_SUCCESS;

bail:
	egg_buffer_uninit (&to_decrypt);
	if (checks)
		g_hash_table_destroy (checks);
	g_free (display_name);

	for (i = 0; items && i < num_items; i++)
		free_item_info (&items[i]);
	g_free (items);
	
	return res;
}
