/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkm-secret-binary.c - The binary encrypted format of a keyring

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

#include "egg/egg-buffer.h"
#include "egg/egg-hex.h"
#include "egg/egg-symkey.h"
#include "egg/egg-secure-memory.h"

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

enum {
	LOCK_ON_IDLE_FLAG = 1 << 0,
	LOCK_AFTER_FLAG = 1 << 1
};

enum {
	ACCESS_READ = 1 << 0,
	ACCESS_WRITE = 1 << 1,
	ACCESS_REMOVE = 1 << 2
};

EGG_SECURE_DEFINE_GLIB_GLOBALS ();

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

static gboolean
buffer_get_bytes (EggBuffer *buffer,
                  gsize offset,
                  gsize *next_offset,
                  guchar *out,
                  gsize n_bytes)
{
	if (buffer->len < n_bytes || offset > buffer->len - n_bytes)
		return FALSE;
	memcpy (out, buffer->buf + offset, n_bytes);
	*next_offset = offset + n_bytes;
	return TRUE;
}

static gboolean
buffer_get_time (EggBuffer *buffer,
                 gsize offset,
                 gsize *next_offset,
                 glong *time)
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
buffer_get_utf8_string (EggBuffer *buffer,
                        gsize offset,
                        gsize *next_offset,
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
read_attributes (EggBuffer *buffer,
                 gsize offset,
                 gsize *next_offset,
                 const gchar *identifier,
                 GKeyFile *file)
{
	guint32 list_size;
	gchar *group = NULL;
	gboolean res = FALSE;
	char *name;
	guint32 type;
	char *str;
	guint32 val;
	int i;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &list_size)) {
		g_message ("couldn't read number of attributes");
		goto bail;
	}

	for (i = 0; i < list_size; i++) {
		g_free (group);
		group = g_strdup_printf ("%s:attribute%d", identifier, i);

		if (!buffer_get_utf8_string (buffer, offset, &offset, &name)) {
			g_message ("couldn't read attribute name");
			goto bail;
		}
		if (file)
			g_key_file_set_string (file, group, "name", name);
		g_free (name);

		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &type)) {
			g_message ("couldn't read attribute type");
			goto bail;
		}
		if (file)
			g_key_file_set_integer (file, group, "type", type);

		switch (type) {
		case 0: /* A string */
			if (!buffer_get_utf8_string (buffer, offset, &offset, &str)) {
				g_message ("couldn't read string attribute value");
				goto bail;
			}
			if (file)
				g_key_file_set_string (file, group, "value", str);
			g_free (str);
			break;

		case 1: /* A uint32 */
			if (!egg_buffer_get_uint32 (buffer, offset, &offset, &val)) {
				g_message ("couldn't read number attribute value");
				goto bail;
			}
			if (file)
				g_key_file_set_int64 (file, group, "value", val);
			break;
		default:
			g_message ("invalid attribute type: %d", type);
			goto bail;
		}
	}

	*next_offset = offset;
	res = TRUE;

bail:
	return res;
}

static gboolean
decrypt_buffer (EggBuffer *buffer,
                const gchar *password,
                guchar salt[8],
                int iterations)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
	guchar *key, *iv;
	gsize n_password = 0;
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	g_assert (16 == gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128));
	g_assert (16 == gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES128));

	/* No password is set, try an null password */
	if (password == NULL)
		n_password = 0;
	else
		n_password = strlen (password);

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
read_acl (EggBuffer *buffer,
          gsize offset,
          gsize *offset_out,
          const gchar *identifier,
          GKeyFile *file)
{
	gboolean res = FALSE;
	gchar *group = NULL;
	guint32 num_acs;
	guint32 x, y;
	int i;
	char *name, *path, *reserved;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &num_acs)) {
		g_message ("couldn't read number of acls");
		return FALSE;
	}

	for (i = 0; i < num_acs; i++) {
		g_free (group);
		group = g_strdup_printf ("%s:acl%d", identifier, i);

		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &x)) {
			g_message ("couldn't read acl types allowed");
			goto bail;
		}
		g_key_file_set_boolean (file, group, "read-access", x & ACCESS_READ);
		g_key_file_set_boolean (file, group, "write-access", x & ACCESS_WRITE);
		g_key_file_set_boolean (file, group, "remove-access", x & ACCESS_REMOVE);

		if (!buffer_get_utf8_string (buffer, offset, &offset, &name)) {
			g_message ("couldn't read acl application name");
			goto bail;
		}
		g_key_file_set_string (file, group, "display-name", name);
		g_free (name);

		if (!buffer_get_utf8_string (buffer, offset, &offset, &path)) {
			g_message ("couldn't read acl application path");
			goto bail;
		}
		g_key_file_set_string (file, group, "path", path);
		g_free (path);

		reserved = NULL;
		if (!buffer_get_utf8_string (buffer, offset, &offset, &reserved)) {
			g_message ("couldn't read acl reserved string");
			goto bail;
		}
		g_free (reserved);

		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &y)) {
			g_message ("couldn't read acl reserved integer");
			goto bail;
		}
	}

	*offset_out = offset;
	res = TRUE;

bail:
	g_free (group);
	return res;
}

static gboolean
read_hashed_item_info (EggBuffer *buffer,
                       gsize *offset,
                       guint n_items,
                       GKeyFile *file,
                       GPtrArray *items)
{
	gchar *identifier;
	guint type;
	guint id;
	gint i;

	g_assert (buffer);
	g_assert (offset);
	g_assert (items);

	for (i = 0; i < n_items; i++) {
		if (!egg_buffer_get_uint32 (buffer, *offset, offset, &id)) {
			g_message ("couldn't read item id");
			return FALSE;
		}
		identifier = g_strdup_printf ("%u", id);
		g_ptr_array_add (items, identifier);

		if (!egg_buffer_get_uint32 (buffer, *offset, offset, &type)) {
			g_message ("couldn't read item type");
			return FALSE;
		}
		g_key_file_set_integer (file, identifier, "item-type", type);

		/* NULL passed as file, so nothing gets written */
		if (!read_attributes (buffer, *offset, offset, identifier, NULL)) {
			g_message ("couldn't read hashed attributes");
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
read_full_item_info (EggBuffer *buffer,
                     gsize *offset,
                     guint n_items,
                     GKeyFile *file,
                     GPtrArray *items)
{
	const gchar *identifier;
	const unsigned char *ptr_secret;
	size_t n_secret;
	gchar *value;
	guint32 tmp;
	time_t ctime, mtime;
	gint i, j;

	g_assert (buffer);
	g_assert (offset);
	g_assert (items->len == n_items);

	for (i = 0; i < n_items; i++) {
		identifier = items->pdata[i];

		/* The display name */
		if (!buffer_get_utf8_string (buffer, *offset, offset, &value)) {
			g_message ("couldn't read item display name");
			return FALSE;
		}
		g_key_file_set_string (file, identifier, "display-name", value);
		g_free (value);

		/* The secret */
		if (!egg_buffer_get_byte_array (buffer, *offset, offset, &ptr_secret, &n_secret)) {
			g_message ("couldn't read item secret");
			return FALSE;
		}
		if (g_utf8_validate ((gchar *)ptr_secret, n_secret, NULL))
			value = g_strndup ((gchar *)ptr_secret, n_secret);
		else
			value = egg_hex_encode (ptr_secret, n_secret);
		g_key_file_set_string (file, identifier, "secret", value);
		g_free (value);

		/* The item times */
		if (!buffer_get_time (buffer, *offset, offset, &ctime)) {
			g_message ("couldn't read item creation time");
			return FALSE;
		}
		g_key_file_set_int64 (file, identifier, "ctime", ctime);

		if (!buffer_get_time (buffer, *offset, offset, &mtime)) {
			g_message ("couldn't read item modification time");
			return FALSE;
		}
		g_key_file_set_int64 (file, identifier, "mtime", mtime);

		/* Reserved data */
		if (!buffer_get_utf8_string (buffer, *offset, offset, &value)) {
			g_message ("couldn't read item reserved string");
			return FALSE;
		}
		g_free (value);
		for (j = 0; j < 4; j++) {
			if (!egg_buffer_get_uint32 (buffer, *offset, offset, &tmp)) {
				g_message ("couldn't read item reserved integer");
				return FALSE;
			}
		}

		if (!read_attributes (buffer, *offset, offset, identifier, file))
			return FALSE;

		/* The ACLs */
		if (!read_acl (buffer, *offset, offset, identifier, file))
			return FALSE;
	}

	return TRUE;
}

static gboolean
transform_keyring_binary_to_text (gconstpointer data,
                                  gsize n_data,
                                  const gchar *password,
                                  GKeyFile *file)
{
	EggBuffer to_decrypt = EGG_BUFFER_EMPTY;
	guchar major, minor, crypto, hash;
	guint32 flags;
	guint32 lock_timeout;
	time_t mtime, ctime;
	guint32 tmp;
	guint32 num_items;
	guint32 crypto_size;
	guint32 hash_iterations;
	guchar salt[8];
	EggBuffer buffer;
	GPtrArray *items = NULL;
	gboolean res = FALSE;
	gsize offset;
	gchar *value;
	int i;

	/* The buffer we read from */
	egg_buffer_init_static (&buffer, data, n_data);

	if (buffer.len < KEYRING_FILE_HEADER_LEN ||
	    memcmp (buffer.buf, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		egg_buffer_uninit (&buffer);
		return FALSE;
	}

	items = g_ptr_array_new_with_free_func (g_free);
	offset = KEYRING_FILE_HEADER_LEN;
	major = buffer.buf[offset++];
	minor = buffer.buf[offset++];
	crypto = buffer.buf[offset++];
	hash = buffer.buf[offset++];

	value = g_strdup_printf ("version: %d.%d / crypto: %d / hash: %d",
	                         (gint)major, (gint)minor, (gint)crypto, (gint)hash);
	if (!g_key_file_set_comment (file, NULL, NULL, value, NULL))
		g_warn_if_reached ();
	g_free (value);

	if (major != 0 || minor != 0) {
		g_message ("unknown version: %d.%d", (gint)major, (gint)minor);
		egg_buffer_uninit (&buffer);
		return FALSE;
	}

	if (!buffer_get_utf8_string (&buffer, offset, &offset, &value)) {
		g_message ("couldn't read keyring display name");
		goto bail;
	}
	g_key_file_set_string (file, "keyring", "display-name", value);
	g_free (value);

	if (!buffer_get_time (&buffer, offset, &offset, &ctime)) {
		g_message ("couldn't read keyring creation time");
		goto bail;
	}
	g_key_file_set_int64 (file, "keyring", "ctime", ctime);

	if (!buffer_get_time (&buffer, offset, &offset, &mtime)) {
		g_message ("couldn't read keyring modification time");
		goto bail;
	}
	g_key_file_set_int64 (file, "keyring", "mtime", mtime);

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &flags)) {
		g_message ("couldn't read keyring flags");
		goto bail;
	}
	g_key_file_set_boolean (file, "keyring", "lock-on-idle", flags & LOCK_ON_IDLE_FLAG);
	g_key_file_set_boolean (file, "keyring", "lock-after", flags & LOCK_AFTER_FLAG);

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &lock_timeout)) {
		g_message ("couldn't read lock timeout");
		goto bail;
	}
	g_key_file_set_integer (file, "keyring", "lock-timeout", lock_timeout);

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &hash_iterations)) {
		g_message ("couldn't read hash iterations");
		goto bail;
	}
	g_key_file_set_integer (file, "keyring", "x-hash-iterations", hash_iterations);

	if (!buffer_get_bytes (&buffer, offset, &offset, salt, 8)) {
		g_message ("couldn't read salt");
		goto bail;
	}
	value = egg_hex_encode (salt, 8);
	g_key_file_set_string (file, "keyring", "x-salt", value);
	g_free (value);

	for (i = 0; i < 4; i++) {
		if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &tmp))
			goto bail;
	}

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &num_items)) {
		g_message ("couldn't read number of items");
		goto bail;
	}
	g_key_file_set_integer (file, "keyring", "x-num-items", num_items);

	/* Hashed data, without secrets */
	if (!read_hashed_item_info (&buffer, &offset, num_items, file, items)) {
		g_message ("couldn't read hashed items");
		goto bail;
	}

	if (!egg_buffer_get_uint32 (&buffer, offset, &offset, &crypto_size)) {
		g_message ("couldn't read size of encrypted data");
		goto bail;
	}
	g_key_file_set_integer (file, "keyring", "x-crypto-size", crypto_size);

	if (crypto_size > buffer.len - offset) {
		g_message ("encrypted data size is greater than file size, possibly truncated");
		crypto_size = buffer.len - offset;
	}

	/* Make the crypted part is the right size */
	if (crypto_size % 16 != 0) {
		g_message ("encrypted data size is not a multiple of the encryption block size, possibly truncated");
		crypto_size = (crypto_size / 16) * 16;
	}

	/* Copy the data into to_decrypt into non-pageable memory */
	egg_buffer_init (&to_decrypt, crypto_size);
	memcpy (to_decrypt.buf, buffer.buf + offset, crypto_size);
	to_decrypt.len = crypto_size;

	if (!decrypt_buffer (&to_decrypt, password, salt, hash_iterations))
		goto bail;
	if (!verify_decrypted_buffer (&to_decrypt))
		g_message ("encrypted data failed to verify, password wrong, or file corrupted");
	offset = 16; /* Skip hash */
	if (!read_full_item_info (&to_decrypt, &offset, num_items, file, items))
		goto bail;

	res = TRUE;

bail:
	g_ptr_array_free (items, TRUE);
	egg_buffer_uninit (&to_decrypt);
	return res;
}



int
main (int argc,
      char *argv[])
{
	GError *error = NULL;
	const gchar *password;
	GKeyFile *file;
	gboolean ret;
	gchar *contents;
	gsize length;

	g_set_prgname ("dump-keyring0-format");

	if (argc < 2 || argc > 3) {
		g_printerr ("usage: %s file.keyring [output]\n", g_get_prgname ());
		return 2;
	}

	if (!g_file_get_contents (argv[1], &contents, &length, &error)) {
		g_printerr ("%s: %s\n", g_get_prgname (), error->message);
		g_error_free (error);
		return 1;
	}

	file = g_key_file_new ();
	password = getpass ("Password: ");

	transform_keyring_binary_to_text (contents, length, password, file);
	g_free (contents);

	contents = g_key_file_to_data (file, &length, &error);
	g_key_file_free (file);

	if (contents == NULL) {
		g_printerr ("%s: couldn't encode: %s", g_get_prgname (), error->message);
		g_error_free (error);
		return 1;
	}

	ret = TRUE;
	if (argc == 3)
		ret = g_file_set_contents (argv[2], contents, length, &error);
	else
		g_print ("%s", contents);
	g_free (contents);

	if (!ret) {
		g_printerr ("%s: %s", g_get_prgname (), error->message);
		g_error_free (error);
		return 1;
	}

	return 0;
}
