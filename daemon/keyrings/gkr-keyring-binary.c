/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring-binary.c - The binary encrypted format of a keyring

   Copyright (C) 2003 Red Hat, Inc
   Copyright (C) 2007 Stefan Walter

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

#include "gkr-keyring.h"
#include "gkr-keyring-item.h"

#include "egg/egg-buffer.h"
#include "egg/egg-symkey.h"
#include "egg/egg-secure-memory.h"

#include "library/gnome-keyring-private.h"
#include "library/gnome-keyring-proto.h"

#include <glib.h>

#include <gcrypt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* -----------------------------------------------------------------------------
 * DECLARATIONS
 */

#define LOCK_ON_IDLE_FLAG (1<<0)

typedef struct {
	/* unencrypted: */
	guint32 id;
	guint32 type;
	GnomeKeyringAttributeList *hashed_attributes;

	/* encrypted: */
	char *display_name;
	char *secret;
	time_t ctime;
	time_t mtime;
	GnomeKeyringAttributeList *attributes;
	GList *acl;
} ItemInfo;

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

/* -----------------------------------------------------------------------------
 * BINARY ENCRYPTED FILE FORMAT
 */

static gboolean
encrypt_buffer (EggBuffer *buffer,
		const char *password,
		guchar salt[8],
		int iterations)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key, *iv;
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	g_assert (16 == gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128));
	g_assert (16 == gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES128));
	
	if (!egg_symkey_generate_simple (GCRY_CIPHER_AES128, GCRY_MD_SHA256, 
	                                 password, -1, salt, 8, iterations, &key, &iv))
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
decrypt_buffer (EggBuffer *buffer,
		const char *password,
		guchar salt[8],
		int iterations)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key, *iv;
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	g_assert (16 == gcry_cipher_get_algo_blklen (GCRY_CIPHER_AES128));
	g_assert (16 == gcry_cipher_get_algo_keylen (GCRY_CIPHER_AES128));
	
	if (!egg_symkey_generate_simple (GCRY_CIPHER_AES128, GCRY_MD_SHA256, 
	                                 password, -1, salt, 8, iterations, &key, &iv))
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
	GnomeKeyringAccessControl *ac;
	
	egg_buffer_add_uint32 (buffer, g_list_length (acl));

	for (l = acl; l != NULL; l = l->next) {
		ac = l->data;
		
		egg_buffer_add_uint32 (buffer, ac->types_allowed);
		if (!gkr_proto_add_utf8_string (buffer, ac->application->display_name)) {
			return FALSE;
		}
		if (!gkr_proto_add_utf8_string (buffer, ac->application->pathname)) {
			return FALSE;
		}
		/* Reserved: */
		if (!gkr_proto_add_utf8_string (buffer, NULL)) {
			return FALSE;
		}
		egg_buffer_add_uint32 (buffer, 0);
	}
	
	return TRUE;
}

static gboolean
generate_encrypted_data (EggBuffer *buffer, GkrKeyring *keyring)
{
	GList *l;
	int i;
	GkrKeyringItem *item;
	
	/* Make sure we're using non-pageable memory */
	gkr_proto_go_secure (buffer);
	
	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		if (!gkr_proto_add_utf8_string (buffer, item->display_name)) {
			return FALSE;
		}
		if (!gkr_proto_add_utf8_secret (buffer, item->secret)) {
			return FALSE;
		}
		gkr_proto_add_time (buffer, item->ctime);
		gkr_proto_add_time (buffer, item->mtime);

		/* reserved: */
		if (!gkr_proto_add_utf8_string (buffer, NULL)) {
			return FALSE;
		}
		for (i = 0; i < 4; i++) {
			egg_buffer_add_uint32 (buffer, 0);
		}

		if (!gkr_proto_add_attribute_list (buffer, item->attributes)) {
			return FALSE;
		}
		if (!generate_acl_data (buffer, item->acl)) {
			return FALSE;
		}
	}
	return TRUE;
}

gboolean 
gkr_keyring_binary_generate (GkrKeyring *keyring, EggBuffer *buffer)
{
	guint flags;
	GList *l;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *hashed;
	EggBuffer to_encrypt;
        guchar digest[16];
	int i;

	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), FALSE);
	
	g_assert (!keyring->locked);
	
	/* Prepare the keyring for encryption */
	if (!keyring->salt_valid) {
		keyring->hash_iterations = 1000 + (int) (1000.0 * rand() / (RAND_MAX + 1.0));
		gcry_create_nonce (keyring->salt, sizeof (keyring->salt));
		keyring->salt_valid = TRUE;
	}	
		
	egg_buffer_append (buffer, (guchar*)KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN);
	egg_buffer_add_byte (buffer, 0); /* Major version */
	egg_buffer_add_byte (buffer, 0); /* Minor version */
	egg_buffer_add_byte (buffer, 0); /* crypto (0 == AEL) */
	egg_buffer_add_byte (buffer, 0); /* hash (0 == MD5) */

	if (!gkr_proto_add_utf8_string (buffer, keyring->keyring_name)) {
		return FALSE;
	}

	gkr_proto_add_time (buffer, keyring->mtime);
	gkr_proto_add_time (buffer, keyring->ctime);
	
	flags = 0;
	if (keyring->lock_on_idle) {
		flags |= 1;
	}
	egg_buffer_add_uint32 (buffer, flags);
	egg_buffer_add_uint32 (buffer, keyring->lock_timeout);
	egg_buffer_add_uint32 (buffer, keyring->hash_iterations);
	egg_buffer_append (buffer, (guchar*)keyring->salt, 8);

	/* Reserved: */
	for (i = 0; i < 4; i++) {
		egg_buffer_add_uint32 (buffer, 0);
	}

	/* Hashed items: */
	egg_buffer_add_uint32 (buffer, g_list_length (keyring->items));

	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		egg_buffer_add_uint32 (buffer, item->id);
		egg_buffer_add_uint32 (buffer, item->type);
		
		hashed = gkr_attribute_list_hash (item->attributes);

		if (!gkr_proto_add_attribute_list (buffer, hashed)) {
			gnome_keyring_attribute_list_free (hashed);
			return FALSE;
		}
		gnome_keyring_attribute_list_free (hashed);
	}

	/* Encrypted data. Use non-pageable memory */
	egg_buffer_init_full (&to_encrypt, 4096, egg_secure_realloc);
	
	egg_buffer_append (&to_encrypt, (guchar*)digest, 16); /* Space for hash */

	if (!generate_encrypted_data (&to_encrypt, keyring)) {
		egg_buffer_uninit (&to_encrypt);
		return FALSE;
	}

	/* Pad with zeros to multiple of 16 bytes */
	while (to_encrypt.len % 16 != 0) {
		egg_buffer_add_byte (&to_encrypt, 0);
	}

	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, 
			     (guchar*)to_encrypt.buf + 16, to_encrypt.len - 16);
	memcpy (to_encrypt.buf, digest, 16);
	
	/* This is either set by gnome_keyring_create, or when reading from disk */
	g_assert (keyring->hash_iterations);
	
	if (!encrypt_buffer (&to_encrypt, keyring->password, keyring->salt, keyring->hash_iterations)) {
		egg_buffer_uninit (&to_encrypt);
		return FALSE;
	}
	egg_buffer_add_uint32 (buffer, to_encrypt.len);
	egg_buffer_append (buffer, to_encrypt.buf, to_encrypt.len);
	egg_buffer_uninit (&to_encrypt);
	
	return TRUE;
}

static gboolean
decode_acl (EggBuffer *buffer, gsize offset, gsize *offset_out, GList **out)
{
	GList *acl;
	guint32 num_acs;
	guint32 x, y;
	int i;
	char *name, *path, *reserved;
	GnomeKeyringApplicationRef *app;
	
	acl = NULL;

	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &num_acs)) {
		return FALSE;
	}
	for (i = 0; i < num_acs; i++) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &x)) {
			goto bail;
		}
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &name)) {
			goto bail;
		}
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &path)) {
			g_free (name);
			goto bail;
		}
		reserved = NULL;
		if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &reserved)) {
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

		app = g_new0 (GnomeKeyringApplicationRef, 1);
		app->display_name = name;
		app->pathname = path;
		
		acl = g_list_prepend (acl,
				      gnome_keyring_access_control_new (app, x));
	}

	*offset_out = offset;
	*out = g_list_reverse (acl);
	return TRUE;
	
 bail:
	gnome_keyring_acl_free (acl);
	return FALSE;
}

static void 
remove_unavailable_item (gpointer key, gpointer dummy, GkrKeyring *keyring)
{
	/* Called to remove items from a keyring that no longer exist */
	
	GkrKeyringItem *item;
	guint id = GPOINTER_TO_UINT (key);
	
	g_assert (GKR_IS_KEYRING (keyring));
	
	item = gkr_keyring_get_item (keyring, id);
	if (item)
		gkr_keyring_remove_item (keyring, item);
}

gint
gkr_keyring_binary_parse (GkrKeyring *keyring, EggBuffer *buffer)
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
	EggBuffer to_decrypt = EGG_BUFFER_EMPTY;
	gboolean locked;
	GList *l;
	GHashTable *checks = NULL;
	GkrKeyringItem *item;
	char *reserved;

	display_name = NULL;
	items = 0;

	/* We're decrypting this, so use secure memory */
	egg_buffer_set_allocator (&to_decrypt, egg_secure_realloc);	

	if (buffer->len < KEYRING_FILE_HEADER_LEN) {
		return 0;
	}
	if (memcmp (buffer->buf, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		return 0;
	}
	offset = KEYRING_FILE_HEADER_LEN;

	major = buffer->buf[offset++];
	minor = buffer->buf[offset++];
	crypto = buffer->buf[offset++];
	hash = buffer->buf[offset++];

	if (major != 0 || minor != 0 ||
	    crypto != 0 || hash != 0) {
		return -1;
	}

	if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &display_name)) {
		goto bail;
	}
	if (!gkr_proto_get_time (buffer, offset, &offset, &ctime)) {
		goto bail;
	}
	if (!gkr_proto_get_time (buffer, offset, &offset, &mtime)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &flags)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &lock_timeout)) {
		goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &hash_iterations)) {
		goto bail;
	}
	if (!gkr_proto_get_bytes (buffer, offset, &offset, salt, 8)) {
		goto bail;
	}
	
	for (i = 0; i < 4; i++) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset, &tmp))
			goto bail;
	}
	if (!egg_buffer_get_uint32 (buffer, offset, &offset, &num_items)) {
		goto bail;
	}

	items = g_new0 (ItemInfo, num_items);

	for (i = 0; i < num_items; i++) {
		if (!egg_buffer_get_uint32 (buffer, offset, &offset,
						     &items[i].id)) {
			goto bail;
		}
		if (!egg_buffer_get_uint32 (buffer, offset, &offset,
						     &items[i].type)) {
			goto bail;
		}
		if (!gkr_proto_decode_attribute_list (buffer, offset, &offset,
		                                      &items[i].hashed_attributes)) {
			goto bail;
		}
	}

	if (!egg_buffer_get_uint32 (buffer, offset, &offset,
					     &crypto_size)) {
		goto bail;
	}
	/* Make the crypted part is the right size */
	if (crypto_size % 16 != 0)
		goto bail;
	
	/* Copy the data into to_decrypt into non-pageable memory */
	egg_buffer_init_static (&to_decrypt, buffer->buf + offset, crypto_size);

	locked = TRUE;
	if (keyring->password != NULL) {
		
		if (!decrypt_buffer (&to_decrypt, keyring->password, salt, hash_iterations)) {
			goto bail;
		}
		if (!verify_decrypted_buffer (&to_decrypt)) {
			egg_secure_strfree (keyring->password);
			keyring->password = NULL;
		} else {
			locked = FALSE;
			offset += 16; /* Skip hash */
			for (i = 0; i < num_items; i++) {
				if (!gkr_proto_get_utf8_string (buffer, offset, &offset,
				                                &items[i].display_name)) {
					goto bail;
				}
				if (!gkr_proto_get_raw_secret (buffer, offset, &offset,
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
				if (!gkr_proto_get_time (buffer, offset, &offset,
				                         &items[i].ctime)) {
					goto bail;
				}
				if (!gkr_proto_get_time (buffer, offset, &offset,
				                         &items[i].mtime)) {
					goto bail;
				}
				reserved = NULL;
				if (!gkr_proto_get_utf8_string (buffer, offset, &offset, &reserved))
					goto bail;
				g_free (reserved);
				for (j = 0; j < 4; j++) {
					guint32 tmp;
					if (!egg_buffer_get_uint32 (buffer, offset, &offset, &tmp))
						goto bail;
				}
				if (!gkr_proto_decode_attribute_list (buffer, offset, &offset,
				                                      &items[i].attributes)) {
					goto bail;
				}
				
				if (!decode_acl (buffer, offset, &offset, &items[i].acl)) {
					goto bail;
				}
			}
		}
	}

	/* Correctly read all data, possibly including the decrypted data.
	 * Now update the keyring and items: */

	keyring->locked = locked;
	g_free (keyring->keyring_name);
	keyring->keyring_name = display_name;
	keyring->mtime = mtime;
	keyring->ctime = ctime;
	keyring->lock_on_idle = !!(flags & LOCK_ON_IDLE_FLAG);
	keyring->lock_timeout = lock_timeout;
	keyring->hash_iterations = hash_iterations;
	memcpy (keyring->salt, salt, 8);
	keyring->salt_valid = TRUE;
	
	/* Build a Hash table where we can track ids we haven't yet seen */
	checks = g_hash_table_new (g_direct_hash, g_direct_equal);
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		g_hash_table_insert (checks, GUINT_TO_POINTER (item->id), GINT_TO_POINTER (TRUE));
	}

	for (i = 0; i < num_items; i++) {
		
		/* We've seen this id */
		g_hash_table_remove (checks, GUINT_TO_POINTER (items[i].id));
		
		item = gkr_keyring_get_item (keyring, items[i].id);
		if (item == NULL) {
			item = gkr_keyring_item_new (keyring, items[i].id, items[i].type);
			gkr_keyring_add_item (keyring, item);
			g_object_unref (item);
		}
		
		item->locked = locked;
		item->type = items[i].type;

		g_free (item->display_name);
		item->display_name = NULL;
		egg_secure_strfree (item->secret);
		item->secret = NULL;
		if (item->acl) {
			gnome_keyring_acl_free (item->acl);
			item->acl = NULL;
		}
		gnome_keyring_attribute_list_free (item->attributes);
		item->attributes = NULL;
		
		if (locked) {
			item->attributes = items[i].hashed_attributes;
			item->mtime = 0;
			item->ctime = 0;
		} else {
			item->attributes = items[i].attributes;
			gnome_keyring_attribute_list_free (items[i].hashed_attributes);
			item->display_name = items[i].display_name;
			item->secret = items[i].secret;
			item->acl = items[i].acl;
			item->mtime = items[i].mtime;
			item->ctime = items[i].ctime;
		}
	}
	
	g_hash_table_foreach (checks, (GHFunc)remove_unavailable_item, keyring);
	g_hash_table_destroy (checks);

	return 1;
 bail:
	egg_buffer_uninit (&to_decrypt);
	if (checks)
		g_hash_table_destroy (checks);
	g_free (display_name);

	if (items != NULL) {
		for (i = 0; i < num_items; i++) {
			g_free (items[i].display_name);
			egg_secure_strfree (items[i].secret);
			gnome_keyring_attribute_list_free (items[i].hashed_attributes);
			gnome_keyring_attribute_list_free (items[i].attributes);
			gnome_keyring_acl_free (items[i].acl);
		}
		g_free (items);
	}
	
	return -1;
}
