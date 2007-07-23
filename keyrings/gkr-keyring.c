/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-keyring.c - represents a keyring in memory, and functionality save/load

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
#include "gkr-keyrings.h"
#include "gkr-keyring-item.h"

#include "common/gkr-buffer.h"

#include "daemon/gnome-keyring-daemon.h"

#include "library/gnome-keyring-memory.h"
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

enum {
    ITEM_ADDED,
    ITEM_REMOVED,
    LAST_SIGNAL
};

enum {
    PROP_0,
    PROP_NAME
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GkrKeyring, gkr_keyring, G_TYPE_OBJECT);

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
 * HELPERS
 */

static void
init_salt (guchar salt[8])
{
	gboolean got_random;
	int i, fd;

	got_random = FALSE;
#ifdef HAVE_DEVRANDOM
	fd = open ("/dev/random", O_RDONLY);
	if (fd != -1) {
		struct stat st;
		/* Make sure it's a character device */
		if ((fstat (fd, &st) == 0) && S_ISCHR (st.st_mode)) {
			if (read (fd, salt, 8) == 8) {
				got_random = TRUE;
			}
		}
		close (fd);
	}
#endif

	if (!got_random) {
		for (i=0; i < 8; i++) {
			salt[i] = (int) (256.0*rand()/(RAND_MAX+1.0));
		}
	}
	
}

static gboolean
generate_key (const char *password,
	      guchar salt[8],
	      int iterations,
	      guchar key[16],
	      guchar iv[16])
{
	gcry_md_hd_t mdh;
	gcry_error_t gerr;
	guchar *digest;
	guchar *digested;
	guint n_digest;

	g_assert (iterations >= 1);
	
	gerr = gcry_md_open (&mdh, GCRY_MD_SHA256, 0);
	if (gerr) {
		g_warning ("couldn't create sha256 hash context: %s", 
			   gcry_strerror (gerr));
		return FALSE;
	}

	n_digest = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
	g_return_val_if_fail (n_digest >= 32, FALSE);
	
	digest = gnome_keyring_memory_new (guchar, n_digest);

	gcry_md_write (mdh, password, strlen (password));
	gcry_md_write (mdh, salt, 8);
	gcry_md_final (mdh);
	digested = gcry_md_read (mdh, 0);
	g_return_val_if_fail (digested, FALSE);
	memcpy (digest, digested, n_digest);
	iterations--;

	while (iterations != 0) {
		gcry_md_reset (mdh);
		gcry_md_write (mdh, digest, n_digest);
		gcry_md_final (mdh);
		digested = gcry_md_read (mdh, 0);
		g_return_val_if_fail (digested, FALSE);
		memcpy (digest, digested, n_digest);
		iterations--;
	}

	memcpy (key, digest, 16);
	memcpy (iv, digest+16, 16);

	gnome_keyring_memory_free (digest);
	gcry_md_close (mdh);
	
	return TRUE;
}

static gboolean
encrypt_buffer (GkrBuffer *buffer,
		const char *password,
		guchar salt[8],
		int iterations)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key;
        guchar iv[16];
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	
	key = gnome_keyring_memory_new (guchar, 16);

	if (!generate_key (password, salt, iterations, key, iv)) {
		gnome_keyring_memory_free (key);
		return FALSE;
	}

	gerr = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gerr) {
		g_warning ("couldn't create aes cipher context: %s", 
			   gcry_strerror (gerr));
		gnome_keyring_memory_free (key);
		return FALSE;
	}

	/* 16 = 128 bits */
	gerr = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (!gerr, FALSE);

	/* 16 = 128 bits */
	gerr = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (!gerr, FALSE);

	for (pos = 0; pos < buffer->len; pos += 16) {
		/* In place encryption */
		gerr = gcry_cipher_encrypt (cih, buffer->buf + pos, 16, NULL, 0);
		g_return_val_if_fail (!gerr, FALSE);
	}

	gnome_keyring_memory_free (key);
	gcry_cipher_close (cih);
	
	return TRUE;
}

static gboolean
decrypt_buffer (GkrBuffer *buffer,
		const char *password,
		guchar salt[8],
		int iterations)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gerr;
        guchar *key;
        guchar iv[16];
	size_t pos;

	g_assert (buffer->len % 16 == 0);
	
	key = gnome_keyring_memory_new (guchar, 16);	

	if (!generate_key (password, salt, iterations, key, iv)) {
		gnome_keyring_memory_free (key);
		return FALSE;
	}
	
	gerr = gcry_cipher_open (&cih, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if (gerr) {
		g_warning ("couldn't create aes cipher context: %s", 
			   gcry_strerror (gerr));
		gnome_keyring_memory_free (key);
		return FALSE;
	}

	/* 16 = 128 bits */
	gerr = gcry_cipher_setkey (cih, key, 16);
	g_return_val_if_fail (!gerr, FALSE);

	/* 16 = 128 bits */
	gerr = gcry_cipher_setiv (cih, iv, 16);
	g_return_val_if_fail (!gerr, FALSE);

	for (pos = 0; pos < buffer->len; pos += 16) {
		/* In place encryption */
		gerr = gcry_cipher_decrypt (cih, buffer->buf + pos, 16, NULL, 0);
		g_return_val_if_fail (!gerr, FALSE);
	}

	gnome_keyring_memory_free (key);
	gcry_cipher_close (cih);
	
	return TRUE;
}

static gboolean
verify_decrypted_buffer (GkrBuffer *buffer)
{
        guchar digest[16];
	
	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), 0);
	
	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, 
			     (guchar*)buffer->buf + 16, buffer->len - 16);
	
	return memcmp (buffer->buf, digest, 16) == 0;
}

static gboolean 
generate_acl_data (GkrBuffer *buffer,
		   GList *acl)
{
	GList *l;
	GnomeKeyringAccessControl *ac;
	
	gkr_buffer_add_uint32 (buffer, g_list_length (acl));

	for (l = acl; l != NULL; l = l->next) {
		ac = l->data;
		
		gkr_buffer_add_uint32 (buffer, ac->types_allowed);
		if (!gnome_keyring_proto_add_utf8_string (buffer, ac->application->display_name)) {
			return FALSE;
		}
		if (!gnome_keyring_proto_add_utf8_string (buffer, ac->application->pathname)) {
			return FALSE;
		}
		/* Reserved: */
		if (!gnome_keyring_proto_add_utf8_string (buffer, NULL)) {
			return FALSE;
		}
		gkr_buffer_add_uint32 (buffer, 0);
	}
	
	
	return TRUE;
}

static gboolean
generate_encrypted_data (GkrBuffer *buffer, GkrKeyring *keyring)
{
	GList *l;
	int i;
	GkrKeyringItem *item;
	
	/* Make sure we're using non-pageable memory */
	gnome_keyring_proto_go_secure (buffer);
	
	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		if (!gnome_keyring_proto_add_utf8_string (buffer, item->display_name)) {
			return FALSE;
		}
		if (!gnome_keyring_proto_add_utf8_secret (buffer, item->secret)) {
			return FALSE;
		}
		gnome_keyring_proto_add_time (buffer, item->ctime);
		gnome_keyring_proto_add_time (buffer, item->mtime);

		/* reserved: */
		if (!gnome_keyring_proto_add_utf8_string (buffer, NULL)) {
			return FALSE;
		}
		for (i = 0; i < 4; i++) {
			gkr_buffer_add_uint32 (buffer, 0);
		}

		if (!gnome_keyring_proto_add_attribute_list (buffer, item->attributes)) {
			return FALSE;
		}
		if (!generate_acl_data (buffer, item->acl)) {
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean 
generate_file (GkrBuffer *buffer, GkrKeyring *keyring)
{
	guint flags;
	GList *l;
	GkrKeyringItem *item;
	GnomeKeyringAttributeList *hashed;
	GkrBuffer to_encrypt;
        guchar digest[16];
	int i;

	/* In case the world changes on us... */
	g_return_val_if_fail (gcry_md_get_algo_dlen (GCRY_MD_MD5) == sizeof (digest), FALSE);
	
	g_assert (!keyring->locked);
		
	gkr_buffer_append (buffer, (guchar*)KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN);
	gkr_buffer_add_byte (buffer, 0); /* Major version */
	gkr_buffer_add_byte (buffer, 0); /* Minor version */
	gkr_buffer_add_byte (buffer, 0); /* crypto (0 == AEL) */
	gkr_buffer_add_byte (buffer, 0); /* hash (0 == MD5) */

	if (!gnome_keyring_proto_add_utf8_string (buffer, keyring->keyring_name)) {
		return FALSE;
	}

	gnome_keyring_proto_add_time (buffer, keyring->mtime);
	gnome_keyring_proto_add_time (buffer, keyring->ctime);
	
	flags = 0;
	if (keyring->lock_on_idle) {
		flags |= 1;
	}
	gkr_buffer_add_uint32 (buffer, flags);
	gkr_buffer_add_uint32 (buffer, keyring->lock_timeout);
	gkr_buffer_add_uint32 (buffer, keyring->hash_iterations);
	gkr_buffer_append (buffer, (guchar*)keyring->salt, 8);

	/* Reserved: */
	for (i = 0; i < 4; i++) {
		gkr_buffer_add_uint32 (buffer, 0);
	}

	/* Hashed items: */
	gkr_buffer_add_uint32 (buffer, g_list_length (keyring->items));

	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		gkr_buffer_add_uint32 (buffer, item->id);
		gkr_buffer_add_uint32 (buffer, item->type);
		
		hashed = gnome_keyring_attributes_hash (item->attributes);

		if (!gnome_keyring_proto_add_attribute_list (buffer, hashed)) {
			gnome_keyring_attribute_list_free (hashed);
			return FALSE;
		}
		gnome_keyring_attribute_list_free (hashed);
	}

	/* Encrypted data. Use non-pageable memory */
	gkr_buffer_init_full (&to_encrypt, 4096, gnome_keyring_memory_realloc);
	
	gkr_buffer_append (&to_encrypt, (guchar*)digest, 16); /* Space for hash */

	if (!generate_encrypted_data (&to_encrypt, keyring)) {
		gkr_buffer_uninit (&to_encrypt);
		return FALSE;
	}

	/* Pad with zeros to multiple of 16 bytes */
	while (to_encrypt.len % 16 != 0) {
		gkr_buffer_add_byte (&to_encrypt, 0);
	}

	gcry_md_hash_buffer (GCRY_MD_MD5, (void*)digest, 
			     (guchar*)to_encrypt.buf + 16, to_encrypt.len - 16);
	memcpy (to_encrypt.buf, digest, 16);
	
	if (!encrypt_buffer (&to_encrypt, keyring->password, keyring->salt, keyring->hash_iterations)) {
		gkr_buffer_uninit (&to_encrypt);
		return FALSE;
	}
	gkr_buffer_add_uint32 (buffer, to_encrypt.len);
	gkr_buffer_append (buffer, to_encrypt.buf, to_encrypt.len);
	gkr_buffer_uninit (&to_encrypt);
	
	return TRUE;
}

static gboolean
decode_acl (GkrBuffer *buffer, gsize offset, gsize *offset_out, GList **out)
{
	GList *acl;
	guint32 num_acs;
	guint32 x, y;
	int i;
	char *name, *path, *reserved;
	GnomeKeyringApplicationRef *app;
	
	acl = NULL;

	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &num_acs)) {
		return FALSE;
	}
	for (i = 0; i < num_acs; i++) {
		if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &x)) {
			goto bail;
		}
		if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
							  &name)) {
			goto bail;
		}
		if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
							  &path)) {
			g_free (name);
			goto bail;
		}
		if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
							  &reserved) ||
		    reserved != NULL) {
			g_free (name);
			g_free (path);
			g_free (reserved);
			goto bail;
		}
		if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &y)) {
			g_free (name);
			g_free (path);
			g_free (reserved);
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

static gboolean
update_keyring_from_data (GkrKeyring *keyring, GkrBuffer *buffer)
{
	gsize offset;
	guchar major, minor, crypto, hash;
	guint32 flags;
	guint32 lock_timeout;
	time_t mtime, ctime;
	char *display_name;
	int i, j;
	guint32 tmp;
	guint32 num_items;
	guint32 crypto_size;
	guint32 hash_iterations;
	guchar salt[8];
	ItemInfo *items;
	GkrBuffer to_decrypt = GKR_BUFFER_EMPTY;
	gboolean locked;
	GList *l;
	GHashTable *checks = NULL;
	GkrKeyringItem *item;
	char *reserved;

	display_name = NULL;
	items = 0;

	/* We're decrypting this, so use secure memory */
	gkr_buffer_set_allocator (&to_decrypt, gnome_keyring_memory_realloc);	

	if (buffer->len < KEYRING_FILE_HEADER_LEN) {
		return FALSE;
	}
	if (memcmp (buffer->buf, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		return FALSE;
	}
	offset = KEYRING_FILE_HEADER_LEN;

	major = buffer->buf[offset++];
	minor = buffer->buf[offset++];
	crypto = buffer->buf[offset++];
	hash = buffer->buf[offset++];

	if (major != 0 || minor != 0 ||
	    crypto != 0 || hash != 0) {
		return FALSE;
	}

	if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
						  &display_name)) {
		goto bail;
	}
	if (!gnome_keyring_proto_get_time (buffer, offset, &offset, &ctime)) {
		goto bail;
	}
	if (!gnome_keyring_proto_get_time (buffer, offset, &offset, &mtime)) {
		goto bail;
	}
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &flags)) {
		goto bail;
	}
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &lock_timeout)) {
		goto bail;
	}
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &hash_iterations)) {
		goto bail;
	}
	if (!gnome_keyring_proto_get_bytes (buffer, offset, &offset, salt, 8)) {
		goto bail;
	}
	
	for (i = 0; i < 4; i++) {
		if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &tmp)) {
			goto bail;
		}
		/* reserved bytes must be zero */
		if (tmp != 0) {
			goto bail;
		}
	}
	if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &num_items)) {
		goto bail;
	}

	items = g_new0 (ItemInfo, num_items);

	for (i = 0; i < num_items; i++) {
		if (!gkr_buffer_get_uint32 (buffer, offset, &offset,
						     &items[i].id)) {
			goto bail;
		}
		if (!gkr_buffer_get_uint32 (buffer, offset, &offset,
						     &items[i].type)) {
			goto bail;
		}
		if (!gnome_keyring_proto_decode_attribute_list (buffer, offset, &offset,
								&items[i].hashed_attributes)) {
			goto bail;
		}
	}

	if (!gkr_buffer_get_uint32 (buffer, offset, &offset,
					     &crypto_size)) {
		goto bail;
	}
	/* Make sure the rest of the file is the crypted part only */
	if (crypto_size % 16 != 0 ||
	    buffer->len - offset != crypto_size) {
		goto bail;
	}
	
	/* Copy the data into to_decrypt into non-pageable memory */
	gkr_buffer_init_static (&to_decrypt, buffer->buf + offset, crypto_size);

	locked = TRUE;
	if (keyring->password != NULL) {
		
		if (!decrypt_buffer (&to_decrypt, keyring->password, salt, hash_iterations)) {
			goto bail;
		}
		if (!verify_decrypted_buffer (&to_decrypt)) {
			gnome_keyring_free_password (keyring->password);
			keyring->password = NULL;
		} else {
			locked = FALSE;
			offset += 16; /* Skip hash */
			for (i = 0; i < num_items; i++) {
				if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
									  &items[i].display_name)) {
					goto bail;
				}
				if (!gnome_keyring_proto_get_utf8_secret (buffer, offset, &offset,
									  &items[i].secret)) {
					goto bail;
				}
				if (!gnome_keyring_proto_get_time (buffer, offset, &offset,
								   &items[i].ctime)) {
					goto bail;
				}
				if (!gnome_keyring_proto_get_time (buffer, offset, &offset,
								   &items[i].mtime)) {
					goto bail;
				}
				reserved = NULL;
				if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
									  &reserved) ||
				    reserved != NULL) {
					g_free (reserved);
					goto bail;
				}
				for (j = 0; j < 4; j++) {
					guint32 tmp;
					if (!gkr_buffer_get_uint32 (buffer, offset, &offset, &tmp)) {
						goto bail;
					}
					/* reserved bytes must be zero */
					if (tmp != 0) {
						goto bail;
					}
				}
				if (!gnome_keyring_proto_decode_attribute_list (buffer, offset, &offset,
										&items[i].attributes)) {
					goto bail;
				}
				
				if (!decode_acl (buffer, offset, &offset,
						 &items[i].acl)) {
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
		}
		
		item->locked = locked;
		item->type = items[i].type;

		g_free (item->display_name);
		item->display_name = NULL;
		gnome_keyring_free_password (item->secret);
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

	return TRUE;
 bail:
	gkr_buffer_uninit (&to_decrypt);
	if (checks)
		g_hash_table_destroy (checks);
	g_free (display_name);

	if (items != NULL) {
		for (i = 0; i < num_items; i++) {
			g_free (items[i].display_name);
			gnome_keyring_free_password (items[i].secret);
			gnome_keyring_attribute_list_free (items[i].hashed_attributes);
			gnome_keyring_attribute_list_free (items[i].attributes);
			gnome_keyring_acl_free (items[i].acl);
		}
		g_free (items);
	}
	
	return FALSE;
}


static int
write_all (int fd, const guchar *buf, size_t len)
{
	size_t bytes;
	int res;

	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				perror ("write_all write failure:");
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

static char*
get_default_keyring_file_for_name (const char *keyring_name)
{
	char *base;
	char *filename;
	int version;
	char *path;
	char *dir;

	base = g_filename_from_utf8 (keyring_name, -1, NULL, NULL, NULL);
	if (base == NULL) {
		base = g_strdup ("keyring");
	}

	dir = gkr_keyrings_get_dir ();
	
	version = 0;
	do {
		if (version == 0) {
			filename = g_strdup_printf ("%s.keyring", base);
		} else {
			filename = g_strdup_printf ("%s%d.keyring", base, version);
		}
		
		path = g_build_filename (dir, filename, NULL);
		g_free (filename);

		version++;
	} while (g_file_test (path, G_FILE_TEST_EXISTS));

	g_free (base);
	g_free (dir);
	
	return path;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_keyring_init (GkrKeyring *keyring)
{
	keyring->ctime = keyring->mtime = time (NULL);

	/* Default values: */
	keyring->lock_on_idle = FALSE;
	keyring->lock_timeout = 0;

	keyring->hash_iterations = 1000 + (int) (1000.0 * rand() / (RAND_MAX + 1.0));
	init_salt (keyring->salt);
}

static void
gkr_keyring_get_property (GObject *obj, guint prop_id, GValue *value, 
                          GParamSpec *pspec)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, keyring->keyring_name);
		break;
	}
}

static void 
gkr_keyring_dispose (GObject *obj)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);
	GkrKeyringItem *item;
	GList *l;
	
	/* Remove all references to items */
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		g_object_unref (item);
	}
	
	g_list_free (keyring->items);
	keyring->items = NULL;
	
	gnome_keyring_free_password (keyring->password);
	keyring->password = NULL;

	G_OBJECT_CLASS (gkr_keyring_parent_class)->dispose (obj);
}

static void
gkr_keyring_finalize (GObject *obj)
{
	GkrKeyring *keyring = GKR_KEYRING (obj);

	g_free (keyring->keyring_name);
	g_free (keyring->file);
	g_assert (keyring->password == NULL);
	
	G_OBJECT_CLASS (gkr_keyring_parent_class)->finalize (obj);
}

static void
gkr_keyring_class_init (GkrKeyringClass *klass)
{
	GObjectClass *gobject_class = (GObjectClass*)klass;

	gkr_keyring_parent_class  = g_type_class_peek_parent (klass);
	
	gobject_class->get_property = gkr_keyring_get_property;
	gobject_class->dispose = gkr_keyring_dispose;
	gobject_class->finalize = gkr_keyring_finalize;
	
	g_object_class_install_property (gobject_class, PROP_NAME,
		g_param_spec_string ("name", "Name", "Keyring Name",
		                     NULL, G_PARAM_READABLE));
	
	signals[ITEM_ADDED] = g_signal_new ("item-added", GKR_TYPE_KEYRING, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrKeyringClass, item_added),
			NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
			G_TYPE_NONE, 1, GKR_TYPE_KEYRING_ITEM);

	signals[ITEM_REMOVED] = g_signal_new ("item-removed", GKR_TYPE_KEYRING, 
			G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkrKeyringClass, item_removed),
			NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
			G_TYPE_NONE, 1, GKR_TYPE_KEYRING_ITEM);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrKeyring*
gkr_keyring_new (const char *name, const char *path)
{
	GkrKeyring *keyring;
	
	/* TODO: This should be done using properties */
	
	keyring = g_object_new (GKR_TYPE_KEYRING, NULL);
	
	keyring->keyring_name = g_strdup (name);
	keyring->file = g_strdup (path);

	return keyring;
}

GkrKeyring*
gkr_keyring_create (const gchar *keyring_name, const gchar *password)
{
	GkrKeyring *keyring;
	
	keyring = gkr_keyring_new (keyring_name, NULL);
	if (keyring != NULL) {
		keyring->file = get_default_keyring_file_for_name (keyring_name);
		keyring->locked = FALSE;
		keyring->password = gnome_keyring_memory_strdup (password);
		gkr_keyring_save_to_disk (keyring);
	}
	return keyring;
}

guint
gkr_keyring_get_new_id (GkrKeyring *keyring)
{
	GkrKeyringItem *item;
	GList *l;
	guint max;

	g_assert (GKR_IS_KEYRING (keyring));

	max = 0;
	for (l = keyring->items; l ; l = g_list_next (l)) {
		item = l->data;
		if (item->id >= max)
			max = item->id;
	}
	/* Naive unique id lookup, but avoid rollaround at lest: */
	
	if (max == 0xffffffff)
		return 0;
	
	return max + 1;
}

GkrKeyringItem*
gkr_keyring_get_item (GkrKeyring *keyring, guint id)
{
	GkrKeyringItem *item;
	GList *l;
	
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		if (item->id == id)
			return item;
	}
	
	return NULL;
}

GkrKeyringItem*  
gkr_keyring_find_item (GkrKeyring *keyring, GnomeKeyringItemType type, 
                       GnomeKeyringAttributeList *attrs)
{    
	GkrKeyringItem *item;
	GList *l;
	
	for (l = keyring->items; l; l = g_list_next (l)) {
		item = GKR_KEYRING_ITEM (l->data);
		if (gkr_keyring_item_match (item, type, attrs, TRUE))
			return item;
	}
	
	return NULL;
}

void
gkr_keyring_add_item (GkrKeyring* keyring, GkrKeyringItem* item)
{
	g_assert (GKR_IS_KEYRING (keyring));
	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	/* Must not be added twice */
	g_assert (g_list_find (keyring->items, item) == NULL);
	
	keyring->items = g_list_append (keyring->items, item);
	g_object_ref (item);
	
	g_signal_emit (keyring, signals[ITEM_ADDED], 0, item);

}

void
gkr_keyring_remove_item (GkrKeyring* keyring, GkrKeyringItem* item)
{
	g_assert (GKR_IS_KEYRING (keyring));
	g_assert (GKR_IS_KEYRING_ITEM (item));
	
	if (g_list_find (keyring->items, item)) {
		keyring->items = g_list_remove (keyring->items, item);

		/* Must not be added twice */
		g_assert (g_list_find (keyring->items, item) == NULL);
		
		/* Keep the reference until after the signal */
		g_signal_emit (keyring, signals[ITEM_REMOVED], 0, item);
		
		g_object_unref (item);
	}
}

gboolean
gkr_keyring_update_from_disk (GkrKeyring *keyring, gboolean force_reload)
{
	struct stat statbuf;
	GkrBuffer buffer;
	char *contents = NULL;
	gsize len;
	gboolean success = FALSE;

	if (keyring->file == NULL)
		return TRUE;

	if (stat (keyring->file, &statbuf) < 0)
		return FALSE;

	if (!force_reload && statbuf.st_mtime == keyring->file_mtime)
		return TRUE;
	keyring->file_mtime = statbuf.st_mtime;

	if (!g_file_get_contents (keyring->file, &contents, &len, NULL))
		return FALSE;

	gkr_buffer_init_static (&buffer, (guchar*)contents, len);
	
	success = update_keyring_from_data (keyring, &buffer);
	gkr_buffer_uninit (&buffer);
	g_free (contents);

	return success;
}

gboolean 
gkr_keyring_remove_from_disk (GkrKeyring *keyring)
{
	int res;

	/* Cannot remove session or memory based keyring */
	if (keyring->file == NULL)
		return FALSE;

	res = unlink (keyring->file);
	return (res == 0);
}

gboolean
gkr_keyring_save_to_disk (GkrKeyring *keyring)
{
	struct stat statbuf;
	GkrBuffer out;
	int fd;
	char *dirname;
	char *template;
	gboolean ret = TRUE;
	
	if (keyring->locked) {
		/* Can't save locked keyrings */
		return FALSE;
	}

	if (keyring->file == NULL) {
		/* Not file backed */
		return TRUE;
	}
	
	gkr_buffer_init_full (&out, 4096, g_realloc);

	if (generate_file (&out, keyring)) {
		dirname = g_path_get_dirname (keyring->file);
		template = g_build_filename (dirname, ".keyringXXXXXX", NULL);
		
		fd = g_mkstemp (template);
		if (fd != -1) {
			fchmod (fd, S_IRUSR | S_IWUSR);
			if (write_all (fd, out.buf, out.len) == 0) {
#ifdef HAVE_FSYNC
			fsync (fd);
#endif
				close (fd);
				if (rename (template, keyring->file) == 0) {
					if (stat (keyring->file, &statbuf) == 0) {
						keyring->file_mtime = statbuf.st_mtime;
					}
				} else {
					unlink (template);
				}
			} else {
				close (fd);
			}
		} else {
			g_warning ("Can't open keyring save file %s", template);
			perror ("mkstemp error: ");
			ret = FALSE;
		}
		g_free (template);
		g_free (dirname);
	} else {
		g_warning ("Internal error: Unable to generate data for keyring %s\n", keyring->keyring_name);
		ret = FALSE;
	}
	
	gkr_buffer_uninit (&out);
	return ret;
}

gboolean
gkr_keyring_lock (GkrKeyring *keyring)
{
	if (keyring->locked)
		return TRUE;

	/* Never lock the session keyring */
	if (keyring->file == NULL)
		return TRUE;

	g_assert (keyring->password != NULL);
	
	gnome_keyring_free_password (keyring->password);
	keyring->password = NULL;
	if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
		/* Failed to re-read, remove the keyring */
		g_warning ("Couldn't re-read keyring %s\n", keyring->keyring_name);
		gkr_keyrings_remove (keyring);
	}
	
	return TRUE;
}

gboolean
gkr_keyring_unlock (GkrKeyring *keyring, const gchar *password)
{
	if (!keyring->locked)
		return TRUE;
		
	g_assert (keyring->password == NULL);
		
	keyring->password = gnome_keyring_memory_strdup (password);
	if (!gkr_keyring_update_from_disk (keyring, TRUE)) {
		gnome_keyring_free_password (keyring->password);
		keyring->password = NULL;
	}
	if (keyring->locked) {
		g_assert (keyring->password == NULL);
		return FALSE;
	} else {
		g_assert (keyring->password != NULL);
		return TRUE;
	}
}
