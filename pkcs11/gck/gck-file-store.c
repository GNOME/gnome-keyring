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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "gck-attributes.h"
#include "gck-crypto.h"
#include "gck-file-store.h"
#include "gck-object.h"
#include "gck-transaction.h"
#include "gck-util.h"

#include "common/gkr-buffer.h"
#include "common/gkr-secure-memory.h"

#include <glib/gstdio.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 

#include <gcrypt.h>

enum {
	PROP_0,
	PROP_FILENAME,
	PROP_LOCKED
};


enum {
	ENTRY_CREATED,
	ENTRY_DESTROYED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _GckFileStore {
	GckStore parent;
	
	GHashTable *privates;
	GHashTable *publics;
	GHashTable *object_by_unique;
	GHashTable *unique_by_object;
	
	gchar *filename;
	time_t last_mtime;
	gboolean locked;
	guchar *password;
	gsize n_password;
	gboolean unlock_failures;
	
	/* Valid when in a transaction */
	GckTransaction *transaction;
	int previous_fd;
	int transaction_fd;
	gchar *transaction_path;
};

G_DEFINE_TYPE (GckFileStore, gck_file_store, GCK_TYPE_STORE);

#define PUBLIC_ALLOC (GkrBufferAllocator)g_realloc
#define PRIVATE_ALLOC (GkrBufferAllocator)gkr_secure_realloc

typedef gboolean (*BlockFunc) (guint block, GkrBuffer *buffer, gpointer user_data);

#define FILE_HEADER ((const guchar*)"Gnome Keyring Store 2\n\r\0")
#define FILE_HEADER_LEN 24

#define FILE_BLOCK_PRIVATE  0x70727632  /* ie: "prv2" */
#define FILE_BLOCK_PUBLIC   0x70756232  /* ie: "pub2" */

#define MAX_LOCK_TRIES 20

/* -----------------------------------------------------------------------------
 * HELPERS 
 */

static void
attribute_free (gpointer data)
{
	CK_ATTRIBUTE_PTR attr = data;
	if (attr) {
		g_free (attr->pValue);
		g_slice_free (CK_ATTRIBUTE, attr);
	}
}

static CK_ATTRIBUTE_PTR
attribute_dup (CK_ATTRIBUTE_PTR attr)
{
	CK_ATTRIBUTE_PTR copy;
	g_assert (attr);
	copy = g_slice_new (CK_ATTRIBUTE);
	copy->ulValueLen = attr->ulValueLen;
	copy->pValue = g_memdup (attr->pValue, copy->ulValueLen);
	copy->type = attr->type;
	return copy;
}

static gboolean
read_all_bytes (int fd, guchar *buf, gsize len)
{
	gsize all = len;
	int res;
	
	while (len > 0) {
		
		res = read (fd, buf, len);
		if (res <= 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			if (res < 0 || len != all)
				g_warning ("couldn't read %u bytes from store file: %s", 
				           (guint)all, g_strerror (errno));
			return FALSE;
		} else  {
			len -= res;
			buf += res;
		}
	}
	
	return TRUE;
}

static gboolean
write_all_bytes (int fd, const guchar *buf, gsize len)
{
	gsize all = len;
	int res;
	
	while (len > 0) {
		
		res = write (fd, buf, len);

		if (res <= 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			g_warning ("couldn't write %u bytes to store file: %s", 
			           (guint)all, res < 0 ? g_strerror (errno) : "");
			return FALSE;
		} else  {
			len -= res;
			buf += res;
		}
	}
	
	return TRUE;
}

static gboolean
parse_file_blocks (int file, BlockFunc block_func, gpointer user_data)
{
	gchar header[FILE_HEADER_LEN];
	GkrBuffer buffer;
	gboolean ret;
	guint32 block;
	guint32 length;
	gsize offset;
	
	g_assert (file != -1);
	g_assert (block_func);
	
	/* Zero length file is valid */
	if (!read_all_bytes (file, (guchar*)header, FILE_HEADER_LEN))
		return TRUE;
	
	/* Check the header */
	if (memcmp (header, FILE_HEADER, FILE_HEADER_LEN) != 0) {
		g_message ("invalid header in store file");
		return FALSE;
	}

	gkr_buffer_init_full (&buffer, 1024, (GkrBufferAllocator)g_realloc);

	ret = FALSE;
	for (;;) {

		gkr_buffer_reset (&buffer);
		gkr_buffer_resize (&buffer, 8);
		offset = 0;

		/* Read in a set of bytes */
		if (!read_all_bytes (file, buffer.buf, 8)) {
			ret = TRUE;
			break;
		}
		
		/* Decode it as the number of bytes in the next section */
		if (!gkr_buffer_get_uint32 (&buffer, offset, &offset, &length) ||
		    !gkr_buffer_get_uint32 (&buffer, offset, &offset, &block) || 
		    length < 8) {
			g_message ("invalid block size or length in store file");
			break;
		}
		
		/* Read in that amount of bytes */
		gkr_buffer_resize (&buffer, length - 8);
		if (!read_all_bytes (file, buffer.buf, length - 8)) 
			break;

		if (!(block_func) (block, &buffer, user_data))
			break;
	}
	
	gkr_buffer_uninit (&buffer);
	return ret;
}

static gboolean
write_file_block (int file, guint block, GkrBuffer *buffer)
{
	GkrBuffer header;
	gboolean ret;
	
	g_assert (file != -1);
	g_assert (buffer);
	
	/* Write out the 8 bytes of header */
	gkr_buffer_init_full (&header, 8, (GkrBufferAllocator)g_realloc);
	gkr_buffer_add_uint32 (&header, buffer->len + 8);
	gkr_buffer_add_uint32 (&header, block);
	g_assert (!gkr_buffer_has_error (&header));
	g_assert (header.len == 8);
	ret = write_all_bytes (file, header.buf, header.len);
	gkr_buffer_uninit (&header);
	
	if (ret != TRUE)
		return FALSE;
	
	/* Now write out the remainder of the data */
	return write_all_bytes (file, buffer->buf, buffer->len);
}

static gboolean
hash_buffer (GkrBuffer *buffer)
{
	const gchar *salgo;
	gsize length;
	guchar *hash;
	gsize n_hash;
	int algo;
	
	/* The length needs to be the first thing in the buffer */
	g_assert (buffer->len > 4);
	g_assert (gkr_buffer_decode_uint32 (buffer->buf) == buffer->len);
	
	length = buffer->len;
	
	algo = GCRY_MD_SHA256;
	salgo = gcry_md_algo_name (algo);
	g_return_val_if_fail (salgo, FALSE);
	n_hash = gcry_md_get_algo_dlen (algo);
	g_return_val_if_fail (n_hash > 0, FALSE);
	
	gkr_buffer_add_string (buffer, salgo);
	hash = gkr_buffer_add_byte_array_empty (buffer, n_hash);
	g_return_val_if_fail (hash, FALSE);
	
	gcry_md_hash_buffer (algo, hash, buffer->buf, length);
	return TRUE;
}

static gboolean
validate_buffer (GkrBuffer *buffer, gsize *offset)
{
	const guchar *hash;
	gchar *salgo, *check;
	gsize n_hash, hash_offset;
	guint32 length;
	int algo;
	
	g_assert (buffer);
	g_assert (offset);
	
	*offset = 0;
	
	if (!gkr_buffer_get_uint32 (buffer, *offset, offset, &length) || 
	    !gkr_buffer_get_string (buffer, length, &hash_offset, &salgo, PUBLIC_ALLOC))
		return FALSE;
	
	algo = gcry_md_map_name (salgo);
	if (algo == 0) {
		g_warning ("unsupported hash algorithm: %s", salgo);
		g_free (salgo);
		return FALSE;
	}
	g_free (salgo);
	
	if (!gkr_buffer_get_byte_array (buffer, hash_offset, &hash_offset, &hash, &n_hash))
		return FALSE;
	
	if (n_hash != gcry_md_get_algo_dlen (algo)) {
		g_warning ("invalid hash length in store file");
		return FALSE;
	}
	
	check = g_malloc0 (n_hash);
	gcry_md_hash_buffer (algo, check, buffer->buf, length);
	if (memcmp (check, hash, n_hash) != 0)
		return FALSE;
	
	return TRUE;
}

static gboolean
create_cipher (int calgo, int halgo, const guchar *password, gsize n_password, 
               const guchar *salt, gsize n_salt, guint iterations, gcry_cipher_hd_t *cipher)
{
	gsize n_key, n_block;
	guchar *key, *iv;
	gcry_error_t gcry;
	
	g_assert (salt);
	g_assert (cipher);

	n_key = gcry_cipher_get_algo_keylen (calgo);
	g_return_val_if_fail (n_key, FALSE);
	n_block = gcry_cipher_get_algo_blklen (calgo);
	g_return_val_if_fail (n_block, FALSE);

	/* Allocate memory for the keys */
	key = gcry_malloc_secure (n_key);
	g_return_val_if_fail (key, FALSE);
	iv = g_malloc0 (n_block);
	
	if (!gck_crypto_symkey_generate_simple (calgo, halgo, (const gchar*)password, 
	                                        n_password, salt, n_salt, iterations, &key, &iv)) {
		gcry_free (key);
		g_free (iv);
		return FALSE;
	}
	
	gcry = gcry_cipher_open (cipher, calgo, GCRY_CIPHER_MODE_CBC, 0);
	if (gcry) {
		g_warning ("couldn't create cipher context: %s", gcry_strerror (gcry));
		gcry_free (key);
		g_free (iv);
		return FALSE;
	}

	gcry = gcry_cipher_setkey (*cipher, key, n_key);
	g_return_val_if_fail (!gcry, FALSE);
	gcry_free (key);

	gcry = gcry_cipher_setiv (*cipher, iv, n_block);
	g_return_val_if_fail (!gcry, FALSE);
	g_free (iv);
	
	return TRUE;
}

static gboolean
encrypt_buffer (GkrBuffer *input, const guchar *password, 
                gsize n_password, GkrBuffer *output)
{
	gcry_cipher_hd_t cipher;
	gcry_error_t gcry;
	guchar salt[8];
	guint32 iterations;
	int calgo, halgo;
	const gchar *salgo;
	guchar *dest;
	gsize n_block;
	
	g_assert (input);
	g_assert (output);
	
	/* The algorithms we're going to use */
	calgo = GCRY_CIPHER_AES128;
	halgo = GCRY_MD_SHA256;
	
	/* Prepare us some salt */
	gcry_create_nonce (salt, sizeof (salt));
	
	/* Prepare us the iterations */
	iterations = 1000 + (int) (1000.0 * rand() / (RAND_MAX + 1.0));
	
	/* Write out crypto algorithm */
	salgo = gcry_cipher_algo_name (calgo);
	g_return_val_if_fail (salgo, FALSE);
	gkr_buffer_add_string (output, salgo);
	
	/* Write out the hash algorithm */
	salgo = gcry_md_algo_name (halgo);
	g_return_val_if_fail (halgo, FALSE);
	gkr_buffer_add_string (output, salgo);
	
	/* Write out the iterations */
	gkr_buffer_add_uint32 (output, iterations);
	
	/* And write out the salt */
	gkr_buffer_add_byte_array (output, salt, sizeof (salt));
	
	/* Okay now use the above info to create our cipher context */
	if (!create_cipher (calgo, halgo, password, n_password, salt,
	                    sizeof (salt), iterations, &cipher))
		return FALSE;
	
	/* Significant block sizes */
	n_block = gcry_cipher_get_algo_blklen (calgo);
	g_return_val_if_fail (n_block, FALSE);
	
	/* Pad the buffer to a multiple of block length */
	while (input->len % n_block != 0)
		gkr_buffer_add_byte (input, 0);
	
	/* Now reserve space for it in the output block, and encrypt */
	dest = gkr_buffer_add_byte_array_empty (output, input->len);
	g_return_val_if_fail (dest, FALSE);

	gcry = gcry_cipher_encrypt (cipher, dest, input->len, input->buf, input->len);
	g_return_val_if_fail (!gcry, FALSE);
	
	gcry_cipher_close (cipher);

	return TRUE;
}

static gboolean
decrypt_buffer (GkrBuffer *input, gsize *offset, const guchar *password, 
                gsize n_password, GkrBuffer *output)
{
	gcry_cipher_hd_t cipher;
	gcry_error_t gcry;
	const guchar *salt, *data;
	gsize n_block, n_salt, n_data;
	guint32 iterations;
	int calgo, halgo;
	gchar *salgo;

	g_assert (input);
	g_assert (output);
	g_assert (offset);

	/* Read in and interpret the cipher algorithm */
	if (!gkr_buffer_get_string (input, *offset, offset, &salgo, NULL))
		return FALSE;
	calgo = gcry_cipher_map_name (salgo); 
	if (!calgo) {
		g_warning ("unsupported crypto algorithm: %s", salgo);
		g_free (salgo);
		return FALSE;
	}
	g_free (salgo);
		
	/* Read in and interpret the hash algorithm */
	if (!gkr_buffer_get_string (input, *offset, offset, &salgo, NULL))
		return FALSE;
	halgo = gcry_md_map_name (salgo);
	if (!halgo) {
		g_warning ("unsupported crypto algorithm: %s", salgo);
		g_free (salgo);
		return FALSE;
	}
	g_free (salgo);
		
	/* Read in the iterations, salt, and encrypted data */
	if (!gkr_buffer_get_uint32 (input, *offset, offset, &iterations) ||
	    !gkr_buffer_get_byte_array (input, *offset, offset, &salt, &n_salt) ||
	    !gkr_buffer_get_byte_array (input, *offset, offset, &data, &n_data))
		return FALSE;

	/* Significant block sizes */
	n_block = gcry_cipher_get_algo_blklen (calgo);
	g_return_val_if_fail (n_block, FALSE);
	
	/* Make sure the encrypted data is of a good length */
	if (n_data % n_block != 0) {
		g_warning ("encrypted data in file store is of an invalid length for algorithm");
		return FALSE;
	}

	/* Create the cipher context */
	if (!create_cipher (calgo, halgo, password, n_password, 
	                    salt, n_salt, iterations, &cipher))
		return FALSE;

	/* Now reserve space for it in the output block, and encrypt */
	gkr_buffer_reset (output);
	gkr_buffer_resize (output, n_data);

	gcry = gcry_cipher_decrypt (cipher, output->buf, output->len, data, n_data);
	g_return_val_if_fail (!gcry, FALSE);
	
	gcry_cipher_close (cipher);

	return TRUE;
}

/* ----------------------------------------------------------------------------------------
 * INTERNAL
 */

static GHashTable*
add_entry (GHashTable *entries, gchar *unique)
{
	GHashTable *attributes;
	
	g_assert (entries);
	g_assert (unique);
	
	attributes = g_hash_table_new_full (gck_util_ulong_hash, gck_util_ulong_equal, NULL, attribute_free);
	g_hash_table_replace (entries, unique, attributes);

	return attributes;
}

static const gchar*
read_entry (GckFileStore *self, GHashTable *entries, 
            GkrBuffer *buffer, gsize *offset)
{
	gboolean added = FALSE;
	CK_ATTRIBUTE attr;
	CK_ATTRIBUTE_PTR at;
	gpointer key, value;
	GHashTable *attributes;
	gchar *unique, *str;
	const guchar *data;
	GckObject *object;
	gsize n_data;
	guint64 type;
	guint32 count, i;
	
	g_assert (GCK_IS_FILE_STORE (self));
	g_assert (buffer);
	g_assert (offset);
	g_assert (entries);
	
	if (!gkr_buffer_get_string (buffer, *offset, offset, &str, (GkrBufferAllocator)g_realloc))
		return NULL;
	
	if (g_hash_table_lookup_extended (entries, str, &key, &value)) {
		unique = key;
		attributes = value;
		g_free (str);

		/* Any object that's associated with this */
		object = g_hash_table_lookup (self->object_by_unique, unique);
		added = FALSE;

	} else {
		unique = str;
		attributes = add_entry (entries, unique);
		
		/* No object should yet be associated */
		object = NULL;
		added = TRUE;
	} 
	
	if (!gkr_buffer_get_uint32 (buffer, *offset, offset, &count))
		return NULL;
	
	for (i = 0; i < count; ++i) {
		if (!gkr_buffer_get_uint64 (buffer, *offset, offset, &type) ||
		    !gkr_buffer_get_byte_array (buffer, *offset, offset, &data, &n_data))
			return NULL;
		
		attr.type = type;
		attr.pValue = (CK_VOID_PTR)data;
		attr.ulValueLen = n_data;
		
		at = g_hash_table_lookup (attributes, &attr.type);
		if (at != NULL && gck_attribute_equal (&attr, at))
			continue;
		
		at = attribute_dup (&attr);
		g_hash_table_replace (attributes, &(at->type), at);
		
		if (object != NULL) 
			gck_object_notify_attribute (object, at->type);
	}
	
	if (added) {
		g_assert (!object);
		g_signal_emit (self, signals[ENTRY_CREATED], 0, unique);
	}
	
	g_assert (unique);
	return unique;
}

static void
clear_each_entry (gpointer key, gpointer value, gpointer data)
{
	GHashTable *attributes = value;
	g_hash_table_remove_all (attributes);
}

static void
copy_each_unique_id (gpointer key, gpointer value, gpointer data)
{
	g_hash_table_insert (data, g_strdup (key), GUINT_TO_POINTER (1));
}

static void
destroy_each_unique_id (gpointer key, gpointer value, gpointer data)
{
	/* Our default handler does the actual remove */
	g_signal_emit (data, signals[ENTRY_DESTROYED], 0, key);
}

static gboolean
read_entries (GckFileStore *self, GHashTable *entries, GkrBuffer *buffer, gsize *offset)
{
	GHashTable *checks;
	const gchar *unique;
	guint32 count, i;
	
	g_assert (GCK_IS_FILE_STORE (self));
	g_assert (entries);
	g_assert (buffer);
	g_assert (offset);
	
	/* The number of entries */
	if (!gkr_buffer_get_uint32 (buffer, *offset, offset, &count))
		return FALSE;

	checks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	g_hash_table_foreach (entries, copy_each_unique_id, checks);
	
	for (i = 0; i < count; ++i) {
		unique = read_entry (self, entries, buffer, offset);
		if (!unique) {
			g_hash_table_destroy (checks);
			return FALSE;
		}
		
		g_hash_table_remove (checks, unique);
	}

	g_hash_table_foreach (checks, destroy_each_unique_id, self);
	g_hash_table_destroy (checks);
	return TRUE;
}

static gboolean
read_from_block (guint block, GkrBuffer *buffer, gpointer user_data)
{
	GckFileStore *self;
	gsize offset;
	GkrBuffer custom;
	GHashTable *attributes;
	gboolean ret = FALSE;
	
	g_assert (GCK_IS_FILE_STORE (user_data));
	g_assert (buffer);

	self = GCK_FILE_STORE (user_data);
	
	switch (block) {
	case FILE_BLOCK_PRIVATE:
		/* Skip private blocks when not unlocked */
		if (self->locked)
			return TRUE;

		attributes = self->privates;
		gkr_buffer_init_full (&custom, 1024, gkr_secure_realloc);

		offset = 0;
		if (!decrypt_buffer (buffer, &offset, self->password, self->n_password, &custom)) {
			g_warning ("couldn't decrypt private attributes in store file");
			gkr_buffer_uninit (&custom);
			return FALSE;
		}
		
		buffer = &custom;
		break;
		
	case FILE_BLOCK_PUBLIC:
		attributes = self->publics;
		gkr_buffer_init_static (&custom, NULL, 0);
		break;
		
	default:
		return TRUE;
	}
	
	offset = 0;

	/* Validate the buffer hash, failure is usually a bad password */
	if (!validate_buffer (buffer, &offset)) {
		if (block == FILE_BLOCK_PRIVATE)
			++self->unlock_failures;
		ret = FALSE;
	} else {
		ret = read_entries (self, attributes, buffer, &offset);
	}
	
	gkr_buffer_uninit (&custom);
	return ret;	
}

static void
write_each_attribute (gpointer key, gpointer value, gpointer data)
{
	CK_ATTRIBUTE_PTR attr = value;
	GkrBuffer *buffer = data;
	gkr_buffer_add_uint64 (buffer, attr->type);
	g_assert (attr->ulValueLen != (gulong)-1);
	gkr_buffer_add_byte_array (buffer, attr->pValue, attr->ulValueLen);
}

static void
write_each_entry (gpointer key, gpointer value, gpointer data)
{
	GkrBuffer *buffer = data;
	const gchar *unique = key;
	GHashTable *attributes = value;
	
	gkr_buffer_add_string (buffer, unique);
	gkr_buffer_add_uint32 (buffer, g_hash_table_size (attributes));
	g_hash_table_foreach (attributes, write_each_attribute, buffer);
}

static gboolean
write_entries (GckFileStore *self, GkrBuffer *output, GHashTable *entries, gboolean is_private)
{
	GkrBuffer secure;
	GkrBuffer *buffer;
	gsize offset;
	
	g_assert (GCK_FILE_STORE (self));
	g_assert (output);
	
	if (is_private) {
		gkr_buffer_init_full (&secure, 1024, PRIVATE_ALLOC);
		buffer = &secure;
	} else {
		gkr_buffer_init_static (&secure, NULL, 0);
		buffer = output;
	}
	
	/* Reserve space for the length */
	offset = buffer->len;
	gkr_buffer_add_uint32 (buffer, 0);
	
	/* The number of attributes we'll be encountering */
	gkr_buffer_add_uint32 (buffer, g_hash_table_size (entries));
	
	/* Fill in the attributes */
	g_hash_table_foreach (entries, write_each_entry, buffer);
	
	g_return_val_if_fail (!gkr_buffer_has_error (buffer), FALSE);
	
	/* Fill in the length */
	gkr_buffer_set_uint32 (buffer, offset, buffer->len);
	
	/* Hash the entire dealio */
	if (!hash_buffer (buffer)) {
		gkr_buffer_uninit (&secure);
		return FALSE;
	}
	
	if (is_private) {
		if (!encrypt_buffer (buffer, self->password, self->n_password, output)) {
			gkr_buffer_uninit (&secure);
			return FALSE;
		}
	}

	gkr_buffer_uninit (&secure);
	return TRUE;
}

static gboolean
write_entries_block (GckFileStore *self, GHashTable *entries)
{
	GkrBuffer buffer;
	gboolean is_private;
	gboolean ret;
	guint32 block;
	
	g_assert (GCK_IS_FILE_STORE (self));
	g_assert (self->transaction_fd != -1);
	g_assert (entries);
	
	if (entries == self->privates) {
		is_private = TRUE;
		block = FILE_BLOCK_PRIVATE;
	} else {
		is_private = FALSE;
		block = FILE_BLOCK_PUBLIC;
	}

	g_assert (!is_private || !self->locked);
	gkr_buffer_init_full (&buffer, 1024, PUBLIC_ALLOC);

	ret = write_entries (self, &buffer, entries, is_private);
	if (ret == TRUE && gkr_buffer_has_error (&buffer)) {
		g_warning ("couldn't prepare file store buffer for writing");
		g_return_val_if_reached (FALSE);
	}
	
	ret = write_file_block (self->transaction_fd, block, &buffer);
	gkr_buffer_uninit (&buffer);
	return ret;
}

static gboolean
write_extraneous_block (guint block, GkrBuffer *buffer, gpointer user_data)
{
	GckFileStore *self = GCK_FILE_STORE (user_data);
	
	g_assert (GCK_IS_FILE_STORE (user_data));
	g_assert (self->transaction_fd != -1);
	g_assert (buffer);
	
	self = GCK_FILE_STORE (user_data);
	
	switch (block) {
	
	/* We can always write public attribute blocks, skip. */
	case FILE_BLOCK_PUBLIC:
		return TRUE;
		
	/* We can write private attribute blocks when not locked, skip. */
	case FILE_BLOCK_PRIVATE:
		if (!self->locked)
			return TRUE;
		break;
		
	default:
		break;
	};
	
	/* Write out the block we don't or can't write */
	if (!write_file_block (self->transaction_fd, block, buffer))
		return FALSE;
	
	return TRUE;
}

static void
cleanup_transaction (GckFileStore *self, GckTransaction *transaction)
{
	g_assert (GCK_IS_FILE_STORE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));
	g_assert (self->transaction == transaction);
	
	if (self->previous_fd != -1)
		close (self->previous_fd);
	self->previous_fd = -1;
	
	if (self->transaction_fd != -1)
		close (self->transaction_fd);
	self->transaction_fd = -1;
	
	if (self->transaction_path) {
		g_unlink (self->transaction_path);
		g_free (self->transaction_path);
		self->transaction_path = NULL;
	}
	
	g_object_unref (self->transaction);
	self->transaction = NULL;
}

static void
fail_transaction (GckFileStore *self, GckTransaction *transaction)
{
	gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
	cleanup_transaction (self, transaction);
}

static gboolean
complete_transaction (GckTransaction *transaction, GckFileStore *self, gpointer unused)
{
	struct stat sb;
	
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), FALSE);
	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), FALSE);
	g_return_val_if_fail (self->transaction == transaction, FALSE);
	
	if (!gck_transaction_get_failed (transaction)) {

		if (!self->locked) {
			if (!write_entries_block (self, self->privates))
				return FALSE;
		}
			
		if (!write_entries_block (self, self->publics))
			return FALSE;
		
		/* Move the file into place */
		if (g_rename (self->transaction_path, self->filename) == -1) {
			g_warning ("couldn't rename temporary store file: %s", self->transaction_path);
			return FALSE;
		}
		
		/* Stat the file and save away the last mtime */
		if (stat (self->filename, &sb) >= 0)
			self->last_mtime = sb.st_mtime;
		
	} else {
		
		/* Transaction failed, load the old stuff again */
		gck_file_store_refresh (self);
	}
	
	/* And we're all done */
	cleanup_transaction (self, transaction);
	return TRUE;
}

#ifndef HAVE_FLOCK
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
	
static int flock(int fd, int operation)
{
	struct flock flock;
	
	switch (operation & ~LOCK_NB) {
	case LOCK_SH:
		flock.l_type = F_RDLCK;
		break;
	case LOCK_EX:
		flock.l_type = F_WRLCK;
		break;
	case LOCK_UN:
		flock.l_type = F_UNLCK;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	
	flock.l_whence = 0;
	flock.l_start = 0;
	flock.l_len = 0;
	
	return fcntl (fd, (operation & LOCK_NB) ? F_SETLK : F_SETLKW, &flock);
}
#endif /* !HAVE_FLOCK */ 

static gboolean
prepare_transaction (GckFileStore *self, GckTransaction *transaction)
{
	struct stat sb;
	guint tries = 0;
	
	g_assert (GCK_IS_FILE_STORE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));

	if (self->transaction) {
		g_return_val_if_fail (self->transaction == transaction, FALSE);
		return TRUE;
	}
	
	g_return_val_if_fail (self->filename, FALSE);
	g_assert (self->previous_fd == -1);
	
	self->transaction = g_object_ref (transaction);

	/* File lock retry loop */
	for (tries = 0; TRUE; ++tries) {
		if (tries > MAX_LOCK_TRIES) {
			g_message ("couldn't write to store file: %s: file is locked", self->filename);
			fail_transaction (self, transaction);
			return FALSE;
		}

		self->previous_fd = open (self->filename, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
		if (self->previous_fd == -1) {
			g_message ("couldn't open store file: %s: %s", self->filename, g_strerror (errno));
			fail_transaction (self, transaction);
			return FALSE;
		}
	
		if (flock (self->previous_fd, LOCK_EX | LOCK_NB) < 0) {

			if (errno != EWOULDBLOCK) {
				g_message ("couldn't lock store file: %s: %s", self->filename, g_strerror (errno));
				fail_transaction (self, transaction);
				return FALSE;
			}
				
			close (self->previous_fd);
			self->previous_fd = -1;
			g_usleep (200000);
			continue;
		}

		/* Successfully opened file */;
		break;
	}

	/* See if file needs updating */
	if (fstat (self->previous_fd, &sb) >= 0 && sb.st_mtime != self->last_mtime) {
		if (!parse_file_blocks (self->previous_fd, read_from_block, self) || 
		    lseek (self->previous_fd, 0, SEEK_SET) != 0) {
			g_message ("couldn't update store from file: %s", self->filename);
			fail_transaction (self, transaction);
			return FALSE;
		}
			
		self->last_mtime = sb.st_mtime;
	}
	
	/* Open the new file */
	g_assert (self->transaction_fd == -1);
	self->transaction_path = g_strdup_printf ("%s.XXXXXX", self->filename);
	self->transaction_fd = g_mkstemp (self->transaction_path);
	if (self->transaction_fd == -1) {
		g_message ("couldn't open new temporary store file: %s: %s", self->filename, g_strerror (errno));
		fail_transaction (self, transaction);
		return FALSE;
	}
	
	/* Now write out everything that we don't understand from previous one into the new */
	if (!write_all_bytes (self->transaction_fd, FILE_HEADER, FILE_HEADER_LEN) ||
	    !parse_file_blocks (self->previous_fd, write_extraneous_block, self)) {
		fail_transaction (self, transaction);
		return FALSE;
	}
	
	/* And we're ready for changes. */
	gck_transaction_add (transaction, self, (GckTransactionFunc)complete_transaction, NULL);
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void 
gck_file_store_real_entry_created (GckFileStore *self, const gchar *unique_id)
{
	/* Actual action happens elsewhere */
	g_return_if_fail (g_hash_table_lookup (self->publics, unique_id) || 
	                  g_hash_table_lookup (self->privates, unique_id));
}

static void 
gck_file_store_real_entry_destroyed (GckFileStore *self, const gchar *unique_id)
{
	/* 
	 * Note we don't remove the object -> unique mapping, we 
	 * keep that unrelated.
	 */
	
	/* Actual action happens here */
	if (!g_hash_table_remove (self->publics, unique_id)) {
		g_return_if_fail (self->locked);
		if (!g_hash_table_remove (self->privates, unique_id))
			g_return_if_reached ();
	}
}

static CK_RV
gck_file_store_real_read_value (GckStore *base, GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckFileStore *self = GCK_FILE_STORE (base);
	CK_ATTRIBUTE_PTR at;
	GHashTable *attributes;
	const gchar *unique;

	g_return_val_if_fail (GCK_IS_FILE_STORE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_OBJECT (object), CKR_GENERAL_ERROR);
	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);

	unique = g_hash_table_lookup (self->unique_by_object, object);
	if (!unique)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	if (self->last_mtime == 0) {
		if (!gck_file_store_refresh (self))
			return CKR_FUNCTION_FAILED;
	}
	
	attributes = g_hash_table_lookup (self->publics, unique);
	if (attributes == NULL) { 
		attributes = g_hash_table_lookup (self->privates, unique);
		if (attributes && self->locked)
			return CKR_USER_NOT_LOGGED_IN;
	}
	
	if (!attributes)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	at = g_hash_table_lookup (attributes, &(attr->type));
	if (at == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	g_assert (at->type == attr->type);
	
	/* Yes, we don't fill a buffer, just return pointer */
	attr->pValue = at->pValue;
	attr->ulValueLen = at->ulValueLen;
	
	return CKR_OK;
}

static void
gck_file_store_real_write_value (GckStore *base, GckTransaction *transaction, 
                                 GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckFileStore *self = GCK_FILE_STORE (base);
	CK_ATTRIBUTE_PTR at;
	GHashTable *attributes;
	const gchar *unique;
	
	g_return_if_fail (GCK_IS_FILE_STORE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (attr);

	unique = g_hash_table_lookup (self->unique_by_object, object);
	if (!unique) {
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_READ_ONLY);
		return;
	}
	
	if (self->last_mtime == 0) {
		if (!gck_file_store_refresh (self))
			gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
	}

	attributes = g_hash_table_lookup (self->publics, unique);
	if (attributes == NULL) {
		attributes = g_hash_table_lookup (self->privates, unique);
		if (attributes && self->locked) {
			gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
			return;
		}
	}

	if (!attributes) {
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_READ_ONLY);
		return;
	}
	
	/* No need to go any further if no change */
	at = g_hash_table_lookup (attributes, &(attr->type));
	if (at != NULL && gck_attribute_equal (at, attr))
		return;

	if (!prepare_transaction (self, transaction))
		return;

	attr = attribute_dup (attr);
	g_hash_table_replace (attributes, &(attr->type), attr);
	gck_object_notify_attribute (object, attr->type);
}

static GObject* 
gck_file_store_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckFileStore *self = GCK_FILE_STORE (G_OBJECT_CLASS (gck_file_store_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	

	g_return_val_if_fail (self->filename, NULL);
	
	return G_OBJECT (self);
}

static void
gck_file_store_init (GckFileStore *self)
{
	self->object_by_unique = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	self->unique_by_object = g_hash_table_new (g_direct_hash, g_direct_equal);
	self->publics = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                       NULL, (GDestroyNotify)g_hash_table_unref);
	self->privates = g_hash_table_new_full (g_str_hash, g_str_equal, 
	                                        NULL, (GDestroyNotify)g_hash_table_unref);
	self->previous_fd = -1;
	self->transaction_fd = -1;
	self->locked = TRUE;
}

static void
gck_file_store_dispose (GObject *obj)
{
	GckFileStore *self = GCK_FILE_STORE (obj);

	g_hash_table_remove_all (self->unique_by_object);
	g_hash_table_remove_all (self->object_by_unique);
	
	G_OBJECT_CLASS (gck_file_store_parent_class)->dispose (obj);
}

static void
gck_file_store_finalize (GObject *obj)
{
	GckFileStore *self = GCK_FILE_STORE (obj);

	g_free (self->filename);
	self->filename = NULL;
	
	g_hash_table_destroy (self->object_by_unique);
	self->object_by_unique = NULL;
	g_hash_table_destroy (self->unique_by_object);
	self->unique_by_object = NULL;
	
	g_hash_table_destroy (self->publics);
	g_hash_table_destroy (self->privates);

	gkr_secure_free (self->password);
	self->password = NULL;
	self->n_password = 0;
	
	G_OBJECT_CLASS (gck_file_store_parent_class)->finalize (obj);
}

static void
gck_file_store_set_property (GObject *obj, guint prop_id, const GValue *value, 
                             GParamSpec *pspec)
{
	GckFileStore *self = GCK_FILE_STORE (obj);
	
	switch (prop_id) {
	case PROP_FILENAME:
		g_return_if_fail (!self->filename);
		self->filename = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_file_store_get_property (GObject *obj, guint prop_id, GValue *value, 
                             GParamSpec *pspec)
{
	GckFileStore *self = GCK_FILE_STORE (obj);
	
	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, gck_file_store_get_filename (self));
		break;
	case PROP_LOCKED:
		g_value_set_boolean (value, gck_file_store_get_locked (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_file_store_class_init (GckFileStoreClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckStoreClass *store_class = GCK_STORE_CLASS (klass);
    
	gobject_class->constructor = gck_file_store_constructor;
	gobject_class->dispose = gck_file_store_dispose;
	gobject_class->finalize = gck_file_store_finalize;
	gobject_class->set_property = gck_file_store_set_property;
	gobject_class->get_property = gck_file_store_get_property;

	store_class->read_value = gck_file_store_real_read_value;
	store_class->write_value = gck_file_store_real_write_value;
	
	klass->entry_created = gck_file_store_real_entry_created;
	klass->entry_destroyed = gck_file_store_real_entry_destroyed;
	
	g_object_class_install_property (gobject_class, PROP_FILENAME,
	           g_param_spec_string ("filename", "File Name", "File name of the store", 
	                                NULL, G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (gobject_class, PROP_LOCKED,
	           g_param_spec_boolean ("locked", "Locked", "Whether store is locked", 
	                                 TRUE, G_PARAM_READABLE));
    
	signals[ENTRY_CREATED] = g_signal_new ("entry-created", GCK_TYPE_FILE_STORE, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckFileStoreClass, entry_created),
	                                NULL, NULL, g_cclosure_marshal_VOID__STRING, 
	                                G_TYPE_NONE, 1, G_TYPE_STRING);
	
	signals[ENTRY_DESTROYED] = g_signal_new ("entry-destroyed", GCK_TYPE_FILE_STORE, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GckFileStoreClass, entry_destroyed),
	                                NULL, NULL, g_cclosure_marshal_VOID__STRING, 
	                                G_TYPE_NONE, 1, G_TYPE_STRING);
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckFileStore*
gck_file_store_new (const gchar *filename)
{
	g_return_val_if_fail (filename, NULL);
	g_return_val_if_fail (filename[0], NULL);
	return g_object_new (GCK_TYPE_FILE_STORE, "filename", filename, NULL);
}

gboolean
gck_file_store_have_entry (GckFileStore *self, const gchar *unique_id)
{
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), FALSE);
	g_return_val_if_fail (unique_id, FALSE);

	return (g_hash_table_lookup (self->publics, unique_id) || 
	        g_hash_table_lookup (self->privates, unique_id));
}

void
gck_file_store_create_entry (GckFileStore *self, GckTransaction *transaction,
                             const gchar *unique_id, gboolean is_private)
{
	GHashTable *entries;
	gchar *unique;
	
	g_return_if_fail (GCK_IS_FILE_STORE (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (unique_id);
	
	/* We can't add an entry twice */
	if (is_private) {
		g_return_if_fail (!self->locked);
		entries = self->privates;
	} else {
		entries = self->publics;
	}

	g_return_if_fail (g_hash_table_lookup (entries, unique_id) == NULL);
	
	if (!prepare_transaction (self, transaction))
		return;
	
	unique = g_strdup (unique_id);
	add_entry (entries, unique);
	g_signal_emit (self, signals[ENTRY_CREATED], 0, unique);
}

void
gck_file_store_connect_entry (GckFileStore *self, const gchar *unique_id, GckObject *object)
{
	gchar *unique;
	
	g_return_if_fail (GCK_IS_FILE_STORE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (unique_id);
	
	g_return_if_fail (g_hash_table_lookup (self->object_by_unique, unique_id) == NULL);
	g_return_if_fail (g_hash_table_lookup (self->unique_by_object, object) == NULL);

	unique = g_strdup (unique_id);
	g_hash_table_replace (self->object_by_unique, unique, object);
	g_hash_table_replace (self->unique_by_object, object, unique);
}

void
gck_file_store_disconnect_entry (GckFileStore *self, const gchar *unique_id, GckObject *object)
{
	const gchar *unique;
	g_return_if_fail (GCK_IS_FILE_STORE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (unique_id);
	
	g_return_if_fail (g_hash_table_lookup (self->object_by_unique, unique_id) == object);
	unique = g_hash_table_lookup (self->unique_by_object, object);
	g_return_if_fail (unique && g_str_equal (unique, unique_id));

	g_hash_table_remove (self->unique_by_object, object);
	g_hash_table_remove (self->object_by_unique, unique);
}

void
gck_file_store_destroy_entry (GckFileStore *self, GckTransaction *transaction,
                              const gchar *unique_id)
{
	g_return_if_fail (GCK_IS_FILE_STORE (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (unique_id);

	/* Can't destroy something that doesn't exist */
	if (!g_hash_table_lookup (self->publics, unique_id) && 
	    !g_hash_table_lookup (self->privates, unique_id)) {
		g_return_if_reached ();
	}
	
	if (!prepare_transaction (self, transaction))
		return;

	/* The default handler actually does the deed */
	g_signal_emit (self, signals[ENTRY_DESTROYED], 0, unique_id);
}

const gchar*
gck_file_store_get_filename (GckFileStore *self)
{
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), NULL);
	return self->filename;
}

gboolean
gck_file_store_refresh (GckFileStore *self)
{
	struct stat sb;
	gboolean ret;
	int file;
	
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), FALSE);
	
	/* Open the file for reading */
	file = open (self->filename, O_RDONLY, 0);
	if (file == -1) {
		/* No file, no worries */
		if (errno == ENOENT)
			return TRUE;
		g_message ("couldn't open store file: %s: %s", self->filename, g_strerror (errno));
		return FALSE;
	}

	/* Try and update the last read time */
	if (fstat (file, &sb) >= 0) 
		self->last_mtime = sb.st_mtime;

	ret = parse_file_blocks (file, read_from_block, self);

	/* Force a reread on next write */
	if (ret == FALSE)
		self->last_mtime = 0;
	
	close (file);
	return ret;
}

CK_RV
gck_file_store_unlock (GckFileStore *self, guchar *password,
                       gsize n_password)
{
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), CKR_GENERAL_ERROR);
	
	if (!self->locked)
		return CKR_USER_ALREADY_LOGGED_IN;
	
	/* Don't copy until we're sure it worked */
	g_assert (!self->password);
	self->password = password;
	self->n_password = n_password;
	self->unlock_failures = 0;
	self->locked = FALSE;
	
	if (!gck_file_store_refresh (self)) {
		self->locked = TRUE;
		self->password = NULL;
		self->n_password = 0;
		if (self->unlock_failures)
			return CKR_PIN_INCORRECT;
		else
			return CKR_FUNCTION_FAILED;
	}
	
	if (self->password) {
		self->password = gkr_secure_alloc (n_password);
		memcpy (self->password, password, n_password);
		self->n_password = n_password;
	}
	
	self->locked = FALSE;
	g_object_notify (G_OBJECT (self), "locked");
	return CKR_OK;
}

CK_RV
gck_file_store_lock (GckFileStore *self)
{
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), CKR_GENERAL_ERROR);
	
	if (self->locked)
		return CKR_USER_NOT_LOGGED_IN;

	/* Remove all data for each private one */
	g_hash_table_foreach (self->privates, clear_each_entry, NULL);
	
	gkr_secure_free (self->password);
	self->password = NULL;
	self->n_password = 0;
	self->locked = TRUE;
	g_object_notify (G_OBJECT (self), "locked");
	
	return CKR_OK;
}

gboolean
gck_file_store_get_locked (GckFileStore *self)
{
	g_return_val_if_fail (GCK_IS_FILE_STORE (self), TRUE);
	return self->locked;
}
