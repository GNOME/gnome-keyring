/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-keyring-daemon-file.c - loading and saving the keyring files

   Copyright (C) 2003 Red Hat, Inc

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
*/
#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <glib.h>

#include "gnome-keyring-daemon.h"
#include "gnome-keyring-proto.h"
#include "sha1.h"
#include "aes.h"

time_t keyring_dir_mtime = 0;

static gboolean
encrypt_buffer (GString *buffer, const char *password)
{
        sha1Param shaparam;
        guchar digest[20];
	aesParam param;
	guchar dst[16];
	size_t pos;

	g_assert (buffer->len % 16 == 0);
		     
	if (sha1Reset(&shaparam)) {
		return FALSE;
	}
	if (sha1Update(&shaparam, password, strlen (password))) {
		return FALSE;
	}
	if (sha1Digest(&shaparam, digest)) {
		return FALSE;
	}

	
	if (aesSetup(&param, digest, 128, ENCRYPT)) {
		return FALSE;
	}
	for (pos = 0; pos < buffer->len; pos += 16) {
		if (aesEncrypt (&param, (guint32*) dst, (guint32*) (buffer->str + pos))) {
			return FALSE;
		}
		
		memcpy (buffer->str + pos, dst, 16);
	}

	return TRUE;
}

static gboolean
decrypt_buffer (GString *buffer, const char *password)
{
        sha1Param shaparam;
        guchar digest[20];
	aesParam param;
	guchar dst[16];
	size_t pos;

	if (sha1Reset(&shaparam)) {
		return FALSE;
	}
	if (sha1Update(&shaparam, password, strlen (password))) {
		return FALSE;
	}
	if (sha1Digest(&shaparam, digest)) {
		return FALSE;
	}

	if (aesSetup(&param, digest, 128, DECRYPT)) {
		return FALSE;
	}

	g_assert (buffer->len % 16 == 0);

	for (pos = 0; pos < buffer->len; pos += 16) {
		if (aesDecrypt (&param, (guint32*) dst, (guint32*) (buffer->str + pos))) {
			return FALSE;
		}
		memcpy (buffer->str + pos, dst, 16);
	}
	
	return TRUE;
}

static gboolean
verify_decrypted_buffer (GString *buffer)
{
        sha1Param param;
        guchar digest[20];
	
	if (sha1Reset(&param)) {
		return FALSE;
	}
	if (sha1Update(&param, buffer->str + 20, buffer->len - 20)) {
		return FALSE;
	}
	if (sha1Digest(&param, digest)) {
		return FALSE;
	}
	
	return memcmp (buffer->str, digest, 20) == 0;
}

static char *
get_keyring_dir (void)
{
	char *dir;
	
	dir = g_build_filename (g_get_home_dir (), ".gnome2/keyrings", NULL);
	if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
		if (mkdir (dir, S_IRWXU) < 0) {
			g_warning ("unable to create keyring dir");
		}
	}
	return dir;
}

char *
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

	dir = get_keyring_dir ();
	
	version = 0;
	do {
		if (version == 0) {
			filename = g_strdup_printf ("%s.keyring", base);
		} else {
			filename = g_strdup_printf ("%s%d.keyring", base, version);
		}
		
		path = g_build_filename (dir, filename, NULL);
				
		g_free (filename);
	} while (g_file_test (path, G_FILE_TEST_EXISTS));

	g_free (base);
	g_free (dir);
	
	return path;
}

static gboolean 
generate_acl_data (GString *buffer,
		   GList *acl)
{
	GList *l;
	GnomeKeyringAccessControl *ac;
	
	gnome_keyring_proto_add_uint32 (buffer, g_list_length (acl));

	for (l = acl; l != NULL; l = l->next) {
		ac = l->data;
		
		gnome_keyring_proto_add_uint32 (buffer, ac->types_allowed);
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
		gnome_keyring_proto_add_uint32 (buffer, 0);
	}
	
	
	return TRUE;
}

static gboolean
generate_encrypted_data (GString *buffer, GnomeKeyring *keyring)
{
	GList *l;
	int i;
	GnomeKeyringItem *item;
	
	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		if (!gnome_keyring_proto_add_utf8_string (buffer, item->display_name)) {
			return FALSE;
		}
		if (!gnome_keyring_proto_add_utf8_string (buffer, item->secret)) {
			return FALSE;
		}
		gnome_keyring_proto_add_time (buffer, item->ctime);
		gnome_keyring_proto_add_time (buffer, item->mtime);

		/* reserved: */
		if (!gnome_keyring_proto_add_utf8_string (buffer, NULL)) {
			return FALSE;
		}
		for (i = 0; i < 4; i++) {
			gnome_keyring_proto_add_uint32 (buffer, 0);
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
generate_file (GString *buffer, GnomeKeyring *keyring)
{
	guint flags;
	GList *l;
	GnomeKeyringItem *item;
	GnomeKeyringAttributeList *hashed;
	GString *to_encrypt;
        sha1Param param;
        guchar digest[20];
	int i;

	g_assert (!keyring->locked);
		
	g_string_append_len (buffer, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN);
	g_string_append_c (buffer, 0); /* Major version */
	g_string_append_c (buffer, 0); /* Minor version */
	g_string_append_c (buffer, 0); /* crypto (0 == AEL) */
	g_string_append_c (buffer, 0); /* hash (0 == SHA1) */

	if (!gnome_keyring_proto_add_utf8_string (buffer, keyring->keyring_name)) {
		return FALSE;
	}

	gnome_keyring_proto_add_time (buffer, keyring->mtime);
	gnome_keyring_proto_add_time (buffer, keyring->ctime);
	
	flags = 0;
	if (keyring->lock_on_idle) {
		flags |= 1;
	}
	gnome_keyring_proto_add_uint32 (buffer, flags);
	gnome_keyring_proto_add_uint32 (buffer, keyring->lock_timeout);

	/* Reserved: */
	for (i = 0; i < 4; i++) {
		gnome_keyring_proto_add_uint32 (buffer, 0);
	}

	/* Hashed items: */
	gnome_keyring_proto_add_uint32 (buffer, g_list_length (keyring->items));

	for (l = keyring->items; l != NULL; l = l->next) {
		item = l->data;
		gnome_keyring_proto_add_uint32 (buffer, item->id);
		gnome_keyring_proto_add_uint32 (buffer, item->type);
		
		hashed = gnome_keyring_attributes_hash (item->attributes);

		if (!gnome_keyring_proto_add_attribute_list (buffer, hashed)) {
			gnome_keyring_attribute_list_free (hashed);
			return FALSE;
		}
		gnome_keyring_attribute_list_free (hashed);
	}

	/* Encrypted data: */
	to_encrypt = g_string_new (NULL);
	g_string_append_len (to_encrypt, digest, 20); /* Space for hash */

	if (!generate_encrypted_data (to_encrypt, keyring)) {
		g_string_free (to_encrypt, TRUE);
		return FALSE;
	}

	/* Pad with zeros to multiple of 16 bytes */
	while (to_encrypt->len % 16 != 0) {
		g_string_append_c (to_encrypt, 0);
	}

	sha1Reset(&param);
	sha1Update(&param, to_encrypt->str + 20, to_encrypt->len - 20);
	sha1Digest(&param, digest);
	memcpy (to_encrypt->str, digest, 20);
	
	if (!encrypt_buffer (to_encrypt, keyring->password)) {
		g_string_free (to_encrypt, TRUE);
		return FALSE;
	}
	gnome_keyring_proto_add_uint32 (buffer, to_encrypt->len);
	g_string_append_len (buffer, to_encrypt->str, to_encrypt->len);
	g_string_free (to_encrypt, TRUE);
	
	return TRUE;
}

static int
write_all (int fd, const char *buf, size_t len)
{
	size_t bytes;
	int res;
	
	bytes = 0;
	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (res != EINTR &&
			    res != EAGAIN) {
				return -1;
			}
		} else {
			bytes += res;
		}
	}
	return 0;
}

void
save_keyring_to_disk (GnomeKeyring *keyring)
{
	struct stat statbuf;
	GString *out;
	int fd;
	char *dirname;
	char *template;
	
	if (keyring->locked) {
		/* Can't save locked keyrings */
		return;
	}

	if (keyring->file == NULL) {
		/* Not file backed */
		return;
	}
	
	out = g_string_new (NULL);

	if (generate_file (out, keyring)) {
		dirname = g_path_get_dirname (keyring->file);
		template = g_build_filename (dirname, ".keyringXXXXXX", NULL);
		
		fd = g_mkstemp (template);
		if (fd != -1) {
			fchmod (fd, S_IRUSR | S_IWUSR);
			if (write_all (fd, out->str, out->len) == 0) {
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
		}
		g_free (template);
		g_free (dirname);
	} else {
		g_warning ("Internal error: Unable to generate data for keyring %s\n", keyring->keyring_name);
	}
	g_string_free (out, TRUE);
}

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

static gboolean
decode_acl (GString *buffer, gsize offset, gsize *offset_out, GList **out)
{
	GList *acl;
	guint32 num_acs;
	guint32 x, y;
	int i;
	char *name, *path, *reserved;
	GnomeKeyringApplicationRef *app;
	
	acl = NULL;

	if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &num_acs)) {
		return FALSE;
	}
	for (i = 0; i < num_acs; i++) {
		if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &x)) {
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
		if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &y)) {
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

#define LOCK_ON_IDLE_FLAG (1<<0)

static gboolean
update_keyring_from_data (GnomeKeyring *keyring, GString *buffer)
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
	ItemInfo *items;
	GString to_decrypt;
	gboolean locked;
	GList *old_items;
	GnomeKeyringItem *item;
	char *reserved;

	display_name = NULL;
	items = 0;
	
	if (buffer->len < KEYRING_FILE_HEADER_LEN) {
		return FALSE;
	}
	if (memcmp (buffer->str, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		return FALSE;
	}
	offset = KEYRING_FILE_HEADER_LEN;

	major = buffer->str[offset++];
	minor = buffer->str[offset++];
	crypto = buffer->str[offset++];
	hash = buffer->str[offset++];

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
	if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &flags)) {
		goto bail;
	}
	if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &lock_timeout)) {
		goto bail;
	}
	for (i = 0; i < 4; i++) {
		if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &tmp)) {
			goto bail;
		}
		/* reserved bytes must be zero */
		if (tmp != 0) {
			goto bail;
		}
	}
	if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &num_items)) {
		goto bail;
	}

	items = g_new0 (ItemInfo, num_items);

	for (i = 0; i < num_items; i++) {
		if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset,
						     &items[i].id)) {
			goto bail;
		}
		if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset,
						     &items[i].type)) {
			goto bail;
		}
		if (!gnome_keyring_proto_decode_attribute_list (buffer, offset, &offset,
								&items[i].hashed_attributes)) {
			goto bail;
		}
	}

	if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset,
					     &crypto_size)) {
		goto bail;
	}
	/* Make sure the rest of the file is the crypted part only */
	if (crypto_size % 16 != 0 ||
	    buffer->len - offset != crypto_size) {
		goto bail;
	}
	to_decrypt.str = buffer->str + offset;
	to_decrypt.len = to_decrypt.allocated_len = crypto_size;

	locked = TRUE;
	if (keyring->password != NULL) {
		if (!decrypt_buffer (&to_decrypt, keyring->password)) {
			goto bail;
		}
		if (!verify_decrypted_buffer (&to_decrypt)) {
			g_free (keyring->password);
			keyring->password = NULL;
		} else {
			locked = FALSE;
			offset += 20; /* Skip hash */
			for (i = 0; i < num_items; i++) {
				if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
									  &items[i].display_name)) {
					goto bail;
				}
				if (!gnome_keyring_proto_get_utf8_string (buffer, offset, &offset,
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
					if (!gnome_keyring_proto_get_uint32 (buffer, offset, &offset, &tmp)) {
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


	old_items = keyring->items;
	keyring->items = NULL;

	for (i = 0; i < num_items; i++) {
		item = find_item_in_list (old_items, items[i].id);
		if (item == NULL) {
			item = g_new0 (GnomeKeyringItem, 1);
			item->keyring = keyring;
			item->id = items[i].id;
		} else {
			old_items = g_list_remove (old_items, item);
		}
		keyring->items = g_list_prepend (keyring->items, item);
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
	/* Need to reverse since we added with prepend */
	keyring->items = g_list_reverse (keyring->items);

	g_list_foreach (old_items, (GFunc)gnome_keyring_item_free, NULL);
	g_list_free (old_items);
	
	return TRUE;
 bail:
	g_free (display_name);

	if (items != NULL) {
		for (i = 0; i < num_items; i++) {
			g_free (items[i].display_name);
			g_free (items[i].secret);
			gnome_keyring_attribute_list_free (items[i].hashed_attributes);
			gnome_keyring_attribute_list_free (items[i].attributes);
			gnome_keyring_acl_free (items[i].acl);
		}
		g_free (items);
	}
	
	return FALSE;
}

gboolean
update_keyring_from_disk (GnomeKeyring *keyring,
			  gboolean force_reload)
{
	struct stat statbuf;
	GString buffer;
	char *contents;
	gsize len;

	if (keyring->file == NULL) {
		return TRUE;
	}

	if (stat (keyring->file, &statbuf) < 0) {
		return FALSE;
	}
	if (!force_reload &&
	    statbuf.st_mtime == keyring->file_mtime) {
		return TRUE;
	}
	keyring->file_mtime = statbuf.st_mtime;


	if (!g_file_get_contents (keyring->file,
				  &contents, &len, NULL)) {
		return FALSE;
	}
	buffer.str = contents;
	buffer.len = buffer.allocated_len = len;

	if (!update_keyring_from_data (keyring, &buffer)) {
		return FALSE;
	}
	
	/* TODO: Actually read file,
	 * set locked to false if password set and correct, otherwise unset password
	 * must set name unless i/o or parse failure
	 * return false on i/o or parse failure
	 */
	
	return TRUE;
}

void
update_keyrings_from_disk (void)
{
	char *dirname, *path;
	const char *filename;
	struct stat statbuf;
	GDir *dir;
	GList *old_keyrings;
	GList *l;
	GnomeKeyring *old_keyring, *keyring;
	
	dirname = get_keyring_dir ();

	if (stat (dirname, &statbuf) < 0) {
		return;
	}
	if (statbuf.st_mtime == keyring_dir_mtime) {
		/* Still need to check for file updates */

		for (l = keyrings; l != NULL; l = l->next) {
			update_keyring_from_disk (l->data, FALSE);
		}
		
		return;
	}

	old_keyrings = keyrings;
	keyrings = NULL;

	/* Always move over the session keyring */
	keyrings = g_list_prepend (keyrings, session_keyring);
	old_keyrings = g_list_remove (old_keyrings, session_keyring);
	
	dir = g_dir_open (dirname, 0, NULL);
	if (dir != NULL) {
		while ((filename = g_dir_read_name (dir)) != NULL) {
			if (filename[0] == '.') {
				continue;
			}
			path = g_build_filename (dirname, filename, NULL);
			keyring = NULL;
			for (l = old_keyrings; l != NULL; l = l->next) {
				old_keyring = l->data;
				if (strcmp (old_keyring->file, path) == 0) {
					keyring = old_keyring;
					old_keyrings = g_list_remove (old_keyrings, old_keyring);
					break;
				}
			}
			if (keyring == NULL) {
				keyring = gnome_keyring_new (NULL, path);
				/* remove it from the list for now, loading might fail */
				keyrings = g_list_remove (keyrings, keyring);
			}
			if (update_keyring_from_disk (keyring, FALSE) &&
			    keyring->keyring_name != NULL &&
			    find_keyring (keyring->keyring_name) == NULL) {
				keyrings = g_list_prepend (keyrings, keyring);
			} else {
				gnome_keyring_free (keyring);
			}
			g_free (path);
		}
		g_dir_close (dir);
	}
	
	for (l = old_keyrings; l != NULL; l = l->next) {
		old_keyring = l->data;
		gnome_keyring_free (old_keyring);
	}
	g_list_free (old_keyrings);

	keyring_dir_mtime = statbuf.st_mtime;

	g_free (dirname);
}

