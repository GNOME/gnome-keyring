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

#include "gck-user-storage.h"
#include "gck-user-private-key.h"
#include "gck-user-public-key.h"

#include "gck/gck-certificate.h"
#include "gck/gck-data-asn1.h"
#include "gck/gck-data-file.h"
#include "gck/gck-login.h"
#include "gck/gck-manager.h"
#include "gck/gck-module.h"
#include "gck/gck-serializable.h"
#include "gck/gck-util.h"

#include "egg/egg-hex.h"

#include "pkcs11/pkcs11i.h"

#include <glib/gstdio.h>

#include <libtasn1.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

enum {
	PROP_0,
	PROP_MODULE,
	PROP_DIRECTORY,
	PROP_MANAGER,
	PROP_LOGIN
};

struct _GckUserStorage {
	GckStore parent;

	GckModule *module;
	GckManager *manager;

	/* Information about file data */
	gchar *directory;
	gchar *filename;
	GckDataFile *file;
	time_t last_mtime;
	GckLogin *login;
	
	/* Mapping of objects loaded */
	GHashTable *object_to_identifier;
	GHashTable *identifier_to_object;
	
	/* Valid when in write state */
	GckTransaction *transaction;
	gchar *write_path;
	gint write_fd;
	gint read_fd;
};

G_DEFINE_TYPE (GckUserStorage, gck_user_storage, GCK_TYPE_STORE);

#define MAX_LOCK_TRIES 20

#define UNWANTED_IDENTIFIER_CHARS  ":/\\<>|\t\n\r\v "

/* -----------------------------------------------------------------------------
 * HELPERS 
 */

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

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */


static gchar*
name_for_subject (const guchar *subject, gsize n_subject)
{
	ASN1_TYPE asn;
	gchar *name;
	
	g_assert (subject);
	g_assert (n_subject);
	
	asn = egg_asn1_decode ("PKIX1.Name", subject, n_subject);
	g_return_val_if_fail (asn, NULL);
	
	name = egg_asn1_read_dn_part (asn, "rdnSequence", "CN");
	asn1_delete_structure (&asn);
	
	return name;
}

static gchar*
identifier_for_object (GckObject *object)
{
	GckSerializableIface *serial;
	const gchar *ext;
	gchar *identifier;
	gchar *name = NULL;
	guchar *data;
	gsize n_data;
	
	g_assert (GCK_IS_OBJECT (object));
	g_assert (GCK_IS_SERIALIZABLE (object));
	
	/* Figure out the extension and prefix */
	serial = GCK_SERIALIZABLE_GET_INTERFACE (object);
	ext = serial->extension;
	g_return_val_if_fail (ext, NULL);
	
	/* First we try to use the CN of a subject */
	data = gck_object_get_attribute_data (object, NULL, CKA_SUBJECT, &n_data);
	if (data && n_data) 
		name = name_for_subject (data, n_data);
	g_free (data);
	
	/* Next we try hex encoding the ID */
	if (name == NULL) {
		data = gck_object_get_attribute_data (object, NULL, CKA_ID, &n_data);
		if (data && n_data)
			name = egg_hex_encode (data, n_data);
		g_free (data);
	}
	
	/* Build up the identifier */
	identifier = g_strconcat (name, ext, NULL);
	g_strdelimit (identifier, UNWANTED_IDENTIFIER_CHARS, '_');

	g_free (name);
	return identifier;
}

static GType
type_from_extension (const gchar *extension)
{
	g_assert (extension);
	
	if (strcmp (extension, ".pkcs8") == 0)
		return GCK_TYPE_USER_PRIVATE_KEY;
	else if (strcmp (extension, ".pub") == 0)
		return GCK_TYPE_USER_PUBLIC_KEY;
	else if (strcmp (extension, ".cer") == 0)
		return GCK_TYPE_CERTIFICATE;
	
	return 0;
}


static GType
type_from_identifier (const gchar *identifier)
{
	const gchar *ext;
	
	g_assert (identifier);
	
	ext = strrchr (identifier, '.');
	if (ext == NULL)
		return 0;
	
	return type_from_extension (ext);
}

static gboolean
complete_lock_file (GckTransaction *transaction, GObject *object, gpointer data)
{
	int fd = GPOINTER_TO_INT (data);
	
	/* This also unlocks the file */
	close (fd);
	
	/* Completed successfully */
	return TRUE;
}

static gint
begin_lock_file (GckUserStorage *self, GckTransaction *transaction)
{
	guint tries = 0;
	gint fd = -1;
	
	/* 
	 * In this function we don't actually put the object into a 'write' state,
	 * that's the callers job if necessary.
	 */ 

	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));

	g_return_val_if_fail (!gck_transaction_get_failed (transaction), -1);

	/* File lock retry loop */
	for (tries = 0; TRUE; ++tries) {
		if (tries > MAX_LOCK_TRIES) {
			g_message ("couldn't write to store file: %s: file is locked", self->filename);
			gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
			return -1;
		}

		fd = open (self->filename, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			g_message ("couldn't open store file: %s: %s", self->filename, g_strerror (errno));
			gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
			return -1;
		}
	
		if (flock (fd, LOCK_EX | LOCK_NB) < 0) {
			if (errno != EWOULDBLOCK) {
				g_message ("couldn't lock store file: %s: %s", self->filename, g_strerror (errno));
				close (fd);
				gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
				return -1;
			}
				
			close (fd);
			fd = -1;
			g_usleep (200000);
			continue;
		}

		/* Successfully opened file */;
		gck_transaction_add (transaction, self, complete_lock_file, GINT_TO_POINTER (fd));
		return fd;
	}

	g_assert_not_reached ();
}

static gboolean
complete_write_state (GckTransaction *transaction, GObject *object, gpointer unused)
{
	GckUserStorage *self = GCK_USER_STORAGE (object);
	gboolean ret = TRUE;
	struct stat sb;
	
	g_return_val_if_fail (GCK_IS_USER_STORAGE (object), FALSE);
	g_return_val_if_fail (GCK_IS_TRANSACTION (transaction), FALSE);
	g_return_val_if_fail (self->transaction == transaction, FALSE);
	
	/* Transaction succeeded, overwrite the old with the new */
	if (!gck_transaction_get_failed (transaction)) {

		if (g_rename (self->write_path, self->filename) == -1) {
			g_warning ("couldn't rename temporary store file: %s", self->write_path);
			ret = FALSE;
		} else {
			if (fstat (self->write_fd, &sb) >= 0)
				self->last_mtime = sb.st_mtime;
		}
	} 
	
	/* read_fd is closed by complete_lock_file */
	
	if (self->write_fd != -1)
		close (self->write_fd);
	self->write_fd = -1;
	
	g_free (self->write_path);
	self->write_path = NULL;

	g_object_unref (self->transaction);
	self->transaction = NULL;
	
	return ret;
}

static gboolean
begin_write_state (GckUserStorage *self, GckTransaction *transaction)
{
	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));

	g_return_val_if_fail (!gck_transaction_get_failed (transaction), FALSE);
	
	/* Already in write state for this transaction? */
	if (self->transaction != NULL) {
		g_return_val_if_fail (self->transaction == transaction, FALSE);
		return TRUE;
	}
	
	/* Lock file for the transaction */
	self->read_fd = begin_lock_file (self, transaction);
	if (self->read_fd == -1)
		return FALSE;

	gck_transaction_add (transaction, self, complete_write_state, NULL);
	self->transaction = g_object_ref (transaction);

	/* Open the new file */
	g_assert (self->write_fd == -1);
	self->write_path = g_strdup_printf ("%s.XXXXXX", self->filename);
	self->write_fd = g_mkstemp (self->write_path);
	if (self->write_fd == -1) {
		g_message ("couldn't open new temporary store file: %s: %s", self->write_path, g_strerror (errno));
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		return FALSE;
	}
	
	return TRUE;
}

static gboolean
complete_modification_state (GckTransaction *transaction, GObject *object, gpointer unused)
{
	GckUserStorage *self = GCK_USER_STORAGE (object);
	GckDataResult res;
	
	if (!gck_transaction_get_failed (transaction)) {
		res = gck_data_file_write_fd (self->file, self->write_fd, self->login);
		switch(res) {
		case GCK_DATA_FAILURE:
		case GCK_DATA_UNRECOGNIZED:
			g_warning ("couldn't write to temporary store file: %s", self->write_path);
			return FALSE;
		case GCK_DATA_LOCKED:
			g_warning ("couldn't encrypt temporary store file: %s", self->write_path);
			return FALSE;
		case GCK_DATA_SUCCESS:
			break;
		default:
			g_assert_not_reached ();
		}
	}
	
	return TRUE;
}

static gboolean
begin_modification_state (GckUserStorage *self, GckTransaction *transaction)
{
	GckDataResult res;
	struct stat sb;
	CK_RV rv;
	
	if (!begin_write_state (self, transaction))
		return FALSE;
	
	/* See if file needs updating */
	if (fstat (self->read_fd, &sb) >= 0 && sb.st_mtime != self->last_mtime) {
		
		res = gck_data_file_read_fd (self->file, self->read_fd, self->login);
		switch (res) {
		case GCK_DATA_FAILURE:
			g_message ("failure updating user store file: %s", self->filename);
			rv = CKR_FUNCTION_FAILED;
			break;
		case GCK_DATA_LOCKED:
			rv = CKR_USER_NOT_LOGGED_IN;
			break;
		case GCK_DATA_UNRECOGNIZED:
			g_message ("unrecognized or invalid user store file: %s", self->filename);
			rv = CKR_FUNCTION_FAILED;
			break;
		case GCK_DATA_SUCCESS:
			rv = CKR_OK;
			break;
		default:
			g_assert_not_reached ();
			break;
		}
		
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return FALSE;
		}
	}
	
	/* Write out the data once completed with modifications */
	gck_transaction_add (transaction, self, complete_modification_state, NULL);
	
	return TRUE;
}

static void
take_object_ownership (GckUserStorage *self, const gchar *identifier, GckObject *object)
{
	gchar *str;
	
	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (GCK_IS_OBJECT (object));
	
	g_assert (g_hash_table_lookup (self->identifier_to_object, identifier) == NULL);
	g_assert (g_hash_table_lookup (self->object_to_identifier, object) == NULL);
	
	str = g_strdup (identifier);
	object = g_object_ref (object);
	
	g_hash_table_replace (self->identifier_to_object, str, object);
	g_hash_table_replace (self->object_to_identifier, object, str);;
	
	g_object_set (object, "store", self, NULL);
	gck_manager_register_object (self->manager, object);
}

static gboolean
check_object_hash (GckUserStorage *self, const gchar *identifier, const guchar *data, gsize n_data)
{
	gconstpointer value;
	GckDataResult res;
	gboolean result;
	gsize n_value;
	gchar *digest;
	
	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (identifier);
	g_assert (data);
	
	digest = g_compute_checksum_for_data (G_CHECKSUM_SHA1, data, n_data);
	g_return_val_if_fail (digest, FALSE);
	
	res = gck_data_file_read_value (self->file, identifier, CKA_GNOME_INTERNAL_SHA1, &value, &n_value);
	g_return_val_if_fail (res == GCK_DATA_SUCCESS, FALSE);
	
	result = (strlen (digest) == n_value && memcmp (digest, value, n_value) == 0);
	g_free (digest);
	
	return result;
}

static void
store_object_hash (GckUserStorage *self, GckTransaction *transaction, const gchar *identifier, 
                   const guchar *data, gsize n_data)
{
	GckDataResult res;
	gchar *digest;
	
	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));
	g_assert (identifier);
	g_assert (data);
	
	digest = g_compute_checksum_for_data (G_CHECKSUM_SHA1, data, n_data);
	if (digest == NULL) {
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		g_return_if_reached ();
	}
	
	res = gck_data_file_write_value (self->file, identifier, CKA_GNOME_INTERNAL_SHA1, digest, strlen (digest));
	g_free (digest);
	
	if (res != GCK_DATA_SUCCESS)
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
}

static void 
data_file_entry_added (GckDataFile *store, const gchar *identifier, GckUserStorage *self)
{
	GError *error = NULL;
	GckObject *object;
	gboolean ret;
	guchar *data;
	gsize n_data;
	GType type;
	gchar *path;

	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (identifier);

	/* Already have this object? */
	object = g_hash_table_lookup (self->identifier_to_object, identifier);
	if (object != NULL)
		return;

	/* Figure out what type of object we're dealing with */
	type = type_from_identifier (identifier);
	if (type == 0) {
		g_warning ("don't know how to load file in user store: %s", identifier);
		return;
	}
	
	/* Read the file in */
	path = g_build_filename (self->directory, identifier, NULL);
	ret = g_file_get_contents (path, (gchar**)&data, &n_data, &error);
	g_free (path);
	
	if (ret == FALSE) {
		g_warning ("couldn't read file in user store: %s: %s", identifier, 
		           error && error->message ? error->message : "");
		g_clear_error (&error);
		return;
	}
	
	/* Make sure that the object wasn't tampered with */
	if (!check_object_hash (self, identifier, data, n_data)) {
		g_message ("file in user store doesn't match hash: %s", identifier);
		return;
	}
	
	/* Create a new object for this identifier */
	object = g_object_new (type, "unique", identifier, "module", self->module, NULL);
	g_return_if_fail (GCK_IS_SERIALIZABLE (object));
	g_return_if_fail (GCK_SERIALIZABLE_GET_INTERFACE (object)->extension);

	/* And load the data into it */
	if (gck_serializable_load (GCK_SERIALIZABLE (object), self->login, data, n_data)) 
		take_object_ownership (self, identifier, object);
	else 
		g_message ("failed to load file in user store: %s", identifier);
	
	g_free (data);
	g_object_unref (object);
}

static void 
data_file_entry_changed (GckDataFile *store, const gchar *identifier, CK_ATTRIBUTE_TYPE type, GckUserStorage *self)
{
	GckObject *object;
	
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (identifier);
	
	object = g_hash_table_lookup (self->identifier_to_object, identifier);
	if (object != NULL)
		gck_object_notify_attribute (object, type);
}

static void 
data_file_entry_removed (GckDataFile *store, const gchar *identifier, GckUserStorage *self)
{
	GckObject *object;
		
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (identifier);
	
	object = g_hash_table_lookup (self->identifier_to_object, identifier);
	if (object != NULL) {
		g_object_set (object, "store", NULL, NULL);

		/* Unrefs and also disposes the object, which unregisters from manager*/
		g_hash_table_remove (self->identifier_to_object, identifier);
		g_hash_table_remove (self->object_to_identifier, object);
	}
}

static void
relock_object (GckUserStorage *self, GckTransaction *transaction, const gchar *path, 
               const gchar *identifier, GckLogin *old_login, GckLogin *new_login)
{
	GError *error = NULL;
	GckObject *object;
	guchar *data;
	gsize n_data;
	GType type;
	
	g_assert (GCK_IS_USER_STORAGE (self));
	g_assert (GCK_IS_TRANSACTION (transaction));
	g_assert (identifier);
	g_assert (path);
	
	g_assert (!gck_transaction_get_failed (transaction));

	/* Figure out the type of object */
	type = type_from_identifier (identifier);
	if (type == 0) {
		g_warning ("don't know how to relock file in user store: %s", identifier);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		return;
	}
	
	/* Create a dummy object for this identifier */
	object = g_object_new (type, "unique", identifier, "module", self->module, NULL);
	if (!GCK_IS_SERIALIZABLE (object)) {
		g_warning ("cannot relock unserializable object for file in user store: %s", identifier);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		return;
	}
	
	/* Read in the data for the object */
	if (!g_file_get_contents (path, (gchar**)&data, &n_data, &error)) {
		g_message ("couldn't load file in user store in order to relock: %s: %s", identifier,
		           error && error->message ? error->message : "");
		g_clear_error (&error);
		g_object_unref (object);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		return;
	}
	
	/* Make sure the data matches the hash */
	if (!check_object_hash (self, identifier, data, n_data)) {
		g_message ("file in data store doesn't match hash: %s", identifier);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		return;
	}
	
	/* Load it into our temporary object */
	if (!gck_serializable_load (GCK_SERIALIZABLE (object), old_login, data, n_data)) {
		g_message ("unrecognized or invalid user store file: %s", identifier);
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		g_free (data);
		g_object_unref (object);
		return;
	} 
	
	g_free (data);
	data = NULL;
		
	/* Read it out of our temporary object */
	if (!gck_serializable_save (GCK_SERIALIZABLE (object), new_login, &data, &n_data)) {
		g_warning ("unable to serialize data with new login: %s", identifier);
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		g_object_unref (object);
		g_free (data);
		return;
	}
	
	g_object_unref (object);
	
	/* And write it back out to the file */
	gck_transaction_write_file (transaction, path, data, n_data);
	
	/* Create and save the hash here */
	if (!gck_transaction_get_failed (transaction))
		store_object_hash (self, transaction, identifier, data, n_data);
	
	g_free (data);

}

typedef struct _RelockArgs {
	GckUserStorage *self;
	GckTransaction *transaction;
	GckLogin *old_login;
	GckLogin *new_login;
} RelockArgs;

static void
relock_each_object (GckDataFile *file, const gchar *identifier, gpointer data)
{
	RelockArgs *args = data;
	gchar *path;
	guint section;
	
	g_assert (GCK_IS_USER_STORAGE (args->self));
	if (gck_transaction_get_failed (args->transaction))
		return;
	
	if (!gck_data_file_lookup_entry (file, identifier, &section))
		g_return_if_reached ();

	/* Only operate on private files */
	if (section != GCK_DATA_FILE_SECTION_PRIVATE)
		return;

	path = g_build_filename (args->self->directory, identifier, NULL);
	relock_object (args->self, args->transaction, path, identifier, args->old_login, args->new_login);
	g_free (path);
}

static CK_RV
refresh_with_login (GckUserStorage *self, GckLogin *login)
{
	GckDataResult res;
	struct stat sb;
	CK_RV rv;
	int fd;
	
	g_assert (GCK_USER_STORAGE (self));
	
	/* Open the file for reading */
	fd = open (self->filename, O_RDONLY, 0);
	if (fd == -1) {
		/* No file, no worries */
		if (errno == ENOENT)
			return login ? CKR_USER_PIN_NOT_INITIALIZED : CKR_OK;
		g_message ("couldn't open store file: %s: %s", self->filename, g_strerror (errno));
		return CKR_FUNCTION_FAILED;
	}

	/* Try and update the last read time */
	if (fstat (fd, &sb) >= 0) 
		self->last_mtime = sb.st_mtime;
	
	res = gck_data_file_read_fd (self->file, fd, login);
	switch (res) {
	case GCK_DATA_FAILURE:
		g_message ("failure reading from file: %s", self->filename);
		rv = CKR_FUNCTION_FAILED;
		break;
	case GCK_DATA_LOCKED:
		rv = CKR_USER_NOT_LOGGED_IN;
		break;
	case GCK_DATA_UNRECOGNIZED:
		g_message ("unrecognized or invalid user store file: %s", self->filename);
		rv = CKR_FUNCTION_FAILED;
		break;
	case GCK_DATA_SUCCESS:
		rv = CKR_OK;
		break;
	default:
		g_assert_not_reached ();
		break;
	}
	
	/* Force a reread on next write */
	if (rv == CKR_FUNCTION_FAILED)
		self->last_mtime = 0;
	
	close (fd);
	return rv;
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static CK_RV 
gck_user_storage_real_read_value (GckStore *base, GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckUserStorage *self = GCK_USER_STORAGE (base);
	const gchar *identifier;
	GckDataResult res;
	gconstpointer value;
	gsize n_value;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (GCK_IS_OBJECT (object), CKR_GENERAL_ERROR);
	g_return_val_if_fail (attr, CKR_GENERAL_ERROR);

	identifier = g_hash_table_lookup (self->object_to_identifier, object);
	if (!identifier)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	
	if (self->last_mtime == 0) {
		rv = gck_user_storage_refresh (self);
		if (rv != CKR_OK)
			return rv;
	}
	
	res = gck_data_file_read_value (self->file, identifier, attr->type, &value, &n_value);
	switch (res) {
	case GCK_DATA_FAILURE:
		g_return_val_if_reached (CKR_GENERAL_ERROR);
	case GCK_DATA_UNRECOGNIZED:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	case GCK_DATA_LOCKED:
		return CKR_USER_NOT_LOGGED_IN;
	case GCK_DATA_SUCCESS:
		/* Yes, we don't fill a buffer, just return pointer */
		attr->pValue = (CK_VOID_PTR)value;
		attr->ulValueLen = n_value;
		return CKR_OK;
	default:
		g_assert_not_reached ();
	}
}

static void 
gck_user_storage_real_write_value (GckStore *base, GckTransaction *transaction, GckObject *object, CK_ATTRIBUTE_PTR attr)
{
	GckUserStorage *self = GCK_USER_STORAGE (base);
	const gchar *identifier;
	GckDataResult res;
	CK_RV rv;
	
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (GCK_IS_OBJECT (object));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (attr);

	identifier = g_hash_table_lookup (self->object_to_identifier, object);
	if (!identifier) {
		gck_transaction_fail (transaction, CKR_ATTRIBUTE_READ_ONLY);
		return;
	}
	
	if (self->last_mtime == 0) {
		rv = gck_user_storage_refresh (self);
		if (rv != CKR_OK) {
			gck_transaction_fail (transaction, rv);
			return;
		}
	}

	res = gck_data_file_write_value (self->file, identifier, attr->type, attr->pValue, attr->ulValueLen);
	switch (res) {
	case GCK_DATA_FAILURE:
		rv = CKR_FUNCTION_FAILED;
		break;
	case GCK_DATA_UNRECOGNIZED:
		rv = CKR_ATTRIBUTE_READ_ONLY;
		break;
	case GCK_DATA_LOCKED:
		rv = CKR_USER_NOT_LOGGED_IN;
		break;
	case GCK_DATA_SUCCESS:
		rv = CKR_OK;
		break;
	default:
		g_assert_not_reached ();
	}	

	if (rv != CKR_OK)
		gck_transaction_fail (transaction, rv);
}

static GObject* 
gck_user_storage_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckUserStorage *self = GCK_USER_STORAGE (G_OBJECT_CLASS (gck_user_storage_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	

	g_return_val_if_fail (self->directory, NULL);
	self->filename = g_build_filename (self->directory, "user.keystore", NULL);
	
	g_return_val_if_fail (self->manager, NULL);
	g_return_val_if_fail (self->module, NULL);
	
	return G_OBJECT (self);
}

static void
gck_user_storage_init (GckUserStorage *self)
{
	self->file = gck_data_file_new ();
	g_signal_connect (self->file, "entry-added", G_CALLBACK (data_file_entry_added), self);
	g_signal_connect (self->file, "entry-changed", G_CALLBACK (data_file_entry_changed), self);
	g_signal_connect (self->file, "entry-removed", G_CALLBACK (data_file_entry_removed), self);
	
	/* Each one owns the key and contains weak ref to other's key as its value */
	self->object_to_identifier = g_hash_table_new_full (g_direct_hash, g_direct_equal, gck_util_dispose_unref, NULL);
	self->identifier_to_object = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	
	self->read_fd = -1;
	self->write_fd = -1;
}

static void
gck_user_storage_dispose (GObject *obj)
{
	GckUserStorage *self = GCK_USER_STORAGE (obj);
	
	if (self->manager)
		g_object_unref (self->manager);
	self->manager = NULL;
	
	g_signal_handlers_disconnect_by_func (self->file, data_file_entry_added, self);
	g_signal_handlers_disconnect_by_func (self->file, data_file_entry_changed, self);
	g_signal_handlers_disconnect_by_func (self->file, data_file_entry_removed, self);
	
	g_hash_table_remove_all (self->object_to_identifier);
	g_hash_table_remove_all (self->identifier_to_object);
	
	G_OBJECT_CLASS (gck_user_storage_parent_class)->dispose (obj);
}

static void
gck_user_storage_finalize (GObject *obj)
{
	GckUserStorage *self = GCK_USER_STORAGE (obj);
	
	g_assert (self->file);
	g_object_unref (self->file);
	self->file = NULL;
	
	g_free (self->filename);
	self->filename = NULL;
	
	g_assert (self->directory);
	g_free (self->directory);
	self->directory = NULL;
	
	g_assert (self->object_to_identifier);
	g_hash_table_destroy (self->object_to_identifier);
	g_hash_table_destroy (self->identifier_to_object);

	G_OBJECT_CLASS (gck_user_storage_parent_class)->finalize (obj);
}

static void
gck_user_storage_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GckUserStorage *self = GCK_USER_STORAGE (obj);
	
	switch (prop_id) {
	case PROP_DIRECTORY:
		g_return_if_fail (!self->directory);
		self->directory = g_value_dup_string (value);
		g_return_if_fail (self->directory);
		break;
	case PROP_MODULE:
		g_return_if_fail (!self->module);
		self->module = g_value_get_object (value);
		break;
	case PROP_MANAGER:
		g_return_if_fail (!self->manager);
		self->manager = g_value_dup_object (value);
		g_return_if_fail (self->manager);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_storage_get_property (GObject *obj, guint prop_id, GValue *value, 
                               GParamSpec *pspec)
{
	GckUserStorage *self = GCK_USER_STORAGE (obj);
	
	switch (prop_id) {
	case PROP_DIRECTORY:
		g_value_set_string (value, gck_user_storage_get_directory (self));
		break;
	case PROP_MODULE:
		g_value_set_object (value, self->module);
		break;
	case PROP_MANAGER:
		g_value_set_object (value, gck_user_storage_get_manager (self));
		break;
	case PROP_LOGIN:
		g_value_set_object (value, gck_user_storage_get_login (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_user_storage_class_init (GckUserStorageClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckStoreClass *store_class = GCK_STORE_CLASS (klass);
    
	gobject_class->constructor = gck_user_storage_constructor;
	gobject_class->dispose = gck_user_storage_dispose;
	gobject_class->finalize = gck_user_storage_finalize;
	gobject_class->set_property = gck_user_storage_set_property;
	gobject_class->get_property = gck_user_storage_get_property;
	
	store_class->read_value = gck_user_storage_real_read_value;
	store_class->write_value = gck_user_storage_real_write_value;
    
	g_object_class_install_property (gobject_class, PROP_DIRECTORY,
	           g_param_spec_string ("directory", "Storage Directory", "Directory for storage", 
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
    
	g_object_class_install_property (gobject_class, PROP_MODULE,
	           g_param_spec_object ("module", "Module", "Module for objects", 
	                                GCK_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_MANAGER,
	           g_param_spec_object ("manager", "Object Manager", "Object Manager", 
	                                GCK_TYPE_MANAGER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_LOGIN,
	           g_param_spec_object ("login", "Login", "Login used to unlock", 
	                                GCK_TYPE_LOGIN, G_PARAM_READABLE));
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckUserStorage*
gck_user_storage_new (GckModule *module, const gchar *directory)
{
	GckManager *manager;
	
	g_return_val_if_fail (GCK_IS_MODULE (module), NULL);
	g_return_val_if_fail (directory, NULL);

	manager = gck_module_get_manager (module);
	g_return_val_if_fail (GCK_IS_MANAGER (manager), NULL);

	return g_object_new (GCK_TYPE_USER_STORAGE,
	                     "module", module,
	                     "manager", manager, 
	                     "directory", directory, 
	                     NULL);
}

CK_RV
gck_user_storage_refresh (GckUserStorage *self)
{
	g_return_val_if_fail (GCK_USER_STORAGE (self), CKR_GENERAL_ERROR);
	return refresh_with_login (self, self->login);
}

void
gck_user_storage_create (GckUserStorage *self, GckTransaction *transaction, GckObject *object)
{
	gboolean is_private;
	GckDataResult res;
	gchar *identifier;
	guchar *data;
	gsize n_data;
	gchar *path;
	
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (GCK_IS_OBJECT (object));
	
	/* Make sure we haven't already stored it */
	identifier = g_hash_table_lookup (self->object_to_identifier, object);
	g_return_if_fail (identifier == NULL);
	
	/* Double check that the object is in fact serializable */
	if (!GCK_IS_SERIALIZABLE (object)) {
		g_warning ("can't store object of type '%s' on token", G_OBJECT_TYPE_NAME (object));
		gck_transaction_fail (transaction, CKR_GENERAL_ERROR);
		g_return_if_reached ();
	}
	
	/* Figure out whether this is a private object */ 
	if (!gck_object_get_attribute_boolean (object, NULL, CKA_PRIVATE, &is_private))
		is_private = FALSE;
	
	/* Can't serialize private if we're not unlocked */
	if (is_private && !self->login) {
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	}

	/* Hook ourselves into the transaction */
	if (!begin_modification_state (self, transaction))
		return;

	/* Create an identifier guaranteed unique by this transaction */
	identifier = identifier_for_object (object);
	if (gck_data_file_unique_entry (self->file, &identifier) != GCK_DATA_SUCCESS) {
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		g_return_if_reached ();
	}
	
	/* We don't want to get signals about this item being added */
	g_signal_handlers_block_by_func (self->file, data_file_entry_added, self);
	g_signal_handlers_block_by_func (self->file, data_file_entry_changed, self);
	
	res = gck_data_file_create_entry (self->file, identifier, 
	                                  is_private ? GCK_DATA_FILE_SECTION_PRIVATE : GCK_DATA_FILE_SECTION_PUBLIC);
	
	g_signal_handlers_unblock_by_func (self->file, data_file_entry_added, self);
	g_signal_handlers_unblock_by_func (self->file, data_file_entry_changed, self);

	switch(res) {
	case GCK_DATA_FAILURE:
	case GCK_DATA_UNRECOGNIZED:
		g_free (identifier);
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		return;
	case GCK_DATA_LOCKED:
		g_free (identifier);
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached ();
	}
	
	/* Serialize the object in question */
	if (!gck_serializable_save (GCK_SERIALIZABLE (object), is_private ? self->login : NULL, &data, &n_data)) {
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		g_return_if_reached ();
	}

	path = g_build_filename (self->directory, identifier, NULL);
	gck_transaction_write_file (transaction, path, data, n_data);
	
	/* Make sure we write in the object hash */
	if (!gck_transaction_get_failed (transaction))
		store_object_hash (self, transaction, identifier, data, n_data);

	/* Now we decide to own the object */
	if (!gck_transaction_get_failed (transaction))
		take_object_ownership (self, identifier, object);
	
	g_free (identifier);
	g_free (path);
	g_free (data);
}

void
gck_user_storage_destroy (GckUserStorage *self, GckTransaction *transaction, GckObject *object)
{
	GckDataResult res;
	gchar *identifier;
	gchar *path;
	
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	g_return_if_fail (!gck_transaction_get_failed (transaction));
	g_return_if_fail (object);
	
	/* Lookup the object identifier */
	identifier = g_hash_table_lookup (self->object_to_identifier, object);
	g_return_if_fail (identifier);
	
	if (!begin_modification_state (self, transaction))
		return;

	/* First actually delete the file */
	path = g_build_filename (self->directory, identifier, NULL);
	gck_transaction_remove_file (transaction, path);
	g_free (path);
	
	if (gck_transaction_get_failed (transaction))
		return;

	/* Now delete the entry from our store */
	res = gck_data_file_destroy_entry (self->file, identifier);
	switch(res) {
	case GCK_DATA_FAILURE:
	case GCK_DATA_UNRECOGNIZED:
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		return;
	case GCK_DATA_LOCKED:
		gck_transaction_fail (transaction, CKR_USER_NOT_LOGGED_IN);
		return;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached ();
	}
	
	/* Actual removal of object happened as a callback above */
	g_return_if_fail (g_hash_table_lookup (self->object_to_identifier, object) == NULL);
}

void
gck_user_storage_relock (GckUserStorage *self, GckTransaction *transaction, 
                         GckLogin *old_login, GckLogin *new_login)
{
	GckDataFile *file;
	GckDataResult res;
	RelockArgs args;
	
	g_return_if_fail (GCK_IS_USER_STORAGE (self));
	g_return_if_fail (GCK_IS_TRANSACTION (transaction));
	
	/* Reload the file with the old password and start transaction */
	if (!begin_write_state (self, transaction))
		return;
	
	file = gck_data_file_new ();
	
	/* Read in from the old file */
	res = gck_data_file_read_fd (file, self->read_fd, old_login);
	switch(res) {
	case GCK_DATA_FAILURE:
	case GCK_DATA_UNRECOGNIZED:
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		return;
	case GCK_DATA_LOCKED:
		gck_transaction_fail (transaction, CKR_PIN_INCORRECT);
		return;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached ();
	}
	
	/* Write out to new path as new file */
	res = gck_data_file_write_fd (file, self->write_fd, new_login);
	switch(res) {
	case GCK_DATA_FAILURE:
	case GCK_DATA_UNRECOGNIZED:
		gck_transaction_fail (transaction, CKR_FUNCTION_FAILED);
		return;
	case GCK_DATA_LOCKED:
		gck_transaction_fail (transaction, CKR_PIN_INVALID);
		return;
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached ();
	}
	
	/* Now go through all objects in the file, and load and reencode them */
	args.transaction = transaction;
	args.old_login = old_login;
	args.new_login = new_login;
	gck_data_file_foreach_entry (file, relock_each_object, &args);
	
	if (!gck_transaction_get_failed (transaction) && self->login) {
		if (new_login)
			g_object_ref (new_login);
		g_object_unref (self->login);
		self->login = new_login;
		g_object_notify (G_OBJECT (self), "login");
	}
	
	g_object_unref (file);
}

CK_RV
gck_user_storage_unlock (GckUserStorage *self, GckLogin *login)
{
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (!self->transaction, CKR_GENERAL_ERROR);
	
	if (self->login)
		return CKR_USER_ALREADY_LOGGED_IN;
	
	self->login = login;
	
	rv = refresh_with_login (self, login);
	if (rv == CKR_USER_NOT_LOGGED_IN)
		rv = CKR_PIN_INCORRECT;
	
	/* Take on new login for good */
	if (rv == CKR_OK) {
		g_assert (self->login == login);
		if (self->login)
			g_object_ref (self->login);
		g_object_notify (G_OBJECT (self), "login");
		
	/* Failed, so keep our previous NULL login */
	} else {
		self->login = NULL;
	}
	
	return rv;
}

CK_RV
gck_user_storage_lock (GckUserStorage *self)
{
	GckLogin *prev;
	CK_RV rv;
	
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), CKR_GENERAL_ERROR);
	g_return_val_if_fail (!self->transaction, CKR_GENERAL_ERROR);
	
	if (!self->login)
		return CKR_USER_NOT_LOGGED_IN;
	
	/* While loading set new NULL login */
	prev = self->login;
	self->login = NULL;
	
	rv = refresh_with_login (self, NULL);
	
	/* Take on new login for good */
	if (rv == CKR_OK) {
		g_object_unref (prev);
		g_assert (self->login == NULL);
		g_object_notify (G_OBJECT (self), "login");
		
	/* Failed so revert to previous login */
	} else {
		self->login = prev;
	}
	
	return rv;
}

GckManager*
gck_user_storage_get_manager (GckUserStorage *self)
{
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), NULL);
	return self->manager;
}

const gchar*
gck_user_storage_get_directory (GckUserStorage *self)
{
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), NULL);
	return self->directory;
}

GckLogin*
gck_user_storage_get_login (GckUserStorage *self)
{
	g_return_val_if_fail (GCK_IS_USER_STORAGE (self), NULL);
	return self->login;
}

gulong
gck_user_storage_token_flags (GckUserStorage *self)
{
	gulong flags = 0;
	CK_RV rv;
	
	/* We don't changing SO logins, so always initialized */
	flags |= CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED;
	
	/* No file has been loaded yet? */
	if (self->last_mtime == 0) {
		rv = gck_user_storage_refresh (self);
		if (rv == CKR_USER_PIN_NOT_INITIALIZED)
			flags |= CKF_USER_PIN_TO_BE_CHANGED;
		else if (rv != CKR_OK)
			g_return_val_if_reached (flags);
	}
	
	/* No private stuff in the file? */
	if (gck_data_file_have_section (self->file, GCK_DATA_FILE_SECTION_PRIVATE))
		flags |= CKF_USER_PIN_INITIALIZED;
	
	return flags;
}
