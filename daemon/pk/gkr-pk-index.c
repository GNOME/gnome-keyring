/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-index.c - indexes to store values related to pk objects

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gkr-pk-index.h"

#include "common/gkr-async.h"
#include "common/gkr-cleanup.h"
#include "common/gkr-crypto.h"
#include "common/gkr-location.h"
#include "common/gkr-secure-memory.h"

#include "keyrings/gkr-keyring-login.h"
#include "keyrings/gkr-keyrings.h"

#include "ui/gkr-ask-daemon.h"
#include "ui/gkr-ask-request.h"

#include <glib/gi18n.h>

enum {
	PROP_0,
	PROP_KEYRING,
	PROP_DEFAULTS
};

G_DEFINE_TYPE (GkrPkIndex, gkr_pk_index, G_TYPE_OBJECT);

static GkrPkIndex *index_default = NULL; 

/* -----------------------------------------------------------------------------
 * HELPERS
 */

static void 
cleanup_default_index (void *unused)
{
	g_assert (index_default);
	g_object_unref (index_default);
	index_default = NULL;
}

static gchar*
digest_to_group (gkrconstid digest)
{
	const guchar *digdata;
	gsize n_group, n_digdata;
	gchar *group;
	gboolean r;
	
	/* Encode the digest */		
	digdata = gkr_id_get_raw (digest, &n_digdata);
	g_assert (digdata);
	n_group = (n_digdata * 2) + 1;
	group = g_malloc0 (n_group);
	r = gkr_crypto_hex_encode (digdata, n_digdata, group, &n_group);
	g_assert (r == TRUE);

	return group;
}
 
static gboolean
request_keyring_new (GQuark location, gchar **password)
{
	GkrAskRequest* ask;
	gboolean ret;
	
	g_assert (password);
	g_assert (!*password);

	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Create Storage for Key Information"), 
	                           _("Choose password to protect storage"),
	 	                   GKR_ASK_REQUEST_NEW_PASSWORD);
	
	gkr_ask_request_set_secondary (ask, _("The system wants to store information about your keys and certificates. "
					      "In order to protect this information, choose a password with which it will be locked."));
	
	gkr_ask_request_set_location (ask, location);
	
	/* And do the prompt */
	gkr_ask_daemon_process (ask);
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	if (ret)
		*password = gkr_secure_strdup (ask->typed_password);
	g_object_unref (ask);
	return ret;
}

static gboolean
request_keyring_unlock (GkrPkIndex *index)
{
	GkrAskRequest* ask;
	gboolean ret;
	
	g_return_val_if_fail (index->keyring, FALSE);
	
	/* If the user denied access to this index, don't try again */
	if (index->denied)
		return FALSE;
	
	/* And put together the ask request */
	ask = gkr_ask_request_new (_("Unlock Storage for Key Information"), 
	                           _("Enter password to unlock storage"),
	                           GKR_ASK_REQUEST_PROMPT_PASSWORD);
	
	gkr_ask_request_set_secondary (ask, _("The system wants to access information about your keys and certificates, "
					      "but it is locked."));
	
	gkr_ask_request_set_location (ask, index->keyring->location);
	gkr_ask_request_set_object (ask, G_OBJECT (index->keyring));
	
	if (gkr_keyring_login_is_usable ())
		gkr_ask_request_set_check_option (ask, _("Automatically unlock this keyring when I log in."));

	/* Intercept item access requests to see if we still need to prompt */
	g_signal_connect (ask, "check-request", G_CALLBACK (gkr_keyring_ask_check_unlock), NULL);
	gkr_ask_daemon_process (ask);
	
	ret = ask->response >= GKR_ASK_RESPONSE_ALLOW;
	if (ask->response == GKR_ASK_RESPONSE_DENY) {
		g_message ("access to the pk index was denied");
		index->denied = TRUE;
	}
	
	g_object_unref (ask);
	return ret;
}

static GkrKeyringItem*
find_item_for_digest (GkrPkIndex *index, gkrconstid digest, gboolean create)
{
	GnomeKeyringAttributeList *attrs;
	GkrKeyringItem *item;
	gchar *group;
	guint type;
	
	g_return_val_if_fail (index && index->keyring, NULL);
	g_return_val_if_fail (digest, NULL);

	/* Unlock the keyring if necassary */
	if (index->keyring->locked) {
		if (!request_keyring_unlock (index))
			return NULL;
		g_return_val_if_fail (index->keyring->locked == FALSE, NULL);
	}
	
	group = digest_to_group (digest);
	
	attrs = gnome_keyring_attribute_list_new ();
	gnome_keyring_attribute_list_append_string (attrs, "object-digest", group);
	item = gkr_keyring_find_item (index->keyring, GNOME_KEYRING_ITEM_PK_STORAGE, attrs, FALSE);
	
	if (item || !create) {
		gnome_keyring_attribute_list_free (attrs);
		g_free (group);
		return item;  
	}

	type = GNOME_KEYRING_ITEM_PK_STORAGE | GNOME_KEYRING_ITEM_APPLICATION_SECRET;
	item = gkr_keyring_item_create (index->keyring, type);

	gkr_keyring_add_item (index->keyring, item);
	g_object_unref (item);
	
	gnome_keyring_attribute_list_free (item->attributes);
	item->attributes = attrs;
	g_free (group);
	
	return item;
}

static GnomeKeyringAttribute*
find_default_attribute (GkrPkIndex *index, const gchar *field)
{
	if (!index->defaults)
		return NULL;
	return gkr_attribute_list_find (index->defaults, field);
}

static gboolean
string_equal (const gchar *one, const gchar *two)
{
	if (!one && !two)
		return TRUE;
	if (!one || !two)
		return FALSE;
	return strcmp (one, two) == 0;
}

static gboolean 
write_string (GkrPkIndex *index, gkrconstid digest, const gchar *field, 
              const gchar *val)
{
	GnomeKeyringAttribute *prev;
	GnomeKeyringAttribute attr;
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	item = find_item_for_digest (index, digest, TRUE);
	if (!item)
		return FALSE;
	
	/* Skip this step if we already have this value */
	prev = gkr_attribute_list_find (item->attributes, field);
	if (prev) {
		if (prev->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING && 
		    string_equal (prev->value.string, val))
			return FALSE;
	}
		
	attr.name = (gchar*)field;
	attr.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attr.value.string = (gchar*)val;
	
	gkr_attribute_list_set (item->attributes, &attr);
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("writing field '%s': couldn't write index keyring to disk", field);
	return TRUE;
}

static gboolean 
write_uint (GkrPkIndex *index, gkrconstid digest, const gchar *field, guint val) 
{
	GnomeKeyringAttribute *prev;
	GnomeKeyringAttribute attr;
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	item = find_item_for_digest (index, digest, TRUE);
	if (!item)
		return FALSE;
	
	/* Skip this step if we already have this value */
	prev = gkr_attribute_list_find (item->attributes, field);
	if (prev) {
		if (prev->type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32 &&
		    prev->value.integer == val)
			return FALSE;
	}
		
	attr.name = (gchar*)field;
	attr.type = GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32;
	attr.value.integer = val;
	
	gkr_attribute_list_set (item->attributes, &attr);
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("writing field '%s': couldn't write index keyring to disk", field);
	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static void
gkr_pk_index_init (GkrPkIndex *index)
{

}

static void
gkr_pk_index_finalize (GObject *obj)
{
	GkrPkIndex *index = GKR_PK_INDEX (obj);
	
	g_object_unref (index->keyring);
	index->keyring = NULL;
	
	gnome_keyring_attribute_list_free (index->defaults);
	index->defaults = NULL;
	
	G_OBJECT_CLASS (gkr_pk_index_parent_class)->finalize (obj);
}

static void
gkr_pk_index_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GkrPkIndex *index = GKR_PK_INDEX (obj);

	switch (prop_id) {
	case PROP_KEYRING:
		g_value_set_object (value, index->keyring);
		break;
	case PROP_DEFAULTS:
		g_value_set_pointer (value, index->defaults); 
		break;
	}
}

static void
gkr_pk_index_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GkrPkIndex *index = GKR_PK_INDEX (obj);
	
	switch (prop_id) {
	case PROP_KEYRING:
		g_return_if_fail (GKR_IS_KEYRING (g_value_get_object (value)));
		g_return_if_fail (!index->keyring);
		index->keyring = GKR_KEYRING (g_value_get_object (value));
		g_object_ref (index->keyring);
		break;
	case PROP_DEFAULTS:
		g_return_if_fail (!index->defaults);
		index->defaults = gnome_keyring_attribute_list_copy (g_value_get_pointer (value));
		break;
	}
}

static void
gkr_pk_index_class_init (GkrPkIndexClass *klass)
{
	GObjectClass *gobject_class;

	gkr_pk_index_parent_class = g_type_class_peek_parent (klass);

	gobject_class = (GObjectClass*)klass;
	gobject_class->finalize = gkr_pk_index_finalize;
	gobject_class->get_property = gkr_pk_index_get_property;
	gobject_class->set_property = gkr_pk_index_set_property;
	
	g_object_class_install_property (gobject_class, PROP_KEYRING,
		g_param_spec_object ("keyring", "Keyring", "Keyring the index writes to",
		                     GKR_TYPE_KEYRING, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (gobject_class, PROP_DEFAULTS,
		g_param_spec_pointer ("defaults", "Defaults", "Default index attributes",
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrPkIndex*
gkr_pk_index_new (GkrKeyring *keyring, GnomeKeyringAttributeList *defaults)
{
	GkrPkIndex *index;
	gpointer unref = NULL;
	
	if (!keyring)
		unref = keyring = gkr_keyring_new ("in-memory", 0);
	g_return_val_if_fail (GKR_IS_KEYRING (keyring), NULL);
	
	index = g_object_new (GKR_TYPE_PK_INDEX, "keyring", keyring, 
	                      "defaults", defaults, NULL);
	
	if (unref)
		g_object_unref (unref);
	return index;
}


GkrPkIndex*
gkr_pk_index_open (GQuark index_location, const gchar *name, 
                   GnomeKeyringAttributeList *defaults)
{
	GkrKeyring *keyring, *login;
	gchar *password;
	
	keyring = gkr_keyrings_for_location (index_location);
	
	/* No keyring, try and create one */
	if (!keyring) {
		
		/* We need a password, see if we can use the login one */
		password = NULL;
		if (gkr_keyring_login_unlock (NULL)) {
			if (gkr_keyring_login_is_usable ()) {
				login = gkr_keyrings_get_login ();
				if (login)
					password = gkr_secure_strdup (login->password);
			}
		}
		
		/* We need to prompt for a password */
		if (!password) {
			if (!request_keyring_new (index_location, &password))
				return NULL;
		}
		
		g_return_val_if_fail (password, NULL);
		
		keyring = gkr_keyring_create (index_location, name, password);
		gkr_secure_strfree (password);

		/* Make it available */
		gkr_keyrings_add (keyring);
		g_object_unref (keyring);
	}
	
	return gkr_pk_index_new (keyring, defaults);
}

GkrPkIndex*
gkr_pk_index_default (void)
{
	if (!index_default) {
		index_default = gkr_pk_index_new (NULL, NULL);
		gkr_cleanup_register (cleanup_default_index, NULL);
	}
	
	return index_default;
}

gboolean
gkr_pk_index_get_boolean (GkrPkIndex *index, gkrconstid digest, 
                          const gchar *field, gboolean defvalue)
{
	return gkr_pk_index_get_uint (index, digest, field, defvalue ? 1 : 0) ? 
			TRUE : FALSE;
}

guint
gkr_pk_index_get_uint (GkrPkIndex *index, gkrconstid digest, 
                       const gchar *field, guint defvalue)
{
	GnomeKeyringAttribute *attr = NULL;
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();
	
	g_return_val_if_fail (GKR_IS_PK_INDEX (index), defvalue);

	item = find_item_for_digest (index, digest, FALSE);
	if (item != NULL)
		attr = gkr_attribute_list_find (item->attributes, field);
		
	attr = gkr_attribute_list_find (item->attributes, field);
	if (!attr) {
		attr = find_default_attribute (index, field);
		if (!attr)
			return defvalue;
	}
		
	g_return_val_if_fail (attr->type == GNOME_KEYRING_ATTRIBUTE_TYPE_UINT32, defvalue);
	return attr->value.integer;
}                                                                 

gchar*
gkr_pk_index_get_string (GkrPkIndex *index, gkrconstid digest, const gchar *field)
{
	GnomeKeyringAttribute *attr = NULL;
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();
	
	g_return_val_if_fail (GKR_IS_PK_INDEX (index), NULL);

	item = find_item_for_digest (index, digest, FALSE);
	if (item != NULL)
		attr = gkr_attribute_list_find (item->attributes, field);
		
	if (!attr) {
		attr = find_default_attribute (index, field);
		if (!attr)
			return NULL;
	}
		
	g_return_val_if_fail (attr->type == GNOME_KEYRING_ATTRIBUTE_TYPE_STRING, NULL);
	return g_strdup (attr->value.string);
}

gchar*
gkr_pk_index_get_secret (GkrPkIndex *index, gkrconstid digest)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), NULL);

	item = find_item_for_digest (index, digest, FALSE);
	if (item == NULL)
		return NULL;
		
	return gkr_secure_strdup (item->secret);	
}

guchar*
gkr_pk_index_get_binary (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *field, gsize *n_data)
{
	guchar *data;
	gchar *string;
	gsize n_string;

	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (n_data != NULL, NULL);	

	string = gkr_pk_index_get_string (index, digest, field);
	if (!string)
		return NULL;
		
	n_string = strlen (string);
	*n_data = (n_string / 2) + 1;
	data = g_malloc0 (*n_data);
	if (!gkr_crypto_hex_decode (string, n_string, data, n_data)) {
		g_message ("invalid binary data in index under field '%s'", field);
		g_free (data);
		data = NULL;
	}

	g_free (string);
	return data;
}

GQuark* 
gkr_pk_index_get_quarks (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *field)
{
	GArray *quarks;
	GQuark quark;
	gchar *string; 
	gchar *at, *next;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	
	string = gkr_pk_index_get_string (index, digest, field);
	if (!string)
		return NULL;
	
	quarks = g_array_new (TRUE, TRUE, sizeof (GQuark));
		
	/* Parse all the quarks */
	at = string;
	while (at != NULL) {
		next = strchr (at, '\n');
		if (next) {
			*next = 0;
			++next;
		}
		
		quark = g_quark_from_string (at);
		g_array_append_val (quarks, quark);
		at = next;
	}
	
	g_free (string);
	return (GQuark*)g_array_free (quarks, FALSE);
}

gboolean
gkr_pk_index_has_value (GkrPkIndex *index, gkrconstid digest, 
                        const gchar *field)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	item = find_item_for_digest (index, digest, FALSE);
	if (!item)
		return index->defaults && gkr_attribute_list_find (index->defaults, field);
		
	return gkr_attribute_list_find (item->attributes, field) ? TRUE : FALSE;
}

gboolean
gkr_pk_index_have (GkrPkIndex *index, gkrconstid digest)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);

	item = find_item_for_digest (index, digest, FALSE);
	return item == NULL ? FALSE : TRUE;
}

gboolean
gkr_pk_index_set_boolean (GkrPkIndex *index, gkrconstid digest, 
                          const gchar *field, gboolean val)
{
	if (!index)
		index = gkr_pk_index_default ();

	return write_uint (index, digest, field, val ? 1 : 0);
}

gboolean
gkr_pk_index_set_uint (GkrPkIndex *index, gkrconstid digest, 
                       const gchar *field, guint val)
{
	return write_uint (index, digest, field, val);
}                              
                                                        
gboolean 
gkr_pk_index_set_string (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *field, const gchar *val)
{
	return write_string (index, digest, field, val);
}

gboolean 
gkr_pk_index_set_secret (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *val)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);

	item = find_item_for_digest (index, digest, TRUE);
	if (!item)
		return FALSE;

	/* Make sure it's actually changed */
	if (string_equal (item->secret, val))
		return FALSE;
	
	gkr_secure_strfree (item->secret);
	item->secret = gkr_secure_strdup (val);
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("writing secret: couldn't write index keyring to disk");
	return TRUE;
}

gboolean
gkr_pk_index_set_binary (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *field, const guchar *data, 
                         gsize n_data)
{
	gboolean ret, r;
	gchar *str;
	gsize n_str;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	
	n_str = (n_data * 2) + 1;
	str = g_malloc0 (n_str);
	
	r = gkr_crypto_hex_encode (data, n_data, str, &n_str);
	g_assert (r == TRUE);
	
	ret = write_string (index, digest, field, str);
	g_free (str);

	return ret;
}

gboolean
gkr_pk_index_set_quarks (GkrPkIndex *index, gkrconstid digest, 
                         const gchar *field, GQuark *quarks)
{
	GString *string;
	gboolean ret;
	gchar *value;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	/* Build up a string with all of this */
	string = g_string_new (NULL);
	while (*quarks) {
		value = g_strescape (g_quark_to_string (*quarks), "");
		if (string->len > 0)
			g_string_append_c (string, '\n');
		g_string_append (string, value);
		g_free (value);
		++quarks;
	}

	/* Store it as a string */
	ret = write_string (index, digest, field, string->str);
	g_string_free (string, TRUE);
	return ret;
}

gboolean
gkr_pk_index_clear (GkrPkIndex *index, gkrconstid digest, 
                     const gchar *field)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);

	item = find_item_for_digest (index, digest, FALSE);
	if (!item)
		return FALSE;
	
	if (!gkr_attribute_list_find (item->attributes, field))
		return FALSE;

	gkr_attribute_list_delete (item->attributes, field);
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("clearing field '%s': couldn't write index keyring to disk", field);
	return TRUE;
}

gboolean
gkr_pk_index_rename (GkrPkIndex *index, gkrconstid old_digest, gkrconstid new_digest)
{
	GnomeKeyringAttribute attr;
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	g_return_val_if_fail (old_digest != NULL, FALSE);
	g_return_val_if_fail (new_digest != NULL, FALSE);
	
	item = find_item_for_digest (index, old_digest, FALSE);
	if (!item)
		return FALSE;

	if (gkr_id_equals (old_digest, new_digest))
		return FALSE;
	
	attr.name = "object-digest";
	attr.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attr.value.string = digest_to_group (new_digest);

	gkr_attribute_list_set (item->attributes, &attr);
	g_free (attr.value.string);
	
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("renaming item: couldn't write index keyring to disk");
	return TRUE;
}

gboolean
gkr_pk_index_copy (GkrPkIndex *old_index, GkrPkIndex *new_index, gkrconstid digest)
{
	GkrKeyringItem *item;
	
	if (!old_index)
		old_index = gkr_pk_index_default ();
	if (!new_index)
		new_index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (old_index), FALSE);
	g_return_val_if_fail (GKR_IS_PK_INDEX (new_index), FALSE);
	g_return_val_if_fail (digest != NULL, FALSE);

	if (old_index == new_index)
		return FALSE;
	
	item = find_item_for_digest (old_index, digest, FALSE);
	if (!item)
		return FALSE;
	
	item = gkr_keyring_item_clone (new_index->keyring, item);
	gkr_keyring_add_item (new_index->keyring, item);
	
	if (!gkr_keyring_save_to_disk (new_index->keyring))
		g_warning ("copying item: couldn't write index keyring to disk");

	return TRUE;
}

gboolean
gkr_pk_index_delete (GkrPkIndex *index, gkrconstid digest)
{
	GkrKeyringItem *item;
	
	if (!index)
		index = gkr_pk_index_default ();

	g_return_val_if_fail (GKR_IS_PK_INDEX (index), FALSE);
	
	item = find_item_for_digest (index, digest, FALSE);
	if (!item)
		return FALSE;
	
	gkr_keyring_remove_item (index->keyring, item);
	
	if (!gkr_keyring_save_to_disk (index->keyring))
		g_warning ("deleting item: couldn't write index keyring to disk");
	
	return TRUE;
}

/* ------------------------------------------------------------------------
 * QUARK LISTS
 */

gboolean
gkr_pk_index_quarks_has (GQuark *quarks, GQuark check)
{
	while (*quarks) {
		if (*quarks == check)
			return TRUE;
		++quarks;
	}
	
	return FALSE;
}

GQuark*
gkr_pk_index_quarks_dup (GQuark *quarks)
{
	GQuark *last = quarks;
	
	/* Figure out how many there are */	
	while (*last)
		++last;
		
	/* Include the null termination */
	++last;
	return g_memdup (quarks, (last - quarks) * sizeof (GQuark));
}

void
gkr_pk_index_quarks_free (GQuark *quarks)
{
	g_free (quarks);
}
