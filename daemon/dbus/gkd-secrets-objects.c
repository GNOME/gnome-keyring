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

#include "gkd-dbus-util.h"

#include "gkd-secrets-service.h"
#include "gkd-secrets-objects.h"
#include "gkd-secrets-types.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_PKCS11_SLOT,
	PROP_SERVICE
};

struct _GkdSecretsObjects {
	GObject parent;
	GkdSecretsService *service;
	GP11Slot *pkcs11_slot;
};

G_DEFINE_TYPE (GkdSecretsObjects, gkd_secrets_objects, G_TYPE_OBJECT);

typedef enum _DataType {
	DATA_TYPE_INVALID = 0,

	/*
	 * The attribute is a CK_BBOOL.
	 * Property is DBUS_TYPE_BOOLEAN
	 */
	DATA_TYPE_BOOL,

	/*
	 * The attribute is in the format: "%Y%m%d%H%M%S00"
	 * Property is DBUS_TYPE_INT64 since 1970 epoch.
	 */
	DATA_TYPE_TIME,

	/*
	 * The attribute is a CK_UTF8_CHAR string, not null-terminated
	 * Property is a DBUS_TYPE_STRING
	 */
	DATA_TYPE_STRING,

	/*
	 * The attribute is in the format: name\0value\0name2\0value2
	 * Property is dbus dictionary of strings: a{ss}
	 */
	DATA_TYPE_FIELDS
} DataType;

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static gchar*
encode_object_identifier (const gchar* name, gssize length)
{
	GString *result;

	g_assert (name);

	if (length < 0)
		length = strlen (name);

	result = g_string_sized_new (length + 2);
	while (length > 0) {
		char ch = *(name++);
		--length;

		/* Normal characters can go right through */
		if (G_LIKELY ((ch >= 'A' && ch <= 'Z') ||
		              (ch >= 'a' && ch <= 'z') ||
		              (ch >= '0' && ch <= '9'))) {
			g_string_append_c_inline (result, ch);

		/* Special characters are encoded with a _ */
		} else {
			g_string_append_printf (result, "_%02x", (unsigned int)ch);
		}
	}

	return g_string_free (result, FALSE);
}

static gchar*
decode_object_identifier (const gchar* enc, gssize length)
{
	GString *result;

	g_assert (enc);

	if (length < 0)
		length = strlen (enc);

	result = g_string_sized_new (length);
	while (length > 0) {
		char ch = *(enc++);
		--length;

		/* Underscores get special handling */
		if (G_UNLIKELY (ch == '_' &&
		                g_ascii_isxdigit(enc[0]) &&
		                g_ascii_isxdigit (enc[1]))) {
			ch = (g_ascii_xdigit_value (enc[0]) * 16) +
			     (g_ascii_xdigit_value (enc[1]));
			enc += 2;
			length -= 2;
		}

		g_string_append_c_inline (result, ch);
	}

	return g_string_free (result, FALSE);
}

static gboolean
parse_collection_and_item_from_path (const gchar *path, gchar **collection, gchar **item)
{
	const gchar *pos;

	g_return_val_if_fail (path, FALSE);
	g_assert (collection);
	g_assert (item);

	/* Make sure it starts with our prefix */
	if (!g_str_has_prefix (path, SECRETS_COLLECTION_PREFIX))
		return FALSE;
	path += strlen (SECRETS_COLLECTION_PREFIX);

	/* Skip the path separator */
	if (path[0] != '/')
		return FALSE;
	++path;

	/* Make sure we have something */
	if (path[0] == '\0')
		return FALSE;

	pos = strchr (path, '/');

	/* No item, just a collection */
	if (pos == NULL) {
		*collection = decode_object_identifier (path, -1);
		*item = NULL;
		return TRUE;
	}

	/* Make sure we have an item, and no further path bits */
	if (pos[1] == '\0' || strchr (pos + 1, '/'))
		return FALSE;

	*collection = decode_object_identifier (path, pos - path);
	*item = decode_object_identifier (pos + 1, -1);
	return TRUE;
}

static gboolean
property_to_attribute (const gchar *prop_name, CK_ATTRIBUTE_TYPE *attr_type, DataType *data_type)
{
	g_return_val_if_fail (prop_name, FALSE);
	g_assert (attr_type);
	g_assert (data_type);

	if (g_str_equal (prop_name, "Label")) {
		*attr_type = CKA_LABEL;
		*data_type = DATA_TYPE_STRING;

	} else if (g_str_equal (prop_name, "Locked")) {
		*attr_type = CKA_G_LOCKED;
		*data_type = DATA_TYPE_BOOL;

	} else if (g_str_equal (prop_name, "Created")) {
		*attr_type = CKA_G_CREATED;
		*data_type = DATA_TYPE_TIME;

	} else if (g_str_equal (prop_name, "Modified")) {
		*attr_type = CKA_G_MODIFIED;
		*data_type = DATA_TYPE_TIME;

	} else if (g_str_equal (prop_name, "Attributes")) {
		*attr_type = CKA_G_FIELDS;
		*data_type = DATA_TYPE_FIELDS;

	} else {
		return FALSE;
	}

	return TRUE;
}

static gboolean
attribute_to_property (CK_ATTRIBUTE_TYPE attr_type, const gchar **prop_name, DataType *data_type)
{
	g_assert (prop_name);
	g_assert (data_type);

	switch (attr_type) {
	case CKA_LABEL:
		*prop_name = "Label";
		*data_type = DATA_TYPE_STRING;
		break;
	case CKA_G_LOCKED:
		*prop_name = "Locked";
		*data_type = DATA_TYPE_BOOL;
		break;
	case CKA_G_CREATED:
		*prop_name = "Created";
		*data_type = DATA_TYPE_TIME;
		break;
	case CKA_G_MODIFIED:
		*prop_name = "Modified";
		*data_type = DATA_TYPE_TIME;
		break;
	case CKA_G_FIELDS:
		*prop_name = "Attributes";
		*data_type = DATA_TYPE_FIELDS;
		break;
	default:
		return FALSE;
	};

	return TRUE;
}

typedef void (*IterAppendFunc) (DBusMessageIter*, GP11Attribute*);

static void
iter_append_string (DBusMessageIter *iter, GP11Attribute *attr)
{
	gchar *value;

	g_assert (iter);
	g_assert (attr);

	if (attr->length == 0) {
		value = "";
		dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &value);
	} else {
		value = g_strndup ((const gchar*)attr->value, attr->length);
		dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &value);
		g_free (value);
	}
}

static void
iter_append_bool (DBusMessageIter *iter, GP11Attribute *attr)
{
	dbus_bool_t value;

	g_assert (iter);
	g_assert (attr);

	value = gp11_attribute_get_boolean (attr) ? TRUE : FALSE;
	dbus_message_iter_append_basic (iter, DBUS_TYPE_BOOLEAN, &value);
}

static void
iter_append_time (DBusMessageIter *iter, GP11Attribute *attr)
{
	gint64 value;
	struct tm tm;
	gchar buf[15];

	g_assert (iter);
	g_assert (attr);

	if (attr->length == 0) {
		value = -1;

	} else if (!attr->value || attr->length != 16) {
		g_warning ("invalid length of time attribute");
		value = -1;

	} else {
		memset (&tm, 0, sizeof (tm));
		memcpy (buf, attr->value, 14);
		buf[14] = 0;

		if (!strptime(buf, "%Y%m%d%H%M%S", &tm)) {
			g_warning ("invalid format of time attribute");
			value = -1;
		}

		/* Convert to seconds since epoch */
		value = timegm (&tm);
		if (value < 0) {
			g_warning ("invalid time attribute");
			value = -1;
		}
	}

	dbus_message_iter_append_basic (iter, DBUS_TYPE_INT64, &value);
}

static void
iter_append_fields (DBusMessageIter *iter, GP11Attribute *attr)
{
	DBusMessageIter array;
	DBusMessageIter dict;
	const gchar *ptr;
	const gchar *last;
	const gchar *name;
	gsize n_name;
	const gchar *value;
	gsize n_value;
	gchar *string;

	g_assert (iter);
	g_assert (attr);

	ptr = (gchar*)attr->value;
	last = ptr + attr->length;
	g_return_if_fail (ptr || last == ptr);

	dbus_message_iter_open_container (iter, DBUS_TYPE_ARRAY, "{ss}", &array);

	while (ptr && ptr != last) {
		g_assert (ptr < last);

		name = ptr;
		ptr = memchr (ptr, 0, last - ptr);
		if (ptr == NULL) /* invalid */
			break;

		n_name = ptr - name;
		value = ++ptr;
		ptr = memchr (ptr, 0, last - ptr);
		if (ptr == NULL) /* invalid */
			break;

		n_value = ptr - value;
		++ptr;

		dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);

		string = g_strndup (name, n_name);
		dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &string);
		g_free (string);

		string = g_strndup (value, n_value);
		dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &string);
		g_free (string);

		dbus_message_iter_close_container (&array, &dict);
	}

	dbus_message_iter_close_container (iter, &array);
}

static void
iter_append_variant (DBusMessageIter *iter, DataType data_type, GP11Attribute *attr)
{
	DBusMessageIter sub;
	IterAppendFunc func;
	const gchar *sig;

	g_assert (iter);
	g_assert (attr);

	switch (data_type) {
	case DATA_TYPE_STRING:
		func = iter_append_string;
		sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DATA_TYPE_BOOL:
		func = iter_append_bool;
		sig = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DATA_TYPE_TIME:
		func = iter_append_time;
		sig = DBUS_TYPE_INT64_AS_STRING;
		break;
	case DATA_TYPE_FIELDS:
		func = iter_append_fields;
		sig = "a{ss}";
		break;
	default:
		g_assert (FALSE);
		break;
	}

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, sig, &sub);
	(func) (&sub, attr);
	dbus_message_iter_close_container (iter, &sub);
}

static void
iter_append_property_dict (DBusMessageIter *iter, GP11Attributes *attrs)
{
	DBusMessageIter dict;
	GP11Attribute *attr;
	DataType data_type;
	const gchar *name;
	gulong num, i;

	num = gp11_attributes_count (attrs);
	for (i = 0; i < num; ++i) {
		attr = gp11_attributes_at (attrs, i);
		if (!attribute_to_property (attr->type, &name, &data_type))
			g_return_if_reached ();

		dbus_message_iter_open_container (iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
		dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &name);
		iter_append_variant (&dict, data_type, attr);
		dbus_message_iter_close_container (iter, &dict);
	}
}

static DBusMessage*
object_property_get (GP11Object *object, DBusMessage *message,
                     const gchar *prop_name)
{
	DBusMessageIter iter;
	GError *error = NULL;
	DBusMessage *reply;
	GP11Attribute attr;
	DataType data_type;

	/* What type of property is it? */
	if (!property_to_attribute (prop_name, &attr.type, &data_type)) {
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have the '%s' property", prop_name);
	}

	/* Retrieve the actual attribute */
	attr.value = gp11_object_get_data (object, attr.type, &attr.length, &error);
	if (error != NULL) {
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Couldn't retrieve '%s' property: %s",
		                                      prop_name, error->message);
	}

	/* Marshall the data back out */
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	iter_append_variant (&iter, data_type, &attr);
	g_free (attr.value);
	return reply;
}

static GP11Object*
item_for_identifier (GP11Session *session, const gchar *coll_id, const gchar *item_id)
{
	GP11Object *object = NULL;
	GError *error = NULL;
	GList *objects;

	g_assert (coll_id);
	g_assert (item_id);

	/*
	 * TODO: I think this could benefit from some sort of
	 * caching?
	 */

	objects = gp11_session_find_objects (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                                     CKA_G_COLLECTION, strlen (coll_id), coll_id,
	                                     CKA_ID, strlen (item_id), item_id,
	                                     GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup '%s/%s' item: %s", coll_id, item_id, error->message);
		g_clear_error (&error);
		return NULL;
	}

	if (objects) {
		object = g_object_ref (objects->data);
		gp11_object_set_session (object, session);
	}

	gp11_list_unref_free (objects);
	return object;
}

static DBusMessage*
item_property_get (GP11Object *object, DBusMessage *message)
{
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, 
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	return object_property_get (object, message, name);
}

static DBusMessage*
item_property_set (GP11Object *object, DBusMessage *message)
{
	g_return_val_if_reached (NULL); /* TODO: Need to implement */
}

static DBusMessage*
item_property_getall (GP11Object *object, DBusMessage *message)
{
	GP11Attributes *attrs;
	DBusMessageIter iter;
	DBusMessageIter array;
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *interface;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	attrs = gp11_object_get (object, &error,
	                         CKA_LABEL,
	                         CKA_G_LOCKED,
	                         CKA_G_CREATED,
	                         CKA_G_MODIFIED,
	                         CKA_G_FIELDS,
	                         GP11_INVALID);

	if (error != NULL)
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Couldn't retrieve properties: %s", 
		                                      error->message);

	reply = dbus_message_new_method_return (message);

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);
	iter_append_property_dict (&array, attrs);
	dbus_message_iter_close_container (&iter, &array);
	return reply;
}

static DBusMessage*
item_message_handler (GkdSecretsObjects *self, GP11Object *object, DBusMessage *message)
{
	/* org.freedesktop.Secrets.Item.Delete() */
	if (dbus_message_is_method_call (message, SECRETS_ITEM_INTERFACE, "Delete"))
		g_return_val_if_reached (NULL);

	/* org.freedesktop.DBus.Properties.Get */
	if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Get"))
		return item_property_get (object, message);

	/* org.freedesktop.DBus.Properties.Set */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Set"))
		return item_property_set (object, message);

	/* org.freedesktop.DBus.Properties.GetAll */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "GetAll"))
		return item_property_getall (object, message);

	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return gkd_dbus_introspect_handle (message, "item");

	return NULL;
}

static const gchar*
collection_get_identifier (GP11Object *coll)
{
	return g_object_get_data (G_OBJECT (coll), "coll-identifier");
}

static GP11Object*
collection_for_identifier (GP11Session *session, const gchar *coll_id)
{
	GP11Object *object = NULL;
	GError *error = NULL;
	GList *objects;

	g_assert (coll_id);

	/*
	 * TODO: I think this could benefit from some sort of
	 * caching?
	 */

	objects = gp11_session_find_objects (session, &error,
	                                     CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                                     CKA_ID, strlen (coll_id), coll_id,
	                                     GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup '%s' collection: %s", coll_id, error->message);
		g_clear_error (&error);
		return NULL;
	}

	if (objects) {
		object = objects->data;
		gp11_object_set_session (object, session);
		g_object_set_data_full (G_OBJECT (object), "coll-identifier", g_strdup (coll_id), g_free);
		g_object_ref (object);
	}

	gp11_list_unref_free (objects);
	return object;
}

static DBusMessage*
collection_property_get (GkdSecretsObjects *self, GP11Object *object, DBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, 
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	/* Special case, the Items property */
	if (g_str_equal (name, "Items")) {
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		gkd_secrets_objects_append_item_paths (self, &iter, message,
		                                       collection_get_identifier (object));
		return reply;
	}

	return object_property_get (object, message, name);
}

static DBusMessage*
collection_property_set (GkdSecretsObjects *self, GP11Object *object, DBusMessage *message)
{
	g_return_val_if_reached (NULL); /* TODO: Need to implement */
}

static DBusMessage*
collection_property_getall (GkdSecretsObjects *self, GP11Object *object, DBusMessage *message)
{
	GP11Attributes *attrs;
	DBusMessageIter iter;
	DBusMessageIter array;
	DBusMessageIter dict;
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *name;
	const gchar *interface;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRETS_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED, 
		                                      "Object does not have properties on interface '%s'", 
		                                      interface);

	attrs = gp11_object_get (object, &error,
	                         CKA_LABEL,
	                         CKA_G_LOCKED,
	                         CKA_G_CREATED,
	                         CKA_G_MODIFIED,
	                         GP11_INVALID);

	if (error != NULL)
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Couldn't retrieve properties: %s", 
		                                      error->message);

	reply = dbus_message_new_method_return (message);

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, "{sv}", &array);

	/* Append all the usual properties */
	iter_append_property_dict (&array, attrs);

	/* Append the Items property */
	dbus_message_iter_open_container (&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	name = "Items";
	dbus_message_iter_append_basic (&dict, DBUS_TYPE_STRING, &name);
	gkd_secrets_objects_append_item_paths (self, &dict, message,
	                                       collection_get_identifier (object));
	dbus_message_iter_close_container (&array, &dict);

	dbus_message_iter_close_container (&iter, &array);
	return reply;
}

static DBusMessage*
collection_message_handler (GkdSecretsObjects *self, GP11Object *object, DBusMessage *message)
{
	/* org.freedesktop.Secrets.Collection.Delete() */
	if (dbus_message_is_method_call (message, SECRETS_COLLECTION_INTERFACE, "Delete"))
		g_return_val_if_reached (NULL);

	/* org.freedesktop.Secrets.Collection.SearchItems() */
	if (dbus_message_is_method_call (message, SECRETS_COLLECTION_INTERFACE, "SearchItems"))
		g_return_val_if_reached (NULL);

	/* org.freedesktop.Secrets.Collection.CreateItem() */
	if (dbus_message_is_method_call (message, SECRETS_COLLECTION_INTERFACE, "CreateItem"))
		g_return_val_if_reached (NULL);

	/* org.freedesktop.DBus.Properties.Get() */
	if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Get"))
		return collection_property_get (self, object, message);

	/* org.freedesktop.DBus.Properties.Set() */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "Set"))
		return collection_property_set (self, object, message);

	/* org.freedesktop.DBus.Properties.GetAll() */
	else if (dbus_message_is_method_call (message, PROPERTIES_INTERFACE, "GetAll"))
		return collection_property_getall (self, object, message);

	else if (dbus_message_has_interface (message, DBUS_INTERFACE_INTROSPECTABLE))
		return gkd_dbus_introspect_handle (message, "collection");

	return NULL;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
gkd_secrets_objects_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->pkcs11_slot, NULL);
	g_return_val_if_fail (self->service, NULL);

	return G_OBJECT (self);
}

static void
gkd_secrets_objects_init (GkdSecretsObjects *self)
{

}

static void
gkd_secrets_objects_dispose (GObject *obj)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	if (self->pkcs11_slot) {
		g_object_unref (self->pkcs11_slot);
		self->pkcs11_slot = NULL;
	}

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->dispose (obj);
}

static void
gkd_secrets_objects_finalize (GObject *obj)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	g_assert (!self->pkcs11_slot);
	g_assert (!self->service);

	G_OBJECT_CLASS (gkd_secrets_objects_parent_class)->finalize (obj);
}

static void
gkd_secrets_objects_set_property (GObject *obj, guint prop_id, const GValue *value, 
                                  GParamSpec *pspec)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_return_if_fail (!self->pkcs11_slot);
		self->pkcs11_slot = g_value_dup_object (value);
		g_return_if_fail (self->pkcs11_slot);
		break;
	case PROP_SERVICE:
		g_return_if_fail (!self->service);
		self->service = g_value_get_object (value);
		g_return_if_fail (self->service);
		g_object_add_weak_pointer (G_OBJECT (self->service),
		                           (gpointer*)&(self->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_objects_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GkdSecretsObjects *self = GKD_SECRETS_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secrets_objects_get_pkcs11_slot (self));
		break;
	case PROP_SERVICE:
		g_value_set_object (value, self->service);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secrets_objects_class_init (GkdSecretsObjectsClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secrets_objects_constructor;
	gobject_class->dispose = gkd_secrets_objects_dispose;
	gobject_class->finalize = gkd_secrets_objects_finalize;
	gobject_class->set_property = gkd_secrets_objects_set_property;
	gobject_class->get_property = gkd_secrets_objects_get_property;

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this objects",
		                     GKD_SECRETS_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GP11Slot*
gkd_secrets_objects_get_pkcs11_slot (GkdSecretsObjects *self)
{
	g_return_val_if_fail (GKD_SECRETS_IS_OBJECTS (self), NULL);
	return self->pkcs11_slot;
}

DBusMessage*
gkd_secrets_objects_dispatch (GkdSecretsObjects *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	GP11Object *object;
	GP11Session *session;
	gchar *coll_id;
	gchar *item_id;

	g_return_val_if_fail (GKD_SECRETS_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (message, NULL);

	/* The session we're using to access the object */
	session = gkd_secrets_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	if (session == NULL)
		return NULL;

	/* Figure out which collection or item we're talking about */
	if (!parse_collection_and_item_from_path (dbus_message_get_path (message), &coll_id, &item_id))
		return NULL;

	/* It's an item */
	if (item_id) {
		object = item_for_identifier (session, coll_id, item_id);
		if (object != NULL) {
			reply = item_message_handler (self, object, message);
			g_object_unref (object);
		}

	/* It's a collection */
	} else {
		object = collection_for_identifier (session, coll_id);
		if (object != NULL) {
			reply = collection_message_handler (self, object, message);
			g_object_unref (object);
		}
	}

	g_free (coll_id);
	g_free (item_id);

	return reply;
}


void
gkd_secrets_objects_append_item_paths (GkdSecretsObjects *self, DBusMessageIter *iter,
                                       DBusMessage *message, const gchar *coll_id)
{
	DBusMessageIter variant;
	gchar *prefix, *part;
	DBusMessageIter array;
	GP11Session *session;
	GError *error = NULL;
	guchar *data;
	gsize n_data;
	gchar *path;
	GList *items, *l;

	g_return_if_fail (GKD_SECRETS_IS_OBJECTS (self));
	g_return_if_fail (coll_id);
	g_return_if_fail (iter && message);

	/* The session we're using to access the object */
	session = gkd_secrets_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_if_fail (session);

	items = gp11_session_find_objects (session, &error,
	                                   CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                                   CKA_G_COLLECTION, strlen (coll_id), coll_id,
	                                   GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup items in '%s' collection: %s", coll_id, error->message);
		g_clear_error (&error);
		return;
	}

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
	dbus_message_iter_open_container (&variant, DBUS_TYPE_ARRAY, "o", &array);
	prefix = encode_object_identifier (coll_id, -1);

	for (l = items; l; l = g_list_next (l)) {

		/* Dig out the raw item identifier */
		data = gp11_object_get_data (l->data, CKA_ID, &n_data, &error);
		if (error != NULL) {
			g_warning ("couldn't retrieve item id: %s", error->message);
			g_clear_error (&error);

		} else if (n_data) {

			/* Build up the object path */
			part = encode_object_identifier ((gchar*)data, n_data);
			path = g_strconcat (SECRETS_COLLECTION_PREFIX, "/", prefix, "/", part, NULL);
			g_free (part);

			dbus_message_iter_append_basic (&array, DBUS_TYPE_OBJECT_PATH, &path);
			g_free (path);
		}

		g_free (data);
	}

	dbus_message_iter_close_container (&variant, &array);
	dbus_message_iter_close_container (iter, &variant);

	g_free (prefix);

	gp11_list_unref_free (items);
}

void
gkd_secrets_objects_append_collection_paths (GkdSecretsObjects *self, DBusMessageIter *iter,
                                             DBusMessage *message)
{
	DBusMessageIter variant;
	DBusMessageIter array;
	GError *error = NULL;
	GP11Session *session;
	GList *colls, *l;
	guchar *data;
	gsize n_data;
	gchar *part;
	gchar *path;

	g_return_if_fail (GKD_SECRETS_IS_OBJECTS (self));
	g_return_if_fail (iter && message);

	/* The session we're using to access the object */
	session = gkd_secrets_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_if_fail (session);

	colls = gp11_session_find_objects (session, &error,
	                                   CKA_CLASS, GP11_ULONG, CKO_G_COLLECTION,
	                                   GP11_INVALID);

	if (error != NULL) {
		g_warning ("couldn't lookup collections: %s", error->message);
		g_clear_error (&error);
		return;
	}

	dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
	dbus_message_iter_open_container (&variant, DBUS_TYPE_ARRAY, "o", &array);

	for (l = colls; l; l = g_list_next (l)) {

		/* Dig out the raw item identifier */
		data = gp11_object_get_data (l->data, CKA_ID, &n_data, &error);
		if (error != NULL) {
			g_warning ("couldn't retrieve collection id: %s", error->message);
			g_clear_error (&error);

		} else if (n_data) {

			/* Build up the object path */
			part = encode_object_identifier ((gchar*)data, n_data);
			path = g_strconcat (SECRETS_COLLECTION_PREFIX, "/", part, NULL);
			g_free (part);

			dbus_message_iter_append_basic (&array, DBUS_TYPE_OBJECT_PATH, &path);
			g_free (path);
		}

		g_free (data);
	}

	dbus_message_iter_close_container (&variant, &array);
	dbus_message_iter_close_container (iter, &variant);

	gp11_list_unref_free (colls);
}
