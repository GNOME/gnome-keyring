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

#include "gkd-secret-service.h"
#include "gkd-secret-objects.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_PKCS11_SLOT,
	PROP_SERVICE
};

struct _GkdSecretObjects {
	GObject parent;
	GkdSecretService *service;
	GP11Slot *pkcs11_slot;
};

G_DEFINE_TYPE (GkdSecretObjects, gkd_secret_objects, G_TYPE_OBJECT);

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
typedef gboolean (*IterGetFunc) (DBusMessageIter*, GP11Attribute*);

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

static gboolean
iter_get_string (DBusMessageIter *iter, GP11Attribute* attr)
{
	const char *value;

	g_assert (iter);
	g_assert (attr);

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING, FALSE);
	dbus_message_iter_get_basic (iter, &value);
	if (value == NULL)
		value = "";
	gp11_attribute_init_string (attr, attr->type, value);
	return TRUE;
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

static gboolean
iter_get_bool (DBusMessageIter *iter, GP11Attribute* attr)
{
	dbus_bool_t value;

	g_assert (iter);
	g_assert (attr);

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_BOOLEAN, FALSE);
	dbus_message_iter_get_basic (iter, &value);
	gp11_attribute_init_boolean (attr, attr->type, value ? TRUE : FALSE);
	return TRUE;
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

static gboolean
iter_get_time (DBusMessageIter *iter, GP11Attribute* attr)
{
	time_t time;
	struct tm tm;
	gchar buf[20];
	gint64 value;

	g_assert (iter);
	g_assert (attr);

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_INT64, FALSE);
	dbus_message_iter_get_basic (iter, &value);
	if (value < 0) {
		gp11_attribute_init_empty (attr, attr->type);
		return TRUE;
	}

	time = value;
	if (!gmtime_r (&time, &tm))
		g_return_val_if_reached (FALSE);

	if (!strftime (buf, sizeof (buf), "%Y%m%d%H%M%S00", &tm))
		g_return_val_if_reached (FALSE);

	gp11_attribute_init (attr, attr->type, buf, 16);
	return TRUE;
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

static gboolean
iter_get_fields (DBusMessageIter *iter, GP11Attribute* attr)
{
	DBusMessageIter array;
	DBusMessageIter dict;
	GString *result;
	const gchar *string;

	g_assert (iter);

	result = g_string_new ("");

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_ARRAY, FALSE);
	dbus_message_iter_recurse (iter, &array);

	while (dbus_message_iter_get_arg_type (&array) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse (&array, &dict);

		/* Key */
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) == DBUS_TYPE_STRING, FALSE);
		dbus_message_iter_get_basic (&dict, &string);
		g_string_append (result, string);
		g_string_append_c (result, '\0');

		dbus_message_iter_next (&dict);

		/* Value */
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) == DBUS_TYPE_STRING, FALSE);
		dbus_message_iter_get_basic (&dict, &string);
		g_string_append (result, string);
		g_string_append_c (result, '\0');

		dbus_message_iter_next (&array);
	}

	gp11_attribute_init (attr, attr->type, result->str, result->len);
	g_string_free (result, TRUE);
	return TRUE;
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

static gboolean
iter_get_variant (DBusMessageIter *iter, DataType data_type, GP11Attribute *attr)
{
	DBusMessageIter variant;
	IterGetFunc func;
	gboolean ret;
	const gchar *sig;
	char *signature;

	g_assert (iter);
	g_assert (attr);

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_VARIANT, FALSE);
	dbus_message_iter_recurse (iter, &variant);

	switch (data_type) {
	case DATA_TYPE_STRING:
		func = iter_get_string;
		sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DATA_TYPE_BOOL:
		func = iter_get_bool;
		sig = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DATA_TYPE_TIME:
		func = iter_get_time;
		sig = DBUS_TYPE_INT64_AS_STRING;
		break;
	case DATA_TYPE_FIELDS:
		func = iter_get_fields;
		sig = "a{ss}";
		break;
	default:
		g_assert (FALSE);
		break;
	}

	signature = dbus_message_iter_get_signature (&variant);
	g_return_val_if_fail (signature, FALSE);
	ret = g_str_equal (sig, signature);
	dbus_free (signature);

	if (ret == FALSE)
		return FALSE;

	return (func) (&variant, attr);
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

static void
iter_append_item_paths (DBusMessageIter *iter, GList *items)
{
	DBusMessageIter array;
	gchar *path;
	GList *l;

	dbus_message_iter_open_container (iter, DBUS_TYPE_ARRAY, "o", &array);

	for (l = items; l; l = g_list_next (l)) {
		path = gkd_secret_util_path_for_item (l->data);
		if (path != NULL) {
			dbus_message_iter_append_basic (&array, DBUS_TYPE_OBJECT_PATH, &path);
			g_free (path);
		}
	}

	dbus_message_iter_close_container (iter, &array);
}

static void
iter_append_collection_paths (DBusMessageIter *iter, GList *collections)
{
	DBusMessageIter array;
	gchar *path;
	GList *l;

	dbus_message_iter_open_container (iter, DBUS_TYPE_ARRAY, "o", &array);

	for (l = collections; l; l = g_list_next (l)) {
		path = gkd_secret_util_path_for_collection (l->data);
		if (path != NULL) {
			dbus_message_iter_append_basic (&array, DBUS_TYPE_OBJECT_PATH, &path);
			g_free (path);
		}
	}

	dbus_message_iter_close_container (iter, &array);
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
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't retrieve '%s' property: %s",
		                                       prop_name, error->message);
		g_clear_error (&error);
		return reply;
	}

	/* Marshall the data back out */
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	iter_append_variant (&iter, data_type, &attr);
	g_free (attr.value);
	return reply;
}

static DBusMessage*
object_property_set (GP11Object *object, DBusMessage *message,
                     DBusMessageIter *iter, const gchar *prop_name)
{
	DBusMessage *reply;
	GP11Attributes *attrs;
	GP11Attribute *attr;
	GError *error = NULL;
	gulong attr_type;
	DataType data_type;

	g_return_val_if_fail (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_VARIANT, NULL);

	/* What type of property is it? */
	if (!property_to_attribute (prop_name, &attr_type, &data_type)) {
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have the '%s' property", prop_name);
	}

	attrs = gp11_attributes_new ();
	gp11_attributes_add_empty (attrs, attr_type);
	attr = gp11_attributes_at (attrs, 0);

	/* Retrieve the actual attribute value */
	if (!iter_get_variant (iter, data_type, attr)) {
		gp11_attributes_unref (attrs);
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "The property type or value was invalid: %s", prop_name);
	}

	gp11_object_set_full (object, attrs, NULL, &error);
	gp11_attributes_unref (attrs);

	if (error != NULL) {
		if (error->code == CKR_USER_NOT_LOGGED_IN)
			reply = dbus_message_new_error (message, SECRET_ERROR_IS_LOCKED,
			                                "Cannot set property on a locked object");
		else
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
			                                       "Couldn't set '%s' property: %s",
			                                       prop_name, error->message);
		g_clear_error (&error);
		return reply;
	}

	return dbus_message_new_method_return (message);
}

static DBusMessage*
item_property_get (GP11Object *object, DBusMessage *message)
{
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	return object_property_get (object, message, name);
}

static DBusMessage*
item_property_set (GP11Object *object, DBusMessage *message)
{
	DBusMessageIter iter;
	const char *interface;
	const char *name;

	if (!dbus_message_has_signature (message, "ssv"))
		return NULL;

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_get_basic (&iter, &interface);
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &name);
	dbus_message_iter_next (&iter);

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	return object_property_set (object, message, &iter, name);
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

	if (!gkd_dbus_interface_match (SECRET_ITEM_INTERFACE, interface))
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
item_method_delete (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *prompt;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	if (!gp11_object_destroy (object, &error)) {
		if (error->code == CKR_USER_NOT_LOGGED_IN)
			reply = dbus_message_new_error_printf (message, SECRET_ERROR_IS_LOCKED,
			                                       "Cannot delete a locked item");
		else
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
			                                       "Couldn't delete collection: %s",
			                                       error->message);
		g_clear_error (&error);
		return reply;
	}

	prompt = "/"; /* No prompt necessary */
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID);
	return reply;
}

static DBusMessage*
item_message_handler (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	/* org.freedesktop.Secrets.Item.Delete() */
	if (dbus_message_is_method_call (message, SECRET_ITEM_INTERFACE, "Delete"))
		return item_method_delete (self, object, message);

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

static DBusMessage*
collection_property_get (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const gchar *interface;
	const gchar *name;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &interface,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
		return NULL;

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	/* Special case, the Items property */
	if (g_str_equal (name, "Items")) {
		reply = dbus_message_new_method_return (message);
		dbus_message_iter_init_append (reply, &iter);
		gkd_secret_objects_append_item_paths (self, &iter, message, object);
		return reply;
	}

	return object_property_get (object, message, name);
}

static DBusMessage*
collection_property_set (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	DBusMessageIter iter;
	const char *interface;
	const char *name;

	if (!dbus_message_has_signature (message, "ssv"))
		return NULL;

	dbus_message_iter_init (message, &iter);
	dbus_message_iter_get_basic (&iter, &interface);
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &name);
	dbus_message_iter_next (&iter);

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
		return dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                      "Object does not have properties on interface '%s'",
		                                      interface);

	return object_property_set (object, message, &iter, name);
}

static DBusMessage*
collection_property_getall (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
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

	if (!gkd_dbus_interface_match (SECRET_COLLECTION_INTERFACE, interface))
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
	gkd_secret_objects_append_item_paths (self, &dict, message, object);
	dbus_message_iter_close_container (&array, &dict);

	dbus_message_iter_close_container (&iter, &array);
	return reply;
}

static DBusMessage*
collection_method_search_items (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	return gkd_secret_objects_handle_search_items (self, message, object);
}

static GP11Object*
collection_find_matching_item (GkdSecretObjects *self, GP11Object *coll, GP11Attribute *fields)
{
	GP11Attributes *attrs;
	const gchar *identifier;
	GP11Object *result = NULL;
	GError *error = NULL;
	GP11Session *session;
	GP11Object *search;
	gpointer data;
	gsize n_data;

	identifier = gkd_secret_util_identifier_for_collection (coll);
	g_return_val_if_fail (identifier, NULL);

	/* Find items matching the collection and fields */
	attrs = gp11_attributes_new ();
	gp11_attributes_add (attrs, fields);
	gp11_attributes_add_string (attrs, CKA_G_COLLECTION, identifier);
	gp11_attributes_add_ulong (attrs, CKA_CLASS, CKO_G_SEARCH);
	gp11_attributes_add_boolean (attrs, CKA_TOKEN, FALSE);

	/* The session we're using to find the object */
	session = gp11_object_get_session (coll);
	g_return_val_if_fail (session, NULL);

	/* Create the search object */
	search = gp11_session_create_object_full (session, attrs, NULL, &error);
	gp11_attributes_unref (attrs);

	if (error != NULL) {
		g_warning ("couldn't search for matching item: %s", error->message);
		g_clear_error (&error);
		return NULL;
	}

	/* Get the matched item handles, and delete the search object */
	gp11_object_set_session (search, session);
	data = gp11_object_get_data (search, CKA_G_MATCHED, &n_data, NULL);
	gp11_object_destroy (search, NULL);
	g_object_unref (search);

	if (n_data >= sizeof (CK_OBJECT_HANDLE)) {
		result = gp11_object_from_handle (gp11_session_get_slot (session),
		                                  *((CK_OBJECT_HANDLE_PTR)data));
		gp11_object_set_session (result, session);
	}

	g_free (data);
	return result;
}

static DBusMessage*
collection_method_create_item (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	dbus_bool_t replace = FALSE;
	GP11Attributes *attrs;
	GP11Attribute *fields;
	DBusMessageIter iter;
	GP11Object *item = NULL;
	const gchar *prompt;
	GError *error = NULL;
	GP11Session *session;
	DBusMessage *reply;
	gchar *path = NULL;
	gchar *identifier;

	/* Parse the message */
	if (!dbus_message_has_signature (message, "a{sv}b"))
		return NULL;
	if (!dbus_message_iter_init (message, &iter))
		g_return_val_if_reached (NULL);
	attrs = gp11_attributes_new ();
	if (!gkd_secret_objects_parse_item_props (self, &iter, attrs)) {
		gp11_attributes_unref (attrs);
		return dbus_message_new_error_printf (message, DBUS_ERROR_INVALID_ARGS,
		                                      "Invalid properties");
	}
	dbus_message_iter_next (&iter);
	dbus_message_iter_get_basic (&iter, &replace);

	if (replace) {
		fields = gp11_attributes_find (attrs, CKA_G_FIELDS);
		if (fields)
			item = collection_find_matching_item (self, object, fields);
	}

	/* Replace the item */
	if (item) {
		if (!gp11_object_set_full (item, attrs, NULL, &error)) {
			g_object_unref (item);
			item = NULL;
		}

	/* Create a new item */
	} else {
		session = gp11_object_get_session (object);
		g_return_val_if_fail (session, NULL);
		identifier = gkd_secret_util_identifier_for_collection (object);
		g_return_val_if_fail (identifier, NULL);
		gp11_attributes_add_ulong (attrs, CKA_CLASS, CKO_SECRET_KEY);
		gp11_attributes_add_string (attrs, CKA_G_COLLECTION, identifier);
		item = gp11_session_create_object_full (session, attrs, NULL, &error);
		g_free (identifier);
	}

	/* Build up the item identifier */
	if (error == NULL)
		path = gkd_secret_util_path_for_item (item);

	if (path != NULL) {
		prompt = "/";
		reply = dbus_message_new_method_return (message);
		dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &path,
		                          DBUS_TYPE_OBJECT_PATH, &prompt,
		                          DBUS_TYPE_INVALID);

	} else {
		if (error->code == CKR_USER_NOT_LOGGED_IN)
			reply = dbus_message_new_error_printf (message, SECRET_ERROR_IS_LOCKED,
			                                       "Cannot create an item in a locked collection");
		else
			reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
			                                       "Couldn't create item: %s", error->message);
		g_clear_error (&error);
	}

	if (item)
		g_object_unref (item);
	g_free (path);
	return reply;
}

static DBusMessage*
collection_method_delete (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	GError *error = NULL;
	DBusMessage *reply;
	const gchar *prompt;

	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_INVALID))
		return NULL;

	if (!gp11_object_destroy (object, &error)) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't delete collection: %s",
		                                       error->message);
		g_clear_error (&error);
		return reply;
	}

	prompt = "/";
	reply = dbus_message_new_method_return (message);
	dbus_message_append_args (reply, DBUS_TYPE_OBJECT_PATH, &prompt, DBUS_TYPE_INVALID);
	return reply;
}

static DBusMessage*
collection_message_handler (GkdSecretObjects *self, GP11Object *object, DBusMessage *message)
{
	/* org.freedesktop.Secrets.Collection.Delete() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "Delete"))
		return collection_method_delete (self, object, message);

	/* org.freedesktop.Secrets.Collection.SearchItems() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "SearchItems"))
		return collection_method_search_items (self, object, message);

	/* org.freedesktop.Secrets.Collection.CreateItem() */
	if (dbus_message_is_method_call (message, SECRET_COLLECTION_INTERFACE, "CreateItem"))
		return collection_method_create_item (self, object, message);

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
gkd_secret_objects_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (G_OBJECT_CLASS (gkd_secret_objects_parent_class)->constructor(type, n_props, props));

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->pkcs11_slot, NULL);
	g_return_val_if_fail (self->service, NULL);

	return G_OBJECT (self);
}

static void
gkd_secret_objects_init (GkdSecretObjects *self)
{

}

static void
gkd_secret_objects_dispose (GObject *obj)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	if (self->pkcs11_slot) {
		g_object_unref (self->pkcs11_slot);
		self->pkcs11_slot = NULL;
	}

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_objects_parent_class)->dispose (obj);
}

static void
gkd_secret_objects_finalize (GObject *obj)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	g_assert (!self->pkcs11_slot);
	g_assert (!self->service);

	G_OBJECT_CLASS (gkd_secret_objects_parent_class)->finalize (obj);
}

static void
gkd_secret_objects_set_property (GObject *obj, guint prop_id, const GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

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
gkd_secret_objects_get_property (GObject *obj, guint prop_id, GValue *value,
                                     GParamSpec *pspec)
{
	GkdSecretObjects *self = GKD_SECRET_OBJECTS (obj);

	switch (prop_id) {
	case PROP_PKCS11_SLOT:
		g_value_set_object (value, gkd_secret_objects_get_pkcs11_slot (self));
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
gkd_secret_objects_class_init (GkdSecretObjectsClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secret_objects_constructor;
	gobject_class->dispose = gkd_secret_objects_dispose;
	gobject_class->finalize = gkd_secret_objects_finalize;
	gobject_class->set_property = gkd_secret_objects_set_property;
	gobject_class->get_property = gkd_secret_objects_get_property;

	g_object_class_install_property (gobject_class, PROP_PKCS11_SLOT,
	        g_param_spec_object ("pkcs11-slot", "Pkcs11 Slot", "PKCS#11 slot that we use for secrets",
	                             GP11_TYPE_SLOT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this objects",
		                     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GP11Slot*
gkd_secret_objects_get_pkcs11_slot (GkdSecretObjects *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	return self->pkcs11_slot;
}

DBusMessage*
gkd_secret_objects_dispatch (GkdSecretObjects *self, DBusMessage *message)
{
	DBusMessage *reply = NULL;
	GP11Object *object;
	GP11Session *session;
	gboolean is_item;
	const char *path;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (message, NULL);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	if (session == NULL)
		return NULL;

	path = dbus_message_get_path (message);
	g_return_val_if_fail (path, NULL);

	object = gkd_secret_util_path_to_object (session, path, &is_item);
	if (!object)
		return NULL;

	if (is_item)
		reply = item_message_handler (self, object, message);
	else
		reply = collection_message_handler (self, object, message);

	g_object_unref (object);
	return reply;
}

gboolean
gkd_secret_objects_parse_item_props (GkdSecretObjects *self, DBusMessageIter *iter,
                                     GP11Attributes *attrs)
{
	DBusMessageIter array, dict;
	CK_ATTRIBUTE_TYPE attr_type;
	GP11Attribute *attr;
	const char *name;
	DataType data_type;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), FALSE);
	g_return_val_if_fail (iter, FALSE);
	g_return_val_if_fail (attrs, FALSE);

	dbus_message_iter_recurse (iter, &array);

	while (dbus_message_iter_get_arg_type (&array) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse (&array, &dict);

		/* Property name */
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) == DBUS_TYPE_STRING, FALSE);
		dbus_message_iter_get_basic (&dict, &name);
		dbus_message_iter_next (&dict);

		if (!property_to_attribute (name, &attr_type, &data_type))
			return FALSE;

		/* Property value */
		g_return_val_if_fail (dbus_message_iter_get_arg_type (&dict) == DBUS_TYPE_VARIANT, FALSE);
		attr = gp11_attributes_add_empty (attrs, attr_type);
		if (!iter_get_variant (&dict, data_type, attr))
			return FALSE;

		dbus_message_iter_next (&array);
	}

	return TRUE;
}


void
gkd_secret_objects_append_item_paths (GkdSecretObjects *self, DBusMessageIter *iter,
                                      DBusMessage *message, GP11Object *collection)
{
	DBusMessageIter variant;
	GP11Session *session;
	GError *error = NULL;
	gchar *identifier;
	GList *items;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (GP11_IS_OBJECT (collection));
	g_return_if_fail (iter && message);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_if_fail (session);

	identifier = gkd_secret_util_identifier_for_collection (collection);
	g_return_if_fail (identifier);

	items = gp11_session_find_objects (session, &error,
	                                   CKA_CLASS, GP11_ULONG, CKO_SECRET_KEY,
	                                   CKA_G_COLLECTION, strlen (identifier), identifier,
	                                   GP11_INVALID);

	if (error == NULL) {
		dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "ao", &variant);
		iter_append_item_paths (&variant, items);
		dbus_message_iter_close_container (iter, &variant);
	} else {
		g_warning ("couldn't lookup items in '%s' collection: %s", identifier, error->message);
		g_clear_error (&error);
	}

	gp11_list_unref_free (items);
	g_free (identifier);
}

void
gkd_secret_objects_append_collection_paths (GkdSecretObjects *self, DBusMessageIter *iter,
                                            DBusMessage *message)
{
	DBusMessageIter variant;
	GError *error = NULL;
	GP11Session *session;
	GList *colls;

	g_return_if_fail (GKD_SECRET_IS_OBJECTS (self));
	g_return_if_fail (iter && message);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
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
	iter_append_collection_paths (&variant, colls);
	dbus_message_iter_close_container (iter, &variant);
	gp11_list_unref_free (colls);
}

DBusMessage*
gkd_secret_objects_handle_search_items (GkdSecretObjects *self, DBusMessage *message,
                                        GP11Object *collection)
{
	GP11Attributes *attrs;
	GP11Attribute *attr;
	DBusMessageIter iter;
	GP11Object *search;
	GP11Session *session;
	DBusMessage *reply;
	GError *error = NULL;
	gchar *identifier;
	gpointer data;
	gsize n_data;
	GList *items;

	g_return_val_if_fail (GKD_SECRET_IS_OBJECTS (self), NULL);
	g_return_val_if_fail (message, NULL);

	if (!dbus_message_has_signature (message, "a{ss}"))
		return NULL;

	attrs = gp11_attributes_new ();
	attr = gp11_attributes_add_empty (attrs, CKA_G_FIELDS);

	dbus_message_iter_init (message, &iter);
	if (!iter_get_fields (&iter, attr)) {
		gp11_attributes_unref (attrs);
		return dbus_message_new_error (message, DBUS_ERROR_FAILED,
		                               "Invalid data in attributes argument");
	}

	if (collection != NULL) {
		identifier = gkd_secret_util_identifier_for_collection (collection);
		g_return_val_if_fail (identifier, NULL);
		gp11_attributes_add_string (attrs, CKA_G_COLLECTION, identifier);
		g_free (identifier);
	}

	gp11_attributes_add_ulong (attrs, CKA_CLASS, CKO_G_SEARCH);
	gp11_attributes_add_boolean (attrs, CKA_TOKEN, FALSE);

	/* The session we're using to access the object */
	session = gkd_secret_service_get_pkcs11_session (self->service, dbus_message_get_sender (message));
	g_return_val_if_fail (session, NULL);

	/* Create the search object */
	search = gp11_session_create_object_full (session, attrs, NULL, &error);
	gp11_attributes_unref (attrs);

	if (error != NULL) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't search for items: %s",
		                                       error->message);
		g_clear_error (&error);
		return reply;
	}

	/* Get the matched item handles, and delete the search object */
	gp11_object_set_session (search, session);
	data = gp11_object_get_data (search, CKA_G_MATCHED, &n_data, &error);
	gp11_object_destroy (search, NULL);
	g_object_unref (search);

	if (error != NULL) {
		reply = dbus_message_new_error_printf (message, DBUS_ERROR_FAILED,
		                                       "Couldn't retrieve matched items: %s",
		                                       error->message);
		g_clear_error (&error);
		return reply;
	}

	/* Build a list of object handles */
	items = gp11_objects_from_handle_array (gp11_session_get_slot (session),
	                                        data, n_data / sizeof (CK_OBJECT_HANDLE));
	g_free (data);

	/* Prepare the reply message */
	reply = dbus_message_new_method_return (message);
	dbus_message_iter_init_append (reply, &iter);
	iter_append_item_paths (&iter, items);
	gp11_list_unref_free (items);

	return reply;
}
