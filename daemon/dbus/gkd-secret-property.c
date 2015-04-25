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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-property.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>


typedef enum _DataType {
	DATA_TYPE_INVALID = 0,

	/*
	 * The attribute is a CK_BBOOL.
	 * Property is DBUS_TYPE_BOOLEAN
	 */
	DATA_TYPE_BOOL,

	/*
	 * The attribute is in the format: "%Y%m%d%H%M%S00"
	 * Property is DBUS_TYPE_UINT64 since 1970 epoch.
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
property_to_attribute (const gchar *prop_name, const gchar *interface,
		       CK_ATTRIBUTE_TYPE *attr_type, DataType *data_type)
{
	g_return_val_if_fail (prop_name, FALSE);
	g_assert (attr_type);
	g_assert (data_type);

	/* If an interface is desired, check that it matches, and remove */
	if (interface) {
		if (!g_str_has_prefix (prop_name, interface))
			return FALSE;

		prop_name += strlen (interface);
		if (prop_name[0] != '.')
			return FALSE;
		++prop_name;
	}

	if (g_str_equal (prop_name, "Label")) {
		*attr_type = CKA_LABEL;
		*data_type = DATA_TYPE_STRING;

	/* Non-standard property for type schema */
	} else if (g_str_equal (prop_name, "Type")) {
		*attr_type = CKA_G_SCHEMA;
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
	/* Non-standard property for type schema */
	case CKA_G_SCHEMA:
		*prop_name = "Type";
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

typedef GVariant * (*IterAppendFunc) (const GckAttribute *);
typedef gboolean (*IterGetFunc) (GVariant *, gulong, GckBuilder *);

static GVariant *
iter_append_string (const GckAttribute *attr)
{
	g_assert (attr);

	if (attr->length == 0) {
		return g_variant_new_string ("");
	} else {
		return g_variant_new_take_string (g_strndup ((const gchar*)attr->value, attr->length));
	}
}

static gboolean
iter_get_string (GVariant *variant,
		 gulong attr_type,
		 GckBuilder *builder)
{
	const char *value;

	g_assert (variant != NULL);
	g_assert (builder != NULL);

	value = g_variant_get_string (variant, NULL);
	if (value == NULL)
		value = "";
	gck_builder_add_string (builder, attr_type, value);
	return TRUE;
}

static GVariant *
iter_append_bool (const GckAttribute *attr)
{
	g_assert (attr);

	return g_variant_new_boolean (gck_attribute_get_boolean (attr));
}

static gboolean
iter_get_bool (GVariant *variant,
	       gulong attr_type,
	       GckBuilder *builder)
{
	gboolean value;

	g_assert (variant != NULL);
	g_assert (builder != NULL);

	value = g_variant_get_boolean (variant);
	gck_builder_add_boolean (builder, attr_type, value);
	return TRUE;
}

static GVariant *
iter_append_time (const GckAttribute *attr)
{
	guint64 value;
	struct tm tm;
	gchar buf[15];
	time_t time;

	g_assert (attr);

	if (attr->length == 0) {
		value = 0;

	} else if (!attr->value || attr->length != 16) {
		g_warning ("invalid length of time attribute");
		value = 0;

	} else {
		memset (&tm, 0, sizeof (tm));
		memcpy (buf, attr->value, 14);
		buf[14] = 0;

		if (!strptime(buf, "%Y%m%d%H%M%S", &tm)) {
			g_warning ("invalid format of time attribute");
			value = 0;
		} else {
			/* Convert to seconds since epoch */
			time = timegm (&tm);
			if (time < 0) {
				g_warning ("invalid time attribute");
				value = 0;
			} else {
				value = time;
			}
		}
	}

	return g_variant_new_uint64 (value);
}

static gboolean
iter_get_time (GVariant *variant,
	       gulong attr_type,
	       GckBuilder *builder)
{
	time_t time;
	struct tm tm;
	gchar buf[20];
	guint64 value;

	g_assert (variant != NULL);
	g_assert (builder != NULL);

	value = g_variant_get_uint64 (variant);
	if (value == 0) {
		gck_builder_add_empty (builder, attr_type);
		return TRUE;
	}

	time = value;
	if (!gmtime_r (&time, &tm))
		g_return_val_if_reached (FALSE);

	if (!strftime (buf, sizeof (buf), "%Y%m%d%H%M%S00", &tm))
		g_return_val_if_reached (FALSE);

	gck_builder_add_data (builder, attr_type, (const guchar *)buf, 16);
	return TRUE;
}

static GVariant *
iter_append_fields (const GckAttribute *attr)
{
	const gchar *ptr;
	const gchar *last;
	const gchar *name;
	gsize n_name;
	const gchar *value;
	gsize n_value;
	gchar *name_string, *value_string;
	GVariantBuilder builder;

	g_assert (attr);

	ptr = (gchar*)attr->value;
	last = ptr + attr->length;
	g_return_val_if_fail (ptr || last == ptr, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

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

		name_string = g_strndup (name, n_name);
		value_string = g_strndup (value, n_value);

		g_variant_builder_add (&builder, "{ss}", name_string, value_string);

		g_free (name_string);
		g_free (value_string);
	}

	return g_variant_builder_end (&builder);
}

static gboolean
iter_get_fields (GVariant *variant,
		 gulong attr_type,
		 GckBuilder *builder)
{
	GString *result;
	const gchar *key, *value;
	GVariantIter iter;

	g_assert (variant != NULL);
	g_assert (builder != NULL);

	g_return_val_if_fail (g_variant_type_is_array (g_variant_get_type (variant)), FALSE);

	result = g_string_new ("");
	g_variant_iter_init (&iter, variant);

	while (g_variant_iter_next (&iter, "{&s&s}", &key, &value)) {
		/* Key */
		g_string_append (result, key);
		g_string_append_c (result, '\0');

		/* Value */
		g_string_append (result, value);
		g_string_append_c (result, '\0');
	}

	gck_builder_add_data (builder, attr_type, (const guchar *)result->str, result->len);
	g_string_free (result, TRUE);
	return TRUE;
}

static GVariant *
iter_append_variant (DataType data_type,
		     const GckAttribute *attr)
{
	IterAppendFunc func = NULL;

	g_assert (attr);

	switch (data_type) {
	case DATA_TYPE_STRING:
		func = iter_append_string;
		break;
	case DATA_TYPE_BOOL:
		func = iter_append_bool;
		break;
	case DATA_TYPE_TIME:
		func = iter_append_time;
		break;
	case DATA_TYPE_FIELDS:
		func = iter_append_fields;
		break;
	default:
		g_assert (FALSE);
		break;
	}

	return (func) (attr);
}

static gboolean
iter_get_variant (GVariant *variant,
		  DataType data_type,
		  gulong attr_type,
		  GckBuilder *builder)
{
	IterGetFunc func = NULL;
	gboolean ret;
	const GVariantType *sig;

	g_assert (variant != NULL);
	g_assert (builder != NULL);

	switch (data_type) {
	case DATA_TYPE_STRING:
		func = iter_get_string;
		sig = G_VARIANT_TYPE_STRING;
		break;
	case DATA_TYPE_BOOL:
		func = iter_get_bool;
		sig = G_VARIANT_TYPE_BOOLEAN;
		break;
	case DATA_TYPE_TIME:
		func = iter_get_time;
		sig = G_VARIANT_TYPE_UINT64;
		break;
	case DATA_TYPE_FIELDS:
		func = iter_get_fields;
		sig = G_VARIANT_TYPE ("a{ss}");
		break;
	default:
		g_assert (FALSE);
		break;
	}

	ret = g_variant_type_equal (g_variant_get_type (variant), sig);
	if (ret == FALSE)
		return FALSE;

	return (func) (variant, attr_type, builder);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

gboolean
gkd_secret_property_get_type (const gchar *property, CK_ATTRIBUTE_TYPE *type)
{
	DataType data_type;

	g_return_val_if_fail (property, FALSE);
	g_return_val_if_fail (type, FALSE);

	return property_to_attribute (property, NULL, type, &data_type);
}

gboolean
gkd_secret_property_parse_all (GVariant *array,
			       const gchar *interface,
			       GckBuilder *builder)
{
	CK_ATTRIBUTE_TYPE attr_type;
	const char *name;
	DataType data_type;
	GVariantIter iter;
	GVariant *variant;

	g_return_val_if_fail (array != NULL, FALSE);
	g_return_val_if_fail (builder != NULL, FALSE);

	g_variant_iter_init (&iter, array);

	while (g_variant_iter_next (&iter, "{&sv}", &name, &variant)) {
		/* Property interface.name */
		if (!property_to_attribute (name, interface, &attr_type, &data_type))
			return FALSE;

		/* Property value */
		if (!iter_get_variant (variant, data_type, attr_type, builder)) {
			g_variant_unref (variant);
			return FALSE;
		}

		g_variant_unref (variant);
	}

	return TRUE;
}

GVariant *
gkd_secret_property_append_all (GckAttributes *attrs)
{
	const GckAttribute *attr;
	DataType data_type;
	const gchar *name;
	gulong num, i;
	GVariantBuilder builder;
	GVariant *variant;

	g_return_val_if_fail (attrs, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	num = gck_attributes_count (attrs);

	for (i = 0; i < num; ++i) {
		attr = gck_attributes_at (attrs, i);
		if (!attribute_to_property (attr->type, &name, &data_type))
			g_return_val_if_reached (NULL);

		variant = iter_append_variant (data_type, attr);
		g_variant_builder_add (&builder, "{sv}", name, variant);
		g_variant_unref (variant);
	}

	return g_variant_builder_end (&builder);
}

GVariant *
gkd_secret_property_append_variant (const GckAttribute *attr)
{
	const gchar *property;
	DataType data_type;

	g_return_val_if_fail (attr, NULL);

	if (!attribute_to_property (attr->type, &property, &data_type))
		return NULL;
	return iter_append_variant (data_type, attr);
}

gboolean
gkd_secret_property_parse_variant (GVariant *variant,
				   const gchar *property,
				   GckBuilder *builder)
{
	CK_ATTRIBUTE_TYPE attr_type;
	DataType data_type;

	g_return_val_if_fail (variant, FALSE);
	g_return_val_if_fail (property, FALSE);
	g_return_val_if_fail (builder != NULL, FALSE);

	if (!property_to_attribute (property, NULL, &attr_type, &data_type))
		return FALSE;

	return iter_get_variant (variant, data_type, attr_type, builder);
}

gboolean
gkd_secret_property_parse_fields (GVariant *variant,
				  GckBuilder *builder)
{
	g_return_val_if_fail (variant != NULL, FALSE);
	g_return_val_if_fail (builder != NULL, FALSE);

	return iter_get_fields (variant, CKA_G_FIELDS, builder);
}
