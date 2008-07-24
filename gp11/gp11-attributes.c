
#include "config.h"

#include "gp11.h"
#include "gp11-private.h"

#include <stdlib.h>
#include <string.h>

void
gp11_attribute_init (GP11Attribute *attr, guint attr_type, 
                     gconstpointer value, gsize length)
{
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (GP11Attribute));
	attr->type = attr_type;
	attr->length = length;
	attr->value = value && length ? g_memdup (value, length) : NULL;
}

void
_gp11_attribute_init_take (GP11Attribute *attr, guint attr_type,
                           gpointer value, gsize length)
{
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (GP11Attribute));
	attr->type = attr_type;
	attr->length = length;
	attr->value = value && length ? value : NULL;	
}

void 
gp11_attribute_init_boolean (GP11Attribute *attr, guint attr_type, 
                             gboolean value)
{
	CK_BBOOL bvalue = value ? CK_TRUE : CK_FALSE;
	gp11_attribute_init (attr, attr_type, &bvalue, sizeof (bvalue));
}

void
gp11_attribute_init_date (GP11Attribute *attr, guint attr_type, 
                          const GDate *value)
{
	gchar buffer[9];
	CK_DATE date;
	g_return_if_fail (value);
	g_snprintf (buffer, sizeof (buffer), "%04d%02d%02d",
	            (int)g_date_get_year (value), 
	            (int)g_date_get_month (value),
	            (int)g_date_get_day (value));
	memcpy (&date.year, buffer + 0, 4);
	memcpy (&date.month, buffer + 4, 2);
	memcpy (&date.day, buffer + 6, 2);
	gp11_attribute_init (attr, attr_type, &date, sizeof (CK_DATE));
}

void
gp11_attribute_init_ulong (GP11Attribute *attr, guint attr_type,
                           gulong value)
{
	CK_ULONG uvalue = value;
	gp11_attribute_init (attr, attr_type, &uvalue, sizeof (uvalue));
}

void
gp11_attribute_init_string (GP11Attribute *attr, guint attr_type, 
                            const gchar *value)
{
	gsize len = value ? strlen (value) : 0;
	gp11_attribute_init (attr, attr_type, (gpointer)value, len);
}


GP11Attribute*
gp11_attribute_new (guint attr_type, gpointer value, gsize length)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init (attr, attr_type, value, length);
	return attr;
}

GP11Attribute*
gp11_attribute_new_boolean (guint attr_type, gboolean value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_boolean (attr, attr_type, value);
	return attr;	
}

GP11Attribute*
gp11_attribute_new_date (guint attr_type, const GDate *value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_date (attr, attr_type, value);
	return attr;		
}

GP11Attribute*
gp11_attribute_new_ulong (guint attr_type, gulong value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_ulong (attr, attr_type, value);
	return attr;			
}

GP11Attribute*
gp11_attribute_new_string (guint attr_type, const gchar *value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_string (attr, attr_type, value);
	return attr;		
}

gboolean
gp11_attribute_get_boolean (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, FALSE);
	g_return_val_if_fail (attr->length == sizeof (CK_BBOOL), FALSE);
	g_return_val_if_fail (attr->value, FALSE);
	return *((CK_BBOOL*)attr->value) == CK_TRUE ? TRUE : FALSE;
}

gulong
gp11_attribute_get_ulong (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, FALSE);
	g_return_val_if_fail (attr->length == sizeof (CK_ULONG), (gulong)-1);
	g_return_val_if_fail (attr->value, (gulong)-1);
	return *((CK_ULONG*)attr->value);
}

gchar*
gp11_attribute_get_string (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, NULL);
	
	if (!attr->value)
		return NULL;

	return g_strndup (attr->value, attr->length);
}

GDate*
gp11_attribute_get_date (GP11Attribute *attr)
{
	guint year, month, day;
	gchar buffer[5];
	CK_DATE *date;
	gchar *end;
	
	g_return_val_if_fail (attr, NULL);
	g_return_val_if_fail (attr->length == sizeof (CK_DATE), NULL);
	g_return_val_if_fail (attr->value, NULL);
	date = (CK_DATE*)attr->value;
	
	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->year, 4);
	year = strtol (buffer, &end, 10);
	g_return_val_if_fail (end != buffer && !*end, NULL); 
	
	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->month, 2);
	month = strtol (buffer, &end, 10);
	g_return_val_if_fail (end != buffer && !*end, NULL); 

	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->day, 2);
	day = strtol (buffer, &end, 10);
	g_return_val_if_fail (end != buffer && !*end, NULL); 
	
	return g_date_new_dmy (day, month, year);	
}

GP11Attribute*
gp11_attribute_dup (GP11Attribute *attr)
{
	GP11Attribute *copy;
	
	if (!attr)
		return NULL;
	
	copy = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_copy (copy, attr);
	return copy;
}

void
gp11_attribute_init_copy (GP11Attribute *dest, GP11Attribute *src)
{
	g_return_if_fail (dest);
	g_return_if_fail (src);

	/* 
	 * TODO: Handle stupid, dumb, broken, special cases like
	 * CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE. 
	 */
	
	memcpy (dest, src, sizeof (GP11Attribute));
	dest->value = src->value && src->length ? g_memdup (src->value, src->length) : NULL;
}

void
gp11_attribute_clear (GP11Attribute *attr)
{
	g_return_if_fail (attr);
	g_free (attr->value);
	memset (attr, 0, sizeof (GP11Attribute));
}

void
gp11_attribute_free (GP11Attribute *attr)
{
	if (attr) {
		gp11_attribute_clear (attr);
		g_slice_free (GP11Attribute, attr);
	}
}

struct _GP11Attributes {
	GArray *array;
	gint immutable;
	gint refs;
};

GP11Attributes*
gp11_attributes_new (void)
{
	GP11Attributes *attrs;
	
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	attrs = g_slice_new0 (GP11Attributes);
	attrs->array = g_array_new (0, 1, sizeof (GP11Attribute));
	attrs->refs = 1;
	attrs->immutable = 0;
	return attrs;
}

static GP11Attributes*
initialize_from_valist (guint type, va_list va)
{
	GP11Attributes *attrs;
	gssize length;
	gpointer value;
	
	attrs = gp11_attributes_new ();
	
	/* No attributes */
	if (type == (guint)-1)
		return attrs;
	
	do {
		length = va_arg (va, gssize);
		
		/* All the different set types */
		switch (length) {
		case GP11_BOOLEAN:
			gp11_attributes_add_boolean (attrs, type, va_arg (va, gboolean));
			break;
		case GP11_ULONG:
			gp11_attributes_add_ulong (attrs, type, va_arg (va, gulong));
			break;
		case GP11_STRING:
			gp11_attributes_add_string (attrs, type, va_arg (va, const gchar*));
			break;
		case GP11_DATE:
			gp11_attributes_add_date (attrs, type, va_arg (va, const GDate*));
			break;

		/* Otherwise it should be data */
		default:
			value = va_arg (va, gpointer);
			
			/* But not this long */
			if (length < 0 || length >= G_MAXSSIZE)
				g_warning ("length passed to attributes varargs is invalid or too large: %d", (int)length);
			else
				gp11_attributes_add_data (attrs, type, value, length);
			break;
		};
		
		type = va_arg (va, guint);
			
	} while (type != (guint)-1);
		
	return attrs;
}

GP11Attributes*
gp11_attributes_newv (guint first_type, ...)
{
	GP11Attributes *attrs;
	va_list va;
	
	va_start (va, first_type);
	attrs = initialize_from_valist (first_type, va);
	va_end (va);
	
	return attrs;
}

GP11Attributes*
gp11_attributes_new_valist (va_list va)
{
	guint type = va_arg (va, guint);
	return initialize_from_valist (type, va);
}

GP11Attribute*
gp11_attributes_at (GP11Attributes *attrs, guint index)
{
	g_return_val_if_fail (attrs && attrs->array, NULL);
	g_return_val_if_fail (index < attrs->array->len, NULL);
	g_return_val_if_fail (g_atomic_int_get (&attrs->immutable) == 0, NULL);
	return &g_array_index (attrs->array, GP11Attribute, index);
}

CK_ATTRIBUTE_PTR
_gp11_attributes_raw (GP11Attributes *attrs)
{
	g_return_val_if_fail (attrs && attrs->array, NULL);
	return (CK_ATTRIBUTE_PTR)attrs->array->data;
}

static GP11Attribute*
attributes_push (GP11Attributes *attrs)
{
	GP11Attribute attr;
	g_assert (g_atomic_int_get (&attrs->immutable) == 0);
	
	memset (&attr, 0, sizeof (attr));
	g_array_append_val (attrs->array, attr);
	return &g_array_index (attrs->array, GP11Attribute, attrs->array->len - 1);
}

void
gp11_attributes_add (GP11Attributes *attrs, GP11Attribute *attr)
{
	GP11Attribute *added;
	g_return_if_fail (attrs && attrs->array);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	g_return_if_fail (attr);
	added = attributes_push (attrs);
	gp11_attribute_init_copy (added, attr);
}

void
_gp11_attributes_add_take (GP11Attributes *attrs, guint attr_type,
                           gpointer value, gsize length)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	_gp11_attribute_init_take (added, attr_type, (gpointer)value, length);
}

void 
gp11_attributes_add_data (GP11Attributes *attrs, guint attr_type,
                          gconstpointer value, gsize length)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init (added, attr_type, value, length);
}

void
gp11_attributes_add_boolean (GP11Attributes *attrs, guint attr_type, gboolean value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_boolean (added, attr_type, value);
}

void
gp11_attributes_add_string (GP11Attributes *attrs, guint attr_type, const gchar *value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_string (added, attr_type, value);
}

void
gp11_attributes_add_date (GP11Attributes *attrs, guint attr_type, const GDate *value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_date (added, attr_type, value);
}

void
gp11_attributes_add_ulong (GP11Attributes *attrs, guint attr_type, gulong value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_ulong (added, attr_type, value);
}

gulong
gp11_attributes_count (GP11Attributes *attrs)
{
	g_return_val_if_fail (attrs, 0);
	return attrs->array->len;
}


GP11Attribute*
gp11_attributes_find (GP11Attributes *attrs, guint attr_type)
{
	GP11Attribute *attr;
	guint i;
	
	g_return_val_if_fail (attrs && attrs->array, NULL);
	
	for (i = 0; i < attrs->array->len; ++i) {
		attr = gp11_attributes_at (attrs, i);
		if (attr->type == attr_type)
			return attr;
	}
	
	return NULL;
}

gboolean
gp11_attributes_find_boolean (GP11Attributes *attrs, guint attr_type, gboolean *value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr)
		return FALSE;
	*value = gp11_attribute_get_boolean (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_ulong (GP11Attributes *attrs, guint attr_type, gulong *value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr)
		return FALSE;
	*value = gp11_attribute_get_ulong (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_string (GP11Attributes *attrs, guint attr_type, gchar **value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr)
		return FALSE;
	*value = gp11_attribute_get_string (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_date (GP11Attributes *attrs, guint attr_type, GDate **value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr)
		return FALSE;
	*value = gp11_attribute_get_date (attr);
	return TRUE;
}

void 
gp11_attributes_ref (GP11Attributes *attrs)
{
	g_return_if_fail (attrs);
	g_atomic_int_inc (&attrs->refs);
}

void
gp11_attributes_unref (GP11Attributes *attrs)
{
	guint i;
	
	if (!attrs)
		return;
	
	if (g_atomic_int_dec_and_test (&attrs->refs)) {
		g_return_if_fail (attrs->array);
		for (i = 0; i < attrs->array->len; ++i)
			gp11_attribute_clear (gp11_attributes_at (attrs, i));
		g_array_free (attrs->array, TRUE);
		attrs->array = NULL;
		g_slice_free (GP11Attributes, attrs);
	}
}
