
#include "config.h"

#include "gp11.h"
#include "gp11-private.h"

#include <stdlib.h>
#include <string.h>

/**
 * gp11_attribute_init:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The raw value of the attribute.
 * @length: The length of the raw value.
 * 
 * Initialize a PKCS#11 attribute. This copies the value memory 
 * into an internal buffer.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/ 
void
gp11_attribute_init (GP11Attribute *attr, gulong attr_type, 
                     gconstpointer value, gsize length)
{
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (GP11Attribute));
	attr->type = attr_type;
	attr->length = length;
	attr->value = value && length ? g_memdup (value, length) : NULL;
}

/**
 * gp11_attribute_init_invalid:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * 
 * Initialize a PKCS#11 attribute to an 'invalid' or 'not found' 
 * state. Specifically this sets the value length to (CK_ULONG)-1
 * as specified in the PKCS#11 specification.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/
void
gp11_attribute_init_invalid (GP11Attribute *attr, gulong attr_type)
{
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (GP11Attribute));
	attr->type = attr_type;
	attr->length = (gulong)-1;
}

void
_gp11_attribute_init_take (GP11Attribute *attr, gulong attr_type,
                           gpointer value, gsize length)
{
	g_assert (sizeof (GP11Attribute) == sizeof (CK_ATTRIBUTE));
	memset (attr, 0, sizeof (GP11Attribute));
	attr->type = attr_type;
	attr->length = length;
	attr->value = value && length ? value : NULL;	
}

/**
 * gp11_attribute_init_boolean:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The boolean value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to boolean. This will result
 * in a CK_BBOOL attribute from the PKCS#11 specs.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/
void 
gp11_attribute_init_boolean (GP11Attribute *attr, gulong attr_type, 
                             gboolean value)
{
	CK_BBOOL bvalue = value ? CK_TRUE : CK_FALSE;
	gp11_attribute_init (attr, attr_type, &bvalue, sizeof (bvalue));
}

/**
 * gp11_attribute_init_date:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The date value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a date. This will result
 * in a CK_DATE attribute from the PKCS#11 specs.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/
void
gp11_attribute_init_date (GP11Attribute *attr, gulong attr_type, 
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

/**
 * gp11_attribute_init_ulong:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The ulong value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a unsigned long. This will result
 * in a CK_ULONG attribute from the PKCS#11 specs.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/
void
gp11_attribute_init_ulong (GP11Attribute *attr, gulong attr_type,
                           gulong value)
{
	CK_ULONG uvalue = value;
	gp11_attribute_init (attr, attr_type, &uvalue, sizeof (uvalue));
}

/**
 * gp11_attribute_init_string:
 * @attr: An uninitialized attribute.
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The null terminated string value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a string. This will result
 * in an attribute containing the text, but not the null terminator. 
 * The text in the attribute will be of the same encoding as you pass 
 * to this function.
 * 
 * When done with the attribute you should use gp11_attribute_clear()
 * to free the internal memory. 
 **/
void
gp11_attribute_init_string (GP11Attribute *attr, gulong attr_type, 
                            const gchar *value)
{
	gsize len = value ? strlen (value) : 0;
	gp11_attribute_init (attr, attr_type, (gpointer)value, len);
}

/**
 * gp11_attribute_new:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The raw value of the attribute.
 * @length: The length of the attribute. 
 * 
 * Create a new PKCS#11 attribute. The value will be copied 
 * into the new attribute. 
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new (gulong attr_type, gpointer value, gsize length)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init (attr, attr_type, value, length);
	return attr;
}

/**
 * gp11_attribute_new_invalid:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * 
 * Create a new PKCS#11 attribute as 'invalid' or 'not found' 
 * state. Specifically this sets the value length to (CK_ULONG)-1
 * as specified in the PKCS#11 specification.
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new_invalid (gulong attr_type)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_invalid (attr, attr_type);
	return attr;
}

/**
 * gp11_attribute_new_boolean:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The boolean value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to boolean. This will result
 * in a CK_BBOOL attribute from the PKCS#11 specs.
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new_boolean (gulong attr_type, gboolean value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_boolean (attr, attr_type, value);
	return attr;	
}

/**
 * gp11_attribute_new_date:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The date value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a date. This will result
 * in a CK_DATE attribute from the PKCS#11 specs.
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new_date (gulong attr_type, const GDate *value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_date (attr, attr_type, value);
	return attr;		
}

/**
 * gp11_attribute_new_ulong:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The ulong value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a unsigned long. This will result
 * in a CK_ULONG attribute from the PKCS#11 specs.
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new_ulong (gulong attr_type, gulong value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_ulong (attr, attr_type, value);
	return attr;			
}

/**
 * gp11_attribute_new_string:
 * @attr_type: The PKCS#11 attribute type to set on the attribute.
 * @value: The null terminated string value of the attribute.
 * 
 * Initialize a PKCS#11 attribute to a string. This will result
 * in an attribute containing the text, but not the null terminator. 
 * The text in the attribute will be of the same encoding as you pass 
 * to this function.
 * 
 * Return value: The new attribute. When done with the attribute use 
 * gp11_attribute_free() to free it. 
 **/
GP11Attribute*
gp11_attribute_new_string (gulong attr_type, const gchar *value)
{
	GP11Attribute *attr = g_slice_new0 (GP11Attribute);
	gp11_attribute_init_string (attr, attr_type, value);
	return attr;		
}

/**
 * gp11_attribute_is_invalid:
 * @attr: The attribute to check.
 * 
 * Check if the PKCS#11 attribute represents 'invalid' or 'not found' 
 * according to the PKCS#11 spec. That is, having length 
 * of (CK_ULONG)-1.
 * 
 * Return value: Whether the attribute represents invalid or not.
 */
gboolean
gp11_attribute_is_invalid (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, TRUE);
	return attr->length == (gulong)-1;
}

/**
 * gp11_attribute_get_boolean:
 * @attr: The attribute to retrieve value from.
 * 
 * Get the CK_BBOOL of a PKCS#11 attribute. No conversion
 * is performed. It is an error to pass an attribute to this
 * function unless you're know it's supposed to contain a 
 * boolean value.
 * 
 * Return value: The boolean value of the attribute.
 */
gboolean
gp11_attribute_get_boolean (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, FALSE);
	if (gp11_attribute_is_invalid (attr))
		return FALSE;
	g_return_val_if_fail (attr->length == sizeof (CK_BBOOL), FALSE);
	g_return_val_if_fail (attr->value, FALSE);
	return *((CK_BBOOL*)attr->value) == CK_TRUE ? TRUE : FALSE;
}

/**
 * gp11_attribute_get_ulong:
 * @attr: The attribute to retrieve value from.
 * 
 * Get the CK_ULONG value of a PKCS#11 attribute. No 
 * conversion is performed. It is an error to pass an attribute 
 * to this function unless you're know it's supposed to contain 
 * a value of the right type.
 * 
 * Return value: The ulong value of the attribute.
 */
gulong
gp11_attribute_get_ulong (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, FALSE);
	if (gp11_attribute_is_invalid (attr))
		return 0;
	g_return_val_if_fail (attr->length == sizeof (CK_ULONG), (gulong)-1);
	g_return_val_if_fail (attr->value, (gulong)-1);
	return *((CK_ULONG*)attr->value);
}

/**
 * gp11_attribute_get_string:
 * @attr: The attribute to retrieve value from.
 * 
 * Get the string value of a PKCS#11 attribute. No 
 * conversion is performed. It is an error to pass an attribute 
 * to this function unless you're know it's supposed to contain 
 * a value of the right type.
 * 
 * Return value: A null terminated string, to be freed with g_free(), 
 * or NULL if the value contained a NULL string.
 */
gchar*
gp11_attribute_get_string (GP11Attribute *attr)
{
	g_return_val_if_fail (attr, NULL);
	
	if (gp11_attribute_is_invalid (attr))
		return NULL;
	if (!attr->value)
		return NULL;

	return g_strndup ((gchar*)attr->value, attr->length);
}

/**
 * gp11_attribute_get_date:
 * @attr: The attribute to retrieve value from.
 * @value: The date value to fill in with the parsed date.
 * 
 * Get the CK_DATE of a PKCS#11 attribute. No 
 * conversion is performed. It is an error to pass an attribute 
 * to this function unless you're know it's supposed to contain 
 * a value of the right type.
 */
void
gp11_attribute_get_date (GP11Attribute *attr, GDate *value)
{
	guint year, month, day;
	gchar buffer[5];
	CK_DATE *date;
	gchar *end;
	
	g_return_if_fail (attr);
	
	if (gp11_attribute_is_invalid (attr)) {
		g_date_clear (value, 1);
		return;
	}

	g_return_if_fail (attr->length == sizeof (CK_DATE));
	g_return_if_fail (attr->value);
	date = (CK_DATE*)attr->value;
	
	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->year, 4);
	year = strtol (buffer, &end, 10);
	g_return_if_fail (end != buffer && !*end); 
	
	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->month, 2);
	month = strtol (buffer, &end, 10);
	g_return_if_fail (end != buffer && !*end); 

	memset (&buffer, 0, sizeof (buffer));
	memcpy (buffer, date->day, 2);
	day = strtol (buffer, &end, 10);
	g_return_if_fail (end != buffer && !*end); 
	
	g_date_set_dmy (value, day, month, year);	
}

/**
 * gp11_attribute_dup:
 * @attr: The attribute to duplicate.
 * 
 * Duplicate the PKCS#11 attribute. All value memory is 
 * also copied. 
 * 
 * Return value: The duplicated attribute. Use gp11_attribute_free()
 * to free it.
 */
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

/**
 * gp11_attribute_init_copy:
 * @dest: An uninitialized attribute.
 * @src: An attribute to copy.
 * 
 * Initialize a PKCS#11 attribute as a copy of another attribute. 
 * This copies the value memory as well.
 * 
 * When done with the copied attribute you should use 
 * gp11_attribute_clear() to free the internal memory. 
 **/ 
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

/**
 * gp11_attribute_clear:
 * @attr: Attribute to clear.
 * 
 * Clear allocated memory held by a statically allocated attribute.
 * These are usually initialized with gp11_attribute_init() or a 
 * similar function.
 **/
void
gp11_attribute_clear (GP11Attribute *attr)
{
	g_return_if_fail (attr);
	g_free (attr->value);
	memset (attr, 0, sizeof (GP11Attribute));
}

/**
 * gp11_attribute_free:
 * @attr: Attribute to free.
 * 
 * Free an attribute and its allocated memory. These is usually 
 * used with attributes that are allocated by gp11_attribute_new()
 * or a similar function.
 **/
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

/**
 * gp11_attributes_get_boxed_type:
 * 
 * Get the boxed type representing a GP11Attributes array.
 * 
 * Return value: The boxed type. 
 **/
GType
gp11_attributes_get_boxed_type (void)
{
	static GType type = 0;
	if (!type)
		type = g_boxed_type_register_static ("GP11Attributes", 
		                                     (GBoxedCopyFunc)gp11_attributes_ref,
		                                     (GBoxedFreeFunc)gp11_attributes_unref);
	return type;
}

/**
 * gp11_attributes_new:
 * 
 * Create a new GP11Attributes array.
 * 
 * Return value: The new attributes array. When done with the array 
 * release it with gp11_attributes_unref().
 **/
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
initialize_from_valist (gulong type, va_list va)
{
	GP11Attributes *attrs;
	gssize length;
	gpointer value;
	
	attrs = gp11_attributes_new ();
	
	/* No attributes */
	if (type == (gulong)-1)
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
		
		type = va_arg (va, gulong);
			
	} while (type != (gulong)-1);
		
	return attrs;
}

/**
 * gp11_attributes_newv:
 * 
 * Create a new GP11Attributes array.
 * 
 * The arguments must be triples of: attribute type, data type, value
 * 
 * Return value: The new attributes array. When done with the array 
 * release it with gp11_attributes_unref().
 **/
GP11Attributes*
gp11_attributes_newv (gulong first_type, ...)
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
	gulong type = va_arg (va, gulong);
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
_gp11_attributes_add_take (GP11Attributes *attrs, gulong attr_type,
                           gpointer value, gsize length)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	_gp11_attribute_init_take (added, attr_type, (gpointer)value, length);
}

void 
gp11_attributes_add_data (GP11Attributes *attrs, gulong attr_type,
                          gconstpointer value, gsize length)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init (added, attr_type, value, length);
}

void
gp11_attributes_add_invalid (GP11Attributes *attrs, gulong attr_type)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_invalid (added, attr_type);	
}

void
gp11_attributes_add_boolean (GP11Attributes *attrs, gulong attr_type, gboolean value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_boolean (added, attr_type, value);
}

void
gp11_attributes_add_string (GP11Attributes *attrs, gulong attr_type, const gchar *value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_string (added, attr_type, value);
}

void
gp11_attributes_add_date (GP11Attributes *attrs, gulong attr_type, const GDate *value)
{
	GP11Attribute *added;
	g_return_if_fail (attrs);
	g_return_if_fail (g_atomic_int_get (&attrs->immutable) == 0);
	added = attributes_push (attrs);
	gp11_attribute_init_date (added, attr_type, value);
}

void
gp11_attributes_add_ulong (GP11Attributes *attrs, gulong attr_type, gulong value)
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
gp11_attributes_find (GP11Attributes *attrs, gulong attr_type)
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
gp11_attributes_find_boolean (GP11Attributes *attrs, gulong attr_type, gboolean *value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr || gp11_attribute_is_invalid (attr))
		return FALSE;
	*value = gp11_attribute_get_boolean (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_ulong (GP11Attributes *attrs, gulong attr_type, gulong *value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr || gp11_attribute_is_invalid (attr))
		return FALSE;
	*value = gp11_attribute_get_ulong (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_string (GP11Attributes *attrs, gulong attr_type, gchar **value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr || gp11_attribute_is_invalid (attr))
		return FALSE;
	*value = gp11_attribute_get_string (attr);
	return TRUE;
}

gboolean
gp11_attributes_find_date (GP11Attributes *attrs, gulong attr_type, GDate *value)
{
	GP11Attribute *attr;
	g_return_val_if_fail (value, FALSE);

	attr = gp11_attributes_find (attrs, attr_type);
	if (!attr || gp11_attribute_is_invalid (attr))
		return FALSE;
	gp11_attribute_get_date (attr, value);
	return TRUE;
}

GP11Attributes*
gp11_attributes_ref (GP11Attributes *attrs)
{
	g_return_val_if_fail (attrs, NULL);
	g_atomic_int_inc (&attrs->refs);
	return attrs;
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
