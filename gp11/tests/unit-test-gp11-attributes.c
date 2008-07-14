
#include <check.h>

#include <glib.h>
#include <string.h>

#include "run-auto-test.h"
#include "gp11-test.h"

#define ATTR_TYPE 55
#define ATTR_DATA "TEST DATA"
#define N_ATTR_DATA 9

DEFINE_TEST(init_memory)
{
	GP11Attribute attr;
	
	fail_if (sizeof (attr) != sizeof (CK_ATTRIBUTE));
	
	gp11_attribute_init (&attr, ATTR_TYPE, ATTR_DATA, N_ATTR_DATA);
	fail_unless (attr.type == ATTR_TYPE);
	fail_unless (attr.length == N_ATTR_DATA);
	fail_unless (memcmp (attr.value, ATTR_DATA, attr.length) == 0);
	
	gp11_attribute_clear (&attr);
}

DEFINE_TEST(init_boolean)
{
	GP11Attribute attr;

	gp11_attribute_init_boolean (&attr, ATTR_TYPE, TRUE);
	fail_unless (attr.type == ATTR_TYPE);
	fail_unless (attr.length == sizeof (CK_BBOOL));
	fail_unless (*((CK_BBOOL*)attr.value) == CK_TRUE);

	gp11_attribute_clear (&attr);
}

DEFINE_TEST(init_date)
{
	GP11Attribute attr;
	CK_DATE ck_date;
	GDate *date;

	date = g_date_new_dmy(05, 06, 1960);
	memcpy (ck_date.year, "1960", 4);
	memcpy (ck_date.month, "06", 2);
	memcpy (ck_date.day, "05", 2);
	gp11_attribute_init_date (&attr, ATTR_TYPE, date);
	g_date_free (date);
	fail_unless (attr.type == ATTR_TYPE);
	fail_unless (attr.length == sizeof (CK_DATE));
	fail_unless (memcmp (attr.value, &ck_date, attr.length) == 0);
	
	gp11_attribute_clear (&attr);
}

DEFINE_TEST(init_ulong)
{
	GP11Attribute attr;
	
	gp11_attribute_init_ulong (&attr, ATTR_TYPE, 88);
	fail_unless (attr.type == ATTR_TYPE);
	fail_unless (attr.length == sizeof (CK_ULONG));
	fail_unless (*((CK_ULONG*)attr.value) == 88);

	gp11_attribute_clear (&attr);
}

DEFINE_TEST(init_string)
{
	GP11Attribute attr;
	
	gp11_attribute_init_string (&attr, ATTR_TYPE, "a test string");
	fail_unless (attr.type == ATTR_TYPE);
	fail_unless (attr.length == strlen ("a test string"));
	fail_unless (memcmp (attr.value, "a test string", attr.length) == 0);

	gp11_attribute_clear (&attr);
}
	
DEFINE_TEST(new_memory)
{
	GP11Attribute *attr;
	
	attr = gp11_attribute_new (ATTR_TYPE, ATTR_DATA, N_ATTR_DATA);
	fail_unless (attr->type == ATTR_TYPE);
	fail_unless (attr->length == N_ATTR_DATA);
	fail_unless (memcmp (attr->value, ATTR_DATA, attr->length) == 0);
	
	gp11_attribute_free (attr);
}

DEFINE_TEST(new_boolean)
{
	GP11Attribute *attr;

	attr = gp11_attribute_new_boolean (ATTR_TYPE, TRUE);
	fail_unless (attr->type == ATTR_TYPE);
	fail_unless (attr->length == sizeof (CK_BBOOL));
	fail_unless (*((CK_BBOOL*)attr->value) == CK_TRUE);

	gp11_attribute_free (attr);
}

DEFINE_TEST(new_date)
{
	GP11Attribute *attr;
	CK_DATE ck_date;
	GDate *date;

	date = g_date_new_dmy(05, 06, 1800);
	memcpy (ck_date.year, "1800", 4);
	memcpy (ck_date.month, "06", 2);
	memcpy (ck_date.day, "05", 2);
	attr = gp11_attribute_new_date (ATTR_TYPE, date);
	g_date_free (date);
	fail_unless (attr->type == ATTR_TYPE);
	fail_unless (attr->length == sizeof (CK_DATE));
	fail_unless (memcmp (attr->value, &ck_date, attr->length) == 0);
	
	gp11_attribute_free (attr);
}

DEFINE_TEST(new_ulong)
{
	GP11Attribute *attr;
	
	attr = gp11_attribute_new_ulong (ATTR_TYPE, 88);
	fail_unless (attr->type == ATTR_TYPE);
	fail_unless (attr->length == sizeof (CK_ULONG));
	fail_unless (*((CK_ULONG*)attr->value) == 88);

	gp11_attribute_free (attr);
}

DEFINE_TEST(new_string)
{
	GP11Attribute *attr;
	
	attr = gp11_attribute_new_string (ATTR_TYPE, "a test string");
	fail_unless (attr->type == ATTR_TYPE);
	fail_unless (attr->length == strlen ("a test string"));
	fail_unless (memcmp (attr->value, "a test string", attr->length) == 0);

	gp11_attribute_free (attr);
}

DEFINE_TEST(get_boolean)
{
	GP11Attribute *attr;

	attr = gp11_attribute_new_boolean (ATTR_TYPE, TRUE);
	fail_unless (gp11_attribute_get_boolean (attr) == TRUE);
	gp11_attribute_free (attr);
}

DEFINE_TEST(get_date)
{
	GP11Attribute *attr;
	CK_DATE ck_date;
	GDate *date, *date2;

	date = g_date_new_dmy(05, 06, 1800);
	memcpy (ck_date.year, "1800", 4);
	memcpy (ck_date.month, "06", 2);
	memcpy (ck_date.day, "05", 2);
	attr = gp11_attribute_new_date (ATTR_TYPE, date);
	date2 = gp11_attribute_get_date (attr);
	fail_unless (g_date_compare (date, date2) == 0);
	g_date_free (date);
	g_date_free (date2);
	gp11_attribute_free (attr);
}

DEFINE_TEST(get_ulong)
{
	GP11Attribute *attr;
	
	attr = gp11_attribute_new_ulong (ATTR_TYPE, 88);
	fail_unless (gp11_attribute_get_ulong (attr) == 88);
	gp11_attribute_free (attr);
}

DEFINE_TEST(get_string)
{
	GP11Attribute *attr;
	gchar *value;
	
	attr = gp11_attribute_new_string (ATTR_TYPE, "a test string");
	value = gp11_attribute_get_string (attr);
	fail_unless (strcmp ("a test string", value) == 0);
	g_free (value);
	gp11_attribute_free (attr);

	/* Should be able to store null strings */
	attr = gp11_attribute_new_string (ATTR_TYPE, NULL);
	value = gp11_attribute_get_string (attr);
	fail_unless (value == NULL);
	gp11_attribute_free (attr);
}

DEFINE_TEST(dup_attribute)
{
	GP11Attribute attr, *dup;

	gp11_attribute_init_ulong (&attr, ATTR_TYPE, 88);
	dup = gp11_attribute_dup (&attr);
	gp11_attribute_clear (&attr);
	fail_unless (gp11_attribute_get_ulong (dup) == 88);
	fail_unless (dup->type == ATTR_TYPE);
	gp11_attribute_free (dup);
	
	/* Should be able to dup null */
	dup = gp11_attribute_dup (NULL);
	fail_if (dup != NULL);
}

DEFINE_TEST(copy_attribute)
{
	GP11Attribute attr, copy;

	gp11_attribute_init_ulong (&attr, ATTR_TYPE, 88);
	gp11_attribute_init_copy (&copy, &attr);
	gp11_attribute_clear (&attr);
	fail_unless (gp11_attribute_get_ulong (&copy) == 88);
	fail_unless (copy.type == ATTR_TYPE);
	gp11_attribute_clear (&copy);
}

DEFINE_TEST(new_attributes)
{
	GP11Attributes *attrs;
	
	attrs = gp11_attributes_new ();
	fail_if (attrs == NULL);
	fail_unless (gp11_attributes_count (attrs) == 0);
	
	gp11_attributes_ref (attrs);
	gp11_attributes_unref (attrs);
	
	gp11_attributes_unref (attrs);
	
	/* Can unref NULL */
	gp11_attributes_unref (NULL);
}

static void
test_attributes_contents (GP11Attributes *attrs)
{
	GP11Attribute *attr;
	gchar *value;
	GDate *date, *check;
	
	fail_if (attrs == NULL);
	fail_unless (gp11_attributes_count (attrs) == 5);
	
	attr = gp11_attributes_at (attrs, 0);
	fail_unless (attr->type == 0);
	fail_unless (gp11_attribute_get_boolean (attr) == TRUE);
	
	attr = gp11_attributes_at (attrs, 1);
	fail_unless (attr->type == 101);
	fail_unless (gp11_attribute_get_ulong (attr) == 888);

	attr = gp11_attributes_at (attrs, 2);
	fail_unless (attr->type == 202);
	value = gp11_attribute_get_string (attr);
	fail_unless (strcmp (value, "string") == 0);
	g_free (value);

	attr = gp11_attributes_at (attrs, 3);
	fail_unless (attr->type == 303);
	check = g_date_new_dmy (11, 12, 2008);
	date = gp11_attribute_get_date (attr);
	fail_unless (g_date_compare (date, check) == 0);
	g_date_free (date);
	g_date_free (check);
	
	attr = gp11_attributes_at (attrs, 4);
	fail_unless (attr->type == 404);
	fail_unless (attr->length == N_ATTR_DATA);
	fail_unless (memcmp (attr->value, ATTR_DATA, N_ATTR_DATA) == 0);
}

DEFINE_TEST(newv_attributes)
{
	GDate *date = g_date_new_dmy (11, 12, 2008);
	GP11Attributes *attrs;
	attrs = gp11_attributes_newv (0, GP11_BOOLEAN, TRUE, 
	                              101, GP11_ULONG, 888,
	                              202, GP11_STRING, "string",
	                              303, GP11_DATE, date,
	                              404, N_ATTR_DATA, ATTR_DATA,
	                              -1);
	g_date_free (date);

	test_attributes_contents (attrs);
	gp11_attributes_unref (attrs);
	
	/* An empty one */
	attrs = gp11_attributes_newv (-1);
	gp11_attributes_unref (attrs);
}

static GP11Attributes*
help_attributes_valist (int dummy, ...)
{
	GP11Attributes *attrs;
	va_list va;
	
	va_start (va, dummy);
	attrs = gp11_attributes_new_valist (va);
	va_end (va);
	
	return attrs;
}

DEFINE_TEST(new_valist_attributes)
{
	GP11Attributes *attrs;
	GDate *date = g_date_new_dmy (11, 12, 2008);
	
	attrs = help_attributes_valist (232434243, /* Not used */
	                                0, GP11_BOOLEAN, TRUE, 
	                                101, GP11_ULONG, 888,
	                                202, GP11_STRING, "string",
	                                303, GP11_DATE, date,
	                                404, N_ATTR_DATA, ATTR_DATA,
	                                -1);
	
	g_date_free (date);
	test_attributes_contents (attrs);
	gp11_attributes_unref (attrs);	
}

DEFINE_ABORT(bad_length)
{
	GP11Attributes *attrs;
	
	/* We should catch this with a warning */
	attrs = gp11_attributes_newv (1, G_MAXSSIZE + 500U, GP11_ULONG, "invalid data",
	                              -1);
	
	gp11_attributes_unref (attrs);
}

DEFINE_TEST(add_data_attributes)
{
	GP11Attributes *attrs;
	GDate *date = g_date_new_dmy (11, 12, 2008);
	attrs = gp11_attributes_new ();
	gp11_attributes_add_boolean (attrs, 0, TRUE);
	gp11_attributes_add_ulong (attrs, 101, 888);
	gp11_attributes_add_string (attrs, 202, "string");
	gp11_attributes_add_date (attrs, 303, date);
	g_date_free (date);
	gp11_attributes_add_data (attrs, 404, ATTR_DATA, N_ATTR_DATA);
	test_attributes_contents (attrs);
	gp11_attributes_unref (attrs);
}

DEFINE_TEST(add_attributes)
{
	GP11Attributes *attrs;
	GP11Attribute attr;
	
	GDate *date = g_date_new_dmy (11, 12, 2008);
	attrs = gp11_attributes_new ();
	
	gp11_attribute_init_boolean (&attr, 0, TRUE);
	gp11_attributes_add (attrs, &attr);
	gp11_attribute_clear (&attr);
	
	gp11_attribute_init_ulong (&attr, 101, 888);
	gp11_attributes_add (attrs, &attr);
	gp11_attribute_clear (&attr);
	
	gp11_attribute_init_string (&attr, 202, "string");
	gp11_attributes_add (attrs, &attr);
	gp11_attribute_clear (&attr);

	gp11_attribute_init_date (&attr, 303, date);
	gp11_attributes_add (attrs, &attr);
	gp11_attribute_clear (&attr);
	g_date_free (date);
	
	gp11_attribute_init (&attr, 404, ATTR_DATA, N_ATTR_DATA);
	gp11_attributes_add (attrs, &attr);
	gp11_attribute_clear (&attr);
	
	test_attributes_contents (attrs);
	gp11_attributes_unref (attrs);
}


DEFINE_TEST(find_attributes)
{
	GP11Attribute *attr;
	GDate *check, *date = g_date_new_dmy (13, 12, 2008);
	gboolean bvalue, ret;
	gulong uvalue;
	gchar *svalue;
	
	GP11Attributes *attrs;
	attrs = gp11_attributes_newv (0, GP11_BOOLEAN, TRUE, 
	                              101, GP11_ULONG, 888,
	                              202, GP11_STRING, "string",
	                              303, GP11_DATE, date,
	                              404, N_ATTR_DATA, ATTR_DATA,
	                              -1);

	attr = gp11_attributes_find (attrs, 404);
	fail_if (attr == NULL);
	fail_unless (attr->length == N_ATTR_DATA);
	fail_unless (memcmp (attr->value, ATTR_DATA, N_ATTR_DATA) == 0);
	
	ret = gp11_attributes_find_boolean (attrs, 0, &bvalue);
	fail_unless (ret == TRUE);
	fail_unless (bvalue == TRUE);
	
	ret = gp11_attributes_find_ulong (attrs, 101, &uvalue);
	fail_unless (ret == TRUE);
	fail_unless (uvalue == 888);

	ret = gp11_attributes_find_string (attrs, 202, &svalue);
	fail_unless (ret == TRUE);
	fail_if (svalue == NULL);
	fail_unless (strcmp (svalue, "string") == 0);
	g_free (svalue);
	
	ret = gp11_attributes_find_date (attrs, 303, &check);
	fail_unless (ret == TRUE);
	fail_if (check == NULL);
	fail_unless (g_date_compare (date, check) == 0);
	g_date_free (check);
	
	gp11_attributes_unref (attrs);
}
