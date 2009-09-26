/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-secret-collection.c: Test the collection keyring

   Copyright (C) 2009 Stefan Walter

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

#include "run-auto-test.h"
#include "test-secret-module.h"

#include "gck-secret-collection.h"
#include "gck-secret-fields.h"
#include "gck-secret-item.h"
#include "gck-secret-search.h"

#include "gck/gck-session.h"
#include "gck/gck-transaction.h"

#include "pkcs11/pkcs11i.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static GckModule *module = NULL;
static GckSession *session = NULL;
static GckFactory factory = NULL;
static GckSecretCollection *collection = NULL;
static GckSecretItem *item = NULL;

DEFINE_SETUP(secret_search)
{
	GHashTable *fields;

	module = test_secret_module_initialize_and_enter ();
	session = test_secret_module_open_session (TRUE);
	factory = GCK_FACTORY_SECRET_SEARCH->factory;
	g_assert (factory);

	collection = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                           "module", module,
	                           "manager", gck_session_get_manager (session),
	                           "identifier", "test-collection",
	                           NULL);

	/* Create an item */
	item = gck_secret_collection_create_item (collection, "test-item");
	fields = gck_secret_fields_new ();
	gck_secret_fields_add (fields, "name1", "value1");
	gck_secret_fields_add (fields, "name2", "value2");
	gck_secret_item_set_fields (item, fields);
	g_hash_table_unref (fields);

	gck_object_expose (GCK_OBJECT (collection), TRUE);
}

DEFINE_TEARDOWN(secret_search)
{
	g_object_unref (collection);

	test_secret_module_leave_and_finalize ();
	module = NULL;
	session = NULL;
}

DEFINE_TEST(create_search_incomplete)
{
	CK_ATTRIBUTE attrs[1];
	GckObject *object = NULL;
	CK_RV rv; 

	rv = gck_session_create_object_for_factory (session, factory, attrs, 0, &object);
	g_assert (rv == CKR_TEMPLATE_INCOMPLETE);
	g_assert (object == NULL);
}

DEFINE_TEST(create_search_bad_fields)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "bad-value", 9 },
	};

	GckObject *object = NULL;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 1, &object);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
	g_assert (object == NULL);
}

DEFINE_TEST(create_search)
{
	CK_ATTRIBUTE attrs[] = { 
	        { CKA_G_FIELDS, "test\0value\0two\0value2", 22 },
	};

	GckSecretCollection *collection;
	GckObject *object = NULL;
	GHashTable *fields;
	gpointer vdata;
	gulong vulong;
	gboolean vbool;
	gsize vsize;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 1, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	if (!gck_object_get_attribute_ulong (object, session, CKA_CLASS, &vulong))
		g_assert_not_reached ();
	g_assert (rv == CKR_OK);
	g_assert (vulong == CKO_G_SEARCH);

	if (!gck_object_get_attribute_boolean (object, session, CKA_MODIFIABLE, &vbool))
		g_assert_not_reached ();
	g_assert (rv == CKR_OK);
	g_assert (vbool == CK_TRUE);

	vdata = gck_object_get_attribute_data (object, session, CKA_G_FIELDS, &vsize);
	g_assert (vdata);
	g_assert (vsize == attrs[0].ulValueLen);
	g_free (vdata);

	vdata = gck_object_get_attribute_data (object, session, CKA_G_COLLECTION, &vsize);
	g_assert (vdata);
	g_assert (vsize == 0);
	g_free (vdata);

	/* No objects matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize == 0);
	g_free (vdata);

	/* Get the fields object and check */
	fields = gck_secret_search_get_fields (GCK_SECRET_SEARCH (object));
	g_assert (fields);
	g_assert_cmpstr (gck_secret_fields_get (fields, "test"), ==, "value");

	/* No collection */
	collection = gck_secret_search_get_collection (GCK_SECRET_SEARCH (object));
	g_assert (collection == NULL);
}

DEFINE_TEST(create_search_and_match)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "name1\0value1\0name2\0value2", 26 },
	};

	GckObject *object = NULL;
	gpointer vdata;
	gsize vsize;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 1, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	/* One object matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize == sizeof (CK_OBJECT_HANDLE));
	g_assert (*((CK_OBJECT_HANDLE_PTR)vdata) == gck_object_get_handle (GCK_OBJECT (item)));
	g_free (vdata);
}

DEFINE_TEST(create_search_and_change_to_match)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "name1\0value1", 13 },
	};

	GckObject *object = NULL;
	GHashTable *fields;
	gpointer vdata;
	gsize vsize;
	CK_RV rv;

	/* Make it not match */
	fields = gck_secret_fields_new ();
	gck_secret_item_set_fields (item, fields);
	g_hash_table_unref (fields);

	rv = gck_session_create_object_for_factory (session, factory, attrs, 1, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	/* Nothing matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vsize == 0);
	g_free (vdata);

	/* Make it match */
	fields = gck_secret_fields_new ();
	gck_secret_fields_add (fields, "name1", "value1");
	gck_secret_fields_add (fields, "name2", "value2");
	gck_secret_item_set_fields (item, fields);
	g_hash_table_unref (fields);

	/* One object matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize == sizeof (CK_OBJECT_HANDLE));
	g_assert (*((CK_OBJECT_HANDLE_PTR)vdata) == gck_object_get_handle (GCK_OBJECT (item)));
	g_free (vdata);
}

DEFINE_TEST(create_search_and_change_to_not_match)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "name1\0value1", 13 },
	};

	GckObject *object = NULL;
	GHashTable *fields;
	gpointer vdata;
	gsize vsize;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 1, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	/* One object matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize == sizeof (CK_OBJECT_HANDLE));
	g_assert (*((CK_OBJECT_HANDLE_PTR)vdata) == gck_object_get_handle (GCK_OBJECT (item)));
	g_free (vdata);

	/* Make it not match */
	fields = gck_secret_fields_new ();
	gck_secret_item_set_fields (item, fields);
	g_hash_table_unref (fields);

	/* Nothing matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vsize == 0);
	g_free (vdata);
}

DEFINE_TEST(create_search_for_bad_collection)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "name1\0value1", 13 },
	        { CKA_G_COLLECTION, "bad-collection", 14 },
	};

	GckObject *object = NULL;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 2, &object);
	g_assert (rv == CKR_TEMPLATE_INCONSISTENT);
}

DEFINE_TEST(create_search_for_collection)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "name1\0value1", 13 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	GckObject *object = NULL;
	gpointer vdata;
	gsize vsize;
	CK_RV rv;

	rv = gck_session_create_object_for_factory (session, factory, attrs, 2, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	/* Should have the collection set properly */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_COLLECTION , &vsize);
	g_assert (vdata);
	g_assert (vsize == 15);
	g_assert (memcmp (vdata, "test-collection", 15) == 0);
	g_free (vdata);

	/* One object matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vdata);
	g_assert (vsize == sizeof (CK_OBJECT_HANDLE));
	g_assert (*((CK_OBJECT_HANDLE_PTR)vdata) == gck_object_get_handle (GCK_OBJECT (item)));
	g_free (vdata);
}

DEFINE_TEST(create_search_for_collection_no_match)
{
	CK_ATTRIBUTE attrs[] = {
	        { CKA_G_FIELDS, "test\0value", 11 },
	        { CKA_G_COLLECTION, "test-collection", 15 },
	};

	GckObject *object = NULL;
	GckSecretCollection *ocoll;
	GckSecretItem *oitem;
	GHashTable *fields;
	gpointer vdata;
	gsize vsize;
	CK_RV rv;

	ocoll = g_object_new (GCK_TYPE_SECRET_COLLECTION,
	                      "module", module,
	                      "manager", gck_session_get_manager (session),
	                      "identifier", "other-collection",
	                      NULL);
	oitem = gck_secret_collection_create_item (ocoll, "other-item");
	gck_object_expose (GCK_OBJECT (ocoll), TRUE);

	/* Make it match, but remember, wrong collection*/
	fields = gck_secret_fields_new ();
	gck_secret_fields_add (fields, "test", "value");
	gck_secret_item_set_fields (oitem, fields);
	g_hash_table_unref (fields);

	rv = gck_session_create_object_for_factory (session, factory, attrs, 2, &object);
	g_assert (rv == CKR_OK);
	g_assert (object != NULL);
	g_assert (GCK_IS_SECRET_SEARCH (object));

	/* No objects matched */
	vdata = gck_object_get_attribute_data (object, session, CKA_G_MATCHED, &vsize);
	g_assert (vsize == 0);
	g_free (vdata);

	g_object_unref (ocoll);
}
