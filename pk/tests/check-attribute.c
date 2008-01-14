#ifndef CHECKATTRIBUTE_H_
#define CHECKATTRIBUTE_H_

#include "pk/gkr-pk-util.h"

static void
check_attribute (CuTest *cu, GkrPkObject *obj, CK_ATTRIBUTE_TYPE type, 
                 const char* name, gpointer value, gsize len)
{
	CK_ATTRIBUTE attr;
	CK_RV ret;
	
	memset (&attr, 0, sizeof (attr));
	attr.type = type;
	
	ret = gkr_pk_object_get_attribute (obj, &attr);
	CuAssert (cu, name, ret == CKR_OK);
	CuAssert (cu, name, attr.type == type);

	CuAssert (cu, name, attr.ulValueLen = len);
	if (len >= 0)
		CuAssert (cu, name, memcmp (attr.pValue, value, len) == 0);
}

#define CHECK_BOOL_ATTRIBUTE(cu, obj, type, value) { \
	CK_BBOOL v = value;  \
	check_attribute (cu, GKR_PK_OBJECT (obj), type, #type, &v, sizeof (CK_BBOOL)); \
}

#define CHECK_ULONG_ATTRIBUTE(cu, obj, type, value) { \
	CK_ULONG v = value;  \
	check_attribute (cu, GKR_PK_OBJECT (obj), type, #type, &v, sizeof (CK_ULONG)); \
}

#define CHECK_BYTE_ATTRIBUTE(cu, obj, type, val, length) \
	check_attribute (cu, GKR_PK_OBJECT (obj), type, #type, val, length)

#define CHECK_DATE_ATTRIBUTE(cu, obj, type, str) { \
	CK_ATTRIBUTE test = { 0, NULL, 0 }; \
	struct tm tm; \
	time_t time; \
	GDate *date = g_date_new (); \
	g_date_set_parse (date, str); \
	g_date_to_struct_tm (date, &tm); \
	time = timegm (&tm); \
	g_date_free (date); \
	gkr_pk_attribute_set_date (&test, time); \
	check_attribute (cu, GKR_PK_OBJECT (obj), type, #type, test.pValue, test.ulValueLen); \
	gkr_pk_attribute_clear (&test); \
}

#endif /*CHECKATTRIBUTE_H_*/
