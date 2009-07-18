/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-attributes.c: Test attributes functionality

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

#include "run-auto-test.h"

#include "gck/gck-attributes.h"

DEFINE_TEST(attribute_consume)
{
	CK_ATTRIBUTE attr;
	attr.type = CKA_LABEL;
	
	gck_attribute_consume (&attr);
	g_assert (attr.type == (gulong)-1);
}

DEFINE_TEST(attribute_set_time)
{
	CK_ATTRIBUTE attr;
	gchar buf[30];
	CK_RV rv;
	
	attr.ulValueLen = 30;
	attr.pValue = buf;
	rv = gck_attribute_set_time (&attr, 1247930171);
	g_assert (rv == CKR_OK);
	g_assert (attr.ulValueLen == 16);
	g_assert (memcmp (attr.pValue, "2009071815161100", 16) == 0);
}

DEFINE_TEST(attribute_set_time_empty)
{
	CK_ATTRIBUTE attr;
	gchar buf[30];
	CK_RV rv;
	
	attr.ulValueLen = 30;
	attr.pValue = buf;
	rv = gck_attribute_set_time (&attr, -1);
	g_assert (rv == CKR_OK);
	g_assert (attr.ulValueLen == 0);
}

DEFINE_TEST(attribute_set_time_length)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;
	
	attr.pValue = NULL;
	attr.ulValueLen = 0;
	rv = gck_attribute_set_time (&attr, 1247930171);
	g_assert (rv == CKR_OK);
	g_assert (attr.ulValueLen == 16);
	g_assert (attr.pValue == NULL);
}

DEFINE_TEST(attribute_get_time)
{
	CK_ATTRIBUTE attr;
	glong when;
	CK_RV rv;
	
	attr.ulValueLen = 16;
	attr.pValue = "2009071815161100";
	rv = gck_attribute_get_time (&attr, &when);
	g_assert (rv == CKR_OK);
	g_assert (when == 1247930171);
}

DEFINE_TEST(attribute_get_time_empty)
{
	CK_ATTRIBUTE attr;
	glong when;
	CK_RV rv;
	
	attr.ulValueLen = 0;
	attr.pValue = "";
	rv = gck_attribute_get_time (&attr, &when);
	g_assert (rv == CKR_OK);
	g_assert (when == -1);
}

DEFINE_TEST(attribute_get_time_invalid)
{
	CK_ATTRIBUTE attr;
	glong when;
	CK_RV rv;
	
	attr.ulValueLen = 16;
	attr.pValue = "aaaaaaaaaaaaaaaa";
	rv = gck_attribute_get_time (&attr, &when);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}

DEFINE_TEST(attribute_get_time_invalid_length)
{
	CK_ATTRIBUTE attr;
	glong when;
	CK_RV rv;
	
	attr.ulValueLen = 8;
	attr.pValue = "2009071815161100";
	rv = gck_attribute_get_time (&attr, &when);
	g_assert (rv == CKR_ATTRIBUTE_VALUE_INVALID);
}
