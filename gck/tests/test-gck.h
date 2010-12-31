/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-uri.c - the GObject PKCS#11 wrapper library

   Copyright (C) 2011, Collabora Ltd.

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#ifndef TEST_GCK_H_
#define TEST_GCK_H_

#include "gck.h"
#include "gck-mock.h"
#include "gck-test.h"

#define FAIL_RES(res, e) do { \
	g_assert ((res) ? FALSE : TRUE); \
	g_assert ((e) && (e)->message && "error should be set"); \
	g_clear_error (&e); \
	} while (0)

#define SUCCESS_RES(res, err) do { \
	if (!(res)) g_printerr ("error: %s\n", err && err->message ? err->message : ""); \
	g_assert ((res) ? TRUE : FALSE && "should have succeeded"); \
	g_clear_error (&err); \
	} while(0)

#endif /* TEST_GCK_H_ */
