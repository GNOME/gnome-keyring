/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* testing.h: Declarations for common functions called from gtest unit tests

   Copyright (C) 2008 Stefan Walter
   Copyright (C) 2010 Collabora Ltd

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

#ifndef TESTING_H_
#define TESTING_H_

/* Don't use this header while preparing tests */
#ifndef TESTING_PREPARING

#include "config.h"

#include <glib.h>
#include <glib-object.h>
#include <glib/gstdio.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

gboolean         testing_wait_until               (gint timeout);

void             testing_wait_stop                (void);

const gchar*     testing_data_directory           (void);

const gchar*     testing_scratch_directory        (void);

guchar*          testing_data_read                (const gchar *basename,
                                                   gsize *n_data);

void             testing_data_to_scratch          (const gchar *basename,
                                                   const gchar *newname);

gchar*           testing_scratch_filename         (const gchar *basename);

void             testing_scratch_empty            (const gchar *basename);

void             testing_scratch_touch            (const gchar *basename,
                                                   gint future);

void             testing_scratch_remove           (const gchar *basename);

void             testing_scratch_remove_all       (void);

gchar*           testing_data_filename            (const gchar *basename);

#ifdef CRYPTOKI_VERSION_MAJOR

void             testing_test_p11_module          (CK_FUNCTION_LIST_PTR module,
                                                   const gchar *config);

#endif

typedef void     (*TestingExternalFunc)           (void);

void             testing_external_run             (const gchar *name,
                                                   TestingExternalFunc func,
                                                   int *result);

const gchar*     testing_external_name            (void);

void             testing_external_fail            (void);

#define TESTING_SETUP(x) \
	void testing__setup__##x(int *__unused, gconstpointer __data)
#define TESTING_TEARDOWN(x) \
	void testing__teardown__##x(int *__unused, gconstpointer __data)
#define TESTING_TEST(x) \
	void testing__test__##x(int *__unused, gconstpointer __data)
#define TESTING_START(x) \
	void testing__start__##x(void)
#define TESTING_STOP(x) \
	void testing__stop__##x(void)
#define TESTING_EXTERNAL(x) \
	void testing__external__##x(void)

#ifndef g_assert_cmpsize
#define g_assert_cmpsize(a, o, b) \
	g_assert_cmpuint ((guint)(a), o, (guint)(b))
#endif

#endif /* TESTING_PREPARING */

#endif /* TESTING_H_ */
