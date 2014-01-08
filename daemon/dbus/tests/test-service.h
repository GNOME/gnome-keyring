/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-service.c: Common service code

   Copyright (C) 2013 Red Hat Inc

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stefw@gnome.org>
*/

#ifndef TEST_COMMON_H__
#define TEST_COMMON_H__

#include <glib.h>
#include <gio/gio.h>

typedef struct {
	GDBusConnection *connection;
	gchar *bus_name;
	const gchar *mock_prompter;
	GPid pid;
	gboolean available;
	gchar *session;
	guint watch_id;
	gchar *directory;
} TestService;

void         test_service_setup           (TestService *test);

void         test_service_teardown        (TestService *test);

GVariant *   test_service_build_secret    (TestService *test,
                                           const gchar *value);

#endif /* TEST_COMMON_H__ */
