/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-timer.c: Test thread timer functionality

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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "mock-module.h"

#include "gkm/gkm-timer.h"

#include "egg/egg-testing.h"

#include <glib-object.h>

typedef struct {
	GkmModule *module;
} Test;

static void
setup (Test* test, gconstpointer unused)
{
	test->module = mock_module_initialize_and_enter ();
}

static void
teardown (Test* test, gconstpointer unused)
{
	mock_module_leave_and_finalize ();
}

static void
test_extra_initialize (Test* test, gconstpointer unused)
{
	gkm_timer_initialize ();
	gkm_timer_shutdown ();
}

static void
timer_callback (GkmTimer *timer, gpointer user_data)
{
	GkmTimer **value = user_data;
	g_assert (timer);
	g_assert (timer == *value);
	*value = NULL;
}

static void
test_simple (Test* test, gconstpointer unused)
{
	GkmTimer *timer;

	timer = gkm_timer_start (test->module, 2, timer_callback, &timer);

	mock_module_leave ();
	egg_test_wait_until (2200);
	mock_module_enter ();

	g_assert (timer == NULL);
}

static void
test_cancel (Test* test, gconstpointer unused)
{
	GkmTimer *timer;

	timer = gkm_timer_start (test->module, 2, timer_callback, &timer);

	mock_module_leave ();
	egg_test_wait_until (50);
	mock_module_enter ();

	gkm_timer_cancel (timer);

	mock_module_leave ();
	egg_test_wait_until (3000);
	mock_module_enter ();

	/* The callback should not have been called */
	g_assert (timer != NULL);
}

static void
test_immediate (Test* test, gconstpointer unused)
{
	GkmTimer *timer;

	/* Setup timer in the past, should execute as soon as possible */
	timer = gkm_timer_start (test->module, -5, timer_callback, &timer);

	/* Should not be called immediately */
	g_assert (timer != NULL);

	mock_module_leave ();
	egg_test_wait_until (50);
	mock_module_enter ();

	/* Should have been called now */
	g_assert (timer == NULL);
}

static GkmTimer *timer_last = NULL;
static gint timer_check = 0;

static void
multiple_callback (GkmTimer *timer, gpointer user_data)
{
	gint value = GPOINTER_TO_INT (user_data);
	g_assert (timer);
	g_assert (timer != timer_last);
	g_assert (value == timer_check);
	timer_last = timer;
	timer_check += 1;
}

static void
test_multiple (Test* test, gconstpointer unused)
{
	timer_check = 0;

	/* Multiple timers, add out of order, should be called in order */
	gkm_timer_start (test->module, 1, multiple_callback, GINT_TO_POINTER (1));
	gkm_timer_start (test->module, 3, multiple_callback, GINT_TO_POINTER (3));
	gkm_timer_start (test->module, 2, multiple_callback, GINT_TO_POINTER (2));
	gkm_timer_start (test->module, 0, multiple_callback, GINT_TO_POINTER (0));

	mock_module_leave ();
	egg_test_wait_until (3500);
	mock_module_enter ();

	g_assert (timer_check == 4);
}

static void
test_outstanding (Test* test, gconstpointer unused)
{
	/* A timer that can't be called */
	gkm_timer_start (test->module, 5, timer_callback, NULL);
	gkm_timer_start (test->module, 10, timer_callback, NULL);
	gkm_timer_start (test->module, 1, timer_callback, NULL);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	egg_tests_set_fatal_timeout (300);
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/gkm/timer/extra_initialize", Test, NULL, setup, test_extra_initialize, teardown);
	g_test_add ("/gkm/timer/simple", Test, NULL, setup, test_simple, teardown);
	g_test_add ("/gkm/timer/cancel", Test, NULL, setup, test_cancel, teardown);
	g_test_add ("/gkm/timer/immediate", Test, NULL, setup, test_immediate, teardown);
	g_test_add ("/gkm/timer/multiple", Test, NULL, setup, test_multiple, teardown);
	g_test_add ("/gkm/timer/outstanding", Test, NULL, setup, test_outstanding, teardown);

	return egg_tests_run_in_thread_with_loop ();
}
