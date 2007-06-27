/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-other.c: Test miscellaneous functionality

   Copyright (C) 2007 Stefan Walter

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "run-library-test.h"
#include "library/gnome-keyring.h"

/* 
 * Each test looks like (on one line):
 *     void unit_test_xxxxx (CuTest* cu)
 * 
 * Each setup looks like (on one line):
 *     void unit_setup_xxxxx (void);
 * 
 * Each teardown looks like (on one line):
 *     void unit_teardown_xxxxx (void);
 * 
 * Tests be run in the order specified here.
 */
 
void unit_test_set_display (CuTest* cu)
{
	GnomeKeyringResult res;
	
	/* Shouldn't work */
	res = gnome_keyring_daemon_set_display_sync ("WOOF");
	CuAssertIntEquals(cu, GNOME_KEYRING_RESULT_DENIED, res);	
}

void unit_test_result_string (CuTest* cu)
{
	const gchar *msg;
	
	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_OK);	
	CuAssert (cu, "should return an empty string", msg && !msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_CANCELLED); 	
	CuAssert (cu, "should return an empty string", msg && !msg[0]);
	
	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_DENIED);
	CuAssert (cu, "should return a valid message", msg && msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_NO_KEYRING_DAEMON); 	
	CuAssert (cu, "should return a valid message", msg && msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_NO_SUCH_KEYRING);
	CuAssert (cu, "should return a valid message", msg && msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_BAD_ARGUMENTS); 	
	CuAssert (cu, "should return a valid message", msg && msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_IO_ERROR);
	CuAssert (cu, "should return a valid message", msg && msg[0]);

	msg = gnome_keyring_result_to_message (GNOME_KEYRING_RESULT_KEYRING_ALREADY_EXISTS); 	
	CuAssert (cu, "should return a valid message", msg && msg[0]);
}
