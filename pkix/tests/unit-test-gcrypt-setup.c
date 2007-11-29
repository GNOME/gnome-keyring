/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-gcrypt-setup.c: Setup gcrypt library

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

#include "config.h"

#include "run-auto-test.h"

#include "common/gkr-crypto.h"

#include <gcrypt.h>

#include <glib.h>

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

void unit_setup_gcrypt (void)
{
	gkr_crypto_setup ();
}
