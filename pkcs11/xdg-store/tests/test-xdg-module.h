/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-xdg-module.h: A test PKCS#11 module implementation

   Copyright (C) 2010 Stefan Walter

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

#ifndef TEST_XDG_MODULE_H_
#define TEST_XDG_MODULE_H_

#include <glib.h>

#include "gkm/gkm-test.h"
#include "gkm/gkm-types.h"

#include "pkcs11.h"
#include "test-suite.h"

void                   test_xdg_module_leave                    (void);

void                   test_xdg_module_enter                    (void);

GkmModule*             test_xdg_module_initialize_and_enter     (void);

void                   test_xdg_module_leave_and_finalize       (void);

GkmSession*            test_xdg_module_open_session             (gboolean writable);

#endif /* TEST_XDG_MODULE_H_ */
