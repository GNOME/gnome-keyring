/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-module.h: A test PKCS#11 module implementation

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

#ifndef TESTMODULE_H_
#define TESTMODULE_H_

#include <glib.h>

#include "gck-types.h"

#include "pkcs11.h"

void                   test_module_leave                    (void);

void                   test_module_enter                    (void);

GckModule*             test_module_initialize_and_enter     (void);

void                   test_module_leave_and_finalize       (void);

GckSession*            test_module_open_session             (gboolean writable);

GckObject*             test_module_object_new               (GckSession *session);

#endif /* TESTMODULE_H_ */
