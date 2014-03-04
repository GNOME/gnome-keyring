/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* mock-module.h: A test PKCS#11 module implementation

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

#ifndef MOCK_MODULE_H_
#define MOCK_MODULE_H_

#include <glib.h>

#include "gkm/gkm-types.h"

#include "pkcs11.h"

void                   mock_module_leave                    (void);

void                   mock_module_enter                    (void);

GkmModule*             mock_module_initialize_and_enter     (void);

void                   mock_module_leave_and_finalize       (void);

GkmSession*            mock_module_open_session             (gboolean writable);

GkmObject*             mock_module_object_new               (GkmSession *session);

#endif /* MOCK_MODULE_H_ */
