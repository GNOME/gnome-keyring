/*
   Copyright (C) 2014 Red Hat Inc

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

#ifndef GKD_TEST_H_
#define GKD_TEST_H_

#include <glib.h>

gchar **    gkd_test_launch_daemon     (const gchar *directory,
                                        const gchar **argv,
                                        GPid *pid,
                                        ...) G_GNUC_NULL_TERMINATED;

#endif /* GKD_TEST_H_ */
