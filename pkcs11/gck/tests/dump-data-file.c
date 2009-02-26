/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* dump-data-file.c: Dump a gck data file

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

#include "gck-crypto.h"
#include "gck-data-file.h"

#include "egg/egg-secure-memory.h"

#include <glib.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void egg_memory_lock (void) 
	{ }
void egg_memory_unlock (void) 
	{ }
void* egg_memory_fallback (void *p, size_t sz) 
	{ return g_realloc (p, sz); }

static void G_GNUC_NORETURN
failure (const gchar* message, ...)
{
	va_list va;
	va_start (va, message);
	vfprintf (stderr, message, va);
	fputc ('\n', stderr);
	va_end (va);
	exit (1);
}

int 
main(int argc, char* argv[])
{
	const gchar *password;
	GckDataResult res;
	GckDataFile *file;
	GckLogin *login;
	int fd;
	
	g_type_init ();
	gck_crypto_initialize ();
	
	if (argc != 2) 
		failure ("usage: dump-data-file filename");
	
	fd = open (argv[1], O_RDONLY, 0);
	if (fd == -1)
		failure ("dump-data-file: couldn't open file: %s: %s", argv[1], g_strerror (errno));
	
	password = getpass ("Password: ");
	login = gck_login_new ((guchar*)password, strlen (password));
	
	file = gck_data_file_new ();
	res = gck_data_file_read_fd (file, fd, login);
	g_object_unref (login);

	switch(res) {
	case GCK_DATA_FAILURE:
		failure ("dump-data-file: failed to read file: %s", argv[1]);
	case GCK_DATA_LOCKED:
		failure ("dump-data-file: invalid password for file: %s", argv[1]);
	case GCK_DATA_UNRECOGNIZED:
		failure ("dump-data-file: unparseable file format: %s", argv[1]);
	case GCK_DATA_SUCCESS:
		break;
	default:
		g_assert_not_reached ();
	}
	
	gck_data_file_dump (file);
	g_object_unref (file);
	
	return 0;
}
