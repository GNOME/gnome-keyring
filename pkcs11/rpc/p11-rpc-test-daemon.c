/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-dispatch.h - A sample daemon.

   Copyright (C) 2008, Stef Walter

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

#include "pkcs11/pkcs11.h"

#include "p11-rpc.h"

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <pthread.h>

#define SOCKET_PREFIX "/tmp/p11-rpc-daemon-sock"

static CK_C_INITIALIZE_ARGS p11_init_args = {
	NULL,
        NULL,
        NULL,
        NULL,
        CKF_OS_LOCKING_OK,
        NULL
};

static int is_running = 1;

void
p11_rpc_log (const char *line)
{
	fprintf (stderr, "%s\n", line);
}

void*
p11_rpc_create_thread (void (*thread_func) (void*), void* thread_arg)
{
	pthread_t *thread;
	int error;
	
	thread = calloc (1, sizeof (pthread_t));
	if (!thread)
		errx (1, "out of memory");
	error = pthread_create (thread, NULL, (void*)thread_func, thread_arg);
	if (error != 0)
		errx (1, "couldn't start thread: %s", strerror (error));
	
	return thread;
}

void
p11_rpc_join_thread (void *th)
{
	pthread_t *thread = th;
	void *value;
	int error;
	
	error = pthread_join (*thread, &value);
	if (error != 0)
		errx (1, "couldn't join thread: %s", strerror (error));
	
	free (thread);
}

int
p11_rpc_read_credentials (int socket)
{
	/* Do nothing */
	return 1;
}

static int 
usage (void)
{
	fprintf (stderr, "usage: p11-rpc-daemon pkcs11-module");
	exit (2);
}

int
main (int argc, char *argv[])
{
	CK_C_GetFunctionList func_get_list;
	CK_FUNCTION_LIST_PTR funcs;
	void *module;
	fd_set read_fds;
	int sock, ret;
	CK_RV rv;
	
	/* The module to load is the argument */
	if (argc != 2)
		usage();

	/* Load the library */
	module = dlopen(argv[1], RTLD_NOW);
	if(!module) 
		errx (1, "couldn't open library: %s: %s", argv[1], dlerror());

	/* Lookup the appropriate function in library */
	func_get_list = (CK_C_GetFunctionList)dlsym (module, "C_GetFunctionList");
	if (!func_get_list)
		errx (1, "couldn't find C_GetFunctionList in library: %s: %s", 
		      argv[1], dlerror());
	
	/* Get the function list */
	rv = (func_get_list) (&funcs);
	if (rv != CKR_OK || !funcs)
		errx (1, "couldn't get function list from C_GetFunctionList in libary: %s: 0x%08x", 
		      argv[1], (int)rv);
	
	if (!p11_rpc_dispatch_init (SOCKET_PREFIX, funcs, &p11_init_args))
		exit (1);
	
	sock = p11_rpc_dispatch_fd ();
	
	is_running = 1;
	while (is_running) {
		FD_SET (sock, &read_fds);
		ret = select (sock, &read_fds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			err (1, "error watching socket");
		}
		
		if (FD_ISSET (sock, &read_fds))
			p11_rpc_dispatch_accept ();
	}
	
	p11_rpc_dispatch_uninit ();
	dlclose(module);

	return 0;
}