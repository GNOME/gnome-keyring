/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* unit-test-pam-setup.c: Setup for PAM tests

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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "run-prompt-test.h"

#include <security/pam_appl.h>

/* Used directly by the other tests */
pam_handle_t *test_pamh = NULL;
  
static int
conv_func (int n, const struct pam_message **msg,
           struct pam_response **resp, void *arg)
{
        struct pam_response *aresp;
        int i;
	
	g_assert (n > 0 && n < PAM_MAX_NUM_MSG);
	aresp = g_new0(struct pam_response, n);
	
        for (i = 0; i < n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			aresp[i].resp = getpass (msg[i]->msg);
			g_assert (aresp[i].resp != NULL);
			break;
		case PAM_PROMPT_ECHO_ON:
			aresp[i].resp = getpass (msg[i]->msg);
			g_assert (aresp[i].resp != NULL);
			break;
		case PAM_ERROR_MSG:
			fputs(msg[i]->msg, stderr);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stderr);
			break;
                case PAM_TEXT_INFO:
			fputs(msg[i]->msg, stdout);
			if (strlen(msg[i]->msg) > 0 &&
			    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
				fputc('\n', stdout);
        		break;
        	default:
        		return PAM_CONV_ERR;
		}
        }
	*resp = aresp;
	return PAM_SUCCESS;
}  

struct pam_conv conv = { conv_func, NULL };

DEFINE_START(setup_pam)
{
	char user[1024];
	int ret;
	
	printf ("Make sure the PAM module is installed by doing:\n"	
		"# make install-pam\n"
		"\n"
		"Then make /etc/pam.d/testgkr contains:\n"
		"\n"
		"auth    required        pam_unix.so nullok_secure\n"
		"auth    optional        pam_gnome_keyring.so try_first_pass\n"
		"session required        pam_unix.so\n"
		"session optional        pam_gnome_keyring.so\n"
		"\n");
	sleep (1);
	
	printf ("User: ");
	if (!fgets (user, sizeof (user), stdin))
		g_return_if_reached ();
	
	g_strstrip (user);

	ret = pam_start ("testgkr", user[0] ? user : g_get_user_name (), &conv, &test_pamh);
	if (ret != PAM_SUCCESS)
		g_error ("couldn't initialize pam");
		
	g_assert (test_pamh);
}	

DEFINE_STOP(setup_pam)
{
	g_assert (test_pamh);
	pam_end (test_pamh, PAM_SUCCESS);
}
