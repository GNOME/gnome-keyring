/*
   Copyright (C) 2014 Red Hat Inc.

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

#include "config.h"

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <stdlib.h>
#include <string.h>

static int
prompt_password (pam_handle_t *ph,
                 const char *prompt,
                 int password_type)
{
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp;
	const struct pam_message *msgs[1];
	const void *item;
	char *password;
	int ret;

	/* Get the conversation function */
	ret = pam_get_item (ph, PAM_CONV, &item);
	if (ret != PAM_SUCCESS)
		return ret;

	/* Setup a message */
	memset (&msg, 0, sizeof (msg));
	memset (&resp, 0, sizeof (resp));
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;
	msgs[0] = &msg;

	/* Call away */
	conv = (const struct pam_conv*)item;
	ret = (conv->conv) (1, msgs, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS)
		return ret;

	password = resp[0].resp;
	free (resp);

	if (password == NULL)
		return PAM_CONV_ERR;

	/* Store it away for later use */
	ret = pam_set_item (ph, password_type, password);
	free (password);

	if (ret == PAM_SUCCESS)
		ret = pam_get_item (ph, password_type, &item);

	return ret;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *ph,
                     int unused,
                     int argc,
                     const char **argv)
{
	/* Just prompt for the password, accept any result */
	return prompt_password (ph, "Password: ", PAM_AUTHTOK);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *ph,
                     int flags,
                     int argc,
                     const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph,
                      int flags,
                      int argc,
                      const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *ph,
                int flags,
                int argc,
                const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *ph,
                  int flags,
                  int argc,
                  const char **argv)
{
	if (flags & PAM_PRELIM_CHECK)
		return prompt_password (ph, "Old Password: ", PAM_OLDAUTHTOK);
	else if (flags & PAM_UPDATE_AUTHTOK)
		return prompt_password (ph, "New Password: ", PAM_AUTHTOK);
	else
		return PAM_IGNORE;
}
