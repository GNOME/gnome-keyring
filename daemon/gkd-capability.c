/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-capability.c - the security-critical initial phase of the daemon
 *
 * Copyright (C) 2011,2020 Steve Grubb
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"

#include "gkd-capability.h"

#ifdef HAVE_LIBCAPNG
#include <cap-ng.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_LIBCAPNG

/* No logging, no gettext */
static void
early_error (const char *err_string, int rc)
{
	fprintf (stderr, "gnome-keyring-daemon: %s - %d, aborting\n",
		err_string, rc);
	exit (1);
}

static void
early_warning (const char *warn_string)
{
	if (!getenv ("GNOME_KEYRING_TEST_SERVICE"))
		fprintf (stderr, "gnome-keyring-daemon: %s\n", warn_string);
}

#endif /* HAVE_LIPCAPNG */

/*
 * This program needs the CAP_IPC_LOCK posix capability.
 * We want to allow either setuid root or file system based capabilies
 * to work. If file system based capabilities, this is a no-op unless
 * the root user is running the program. In that case we just drop
 * capabilities down to IPC_LOCK. If we are setuid root, then change to the
 * invoking user retaining just the IPC_LOCK capability. The application
 * is aborted if for any reason we are unable to drop privileges.
 * Note: even gettext is unavailable!
 */
void
gkd_capability_obtain_capability_and_drop_privileges (void)
{
#ifdef HAVE_LIBCAPNG
	int rc;

	capng_get_caps_process ();
	switch (capng_have_capabilities (CAPNG_SELECT_CAPS))
	{
		case CAPNG_FULL:
			/* We are either setuid root or the root user */
			capng_clear (CAPNG_SELECT_CAPS);
			capng_update (CAPNG_ADD,
					CAPNG_EFFECTIVE|CAPNG_PERMITTED,
					CAP_IPC_LOCK);
			if ((rc = capng_change_id (getuid (), getgid (),
						   CAPNG_DROP_SUPP_GRP|
						   CAPNG_CLEAR_BOUNDING))) {
				early_error ("failed dropping capabilities",
					     rc);
			}
			break;
		case CAPNG_FAIL:
			early_error ("error getting process capabilities", 0);
			break;
		case CAPNG_NONE:
			early_warning ("no process capabilities, insecure memory might get used");
			break;
		case CAPNG_PARTIAL: { /* File system based capabilities */
			capng_select_t set = CAPNG_SELECT_CAPS;
			if (!capng_have_capability (CAPNG_EFFECTIVE,
							    CAP_IPC_LOCK)) {
				early_warning ("insufficient process capabilities, insecure memory might get used");
			}

			/* If we don't have CAP_SETPCAP, we can't update the
			 * bounding set */
			if (capng_have_capability (CAPNG_EFFECTIVE,
								CAP_SETPCAP)) {
				set = CAPNG_SELECT_BOTH;
			}

			 /* Drop all capabilities except ipc_lock */
			capng_clear (CAPNG_SELECT_BOTH);
			if ((rc = capng_update (CAPNG_ADD,
						CAPNG_EFFECTIVE|CAPNG_PERMITTED,
						CAP_IPC_LOCK)) != 0) {
				early_error ("error updating process capabilities", rc);
			}
			if ((rc = capng_apply (set)) != 0) {
				early_error ("error dropping process capabilities", rc);
			}} /* Extra brace for local variable declaration */
			break;
	}
#endif /* HAVE_LIBCAPNG */
}
