/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-capability.c - the security-critical initial phase of the daemon
 *
 * Copyright (C) 2010 Yaron Sheffer
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Yaron Sheffer <yaronf@gmx.com>
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"

#include "gkd-capability.h"

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

/* Security note: this portion of the code is extremely sensitive.
 * DO NOT add any other include files.
 */

/*
 * No logging, no gettext
 */
static void
early_error (const char *err_string)
{
	fprintf (stderr, "gnome-keyring-daemon: %s\n", err_string);
}

static void
drop_privileges (void)
{
	uid_t orig_uid;
	gid_t orig_gid;

	orig_uid = getuid ();
	orig_gid = getgid ();

	/* This is permanent, you cannot go back to root */
	setgid (orig_gid);
	setuid (orig_uid);

	/*
	 * Check that the switch was ok
	 * We do not allow programs to run without the drop being
	 * successful as this would possibly run the program
	 * using root-privs, when that is not what we want
	 */
	if ((getegid () != orig_gid) || (geteuid () != orig_uid)) {
		early_error ("failed to drop privileges, aborting");
		exit (1);
	}
}

/*
 * Try to obtain the CAP_IPC_LOCK Linux capability.
 * Then, whether or not this is successful, drop root
 * privileges to run as the invoking user. The application is aborted
 * if for any reason we are unable to drop privileges. Note: even gettext
 * is unavailable!
 */
void
gkd_capability_obtain_capability_and_drop_privileges (void)
{
#ifdef HAVE_LIBCAP
	cap_t caps;
	cap_value_t cap_list[1];

	caps = cap_get_proc ();
	if (caps == NULL) {
		early_error ("capability state cannot be allocated");
		goto drop;
	}

	cap_list[0] = CAP_IPC_LOCK;
	if (cap_set_flag (caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == -1) {
		early_error ("error when manipulating capability sets");
		goto drop;
	}

	if (cap_set_proc (caps) == -1) {
		/* Only warn when it's root that's running */
		if (getuid () == 0)
			early_error ("cannot apply capabilities to process");
		goto drop;
	}

	if (cap_free (caps) == -1) {
		early_error ("failed to free capability structure");
		goto drop;
	}
drop:

#endif
	/* Now finally drop the suid by becoming the invoking user */
	if (geteuid () != getuid() || getegid () != getgid ())
		drop_privileges ();
}
