/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-wakeup.c - wakeup GSource for arbitrary events

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

#include "config.h"

#include "gkr-wakeup.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

static int wakeup_fds[2] = { -1, -1 };
static guint wakeup_n = 0;

int
gkr_wakeup_register (void)
{
	if (wakeup_n++ == 0) {
		if (pipe (wakeup_fds)) {
			g_critical ("can't create wakeup pipe: %s", g_strerror (errno));
			return -1;
		}
		
		/* Non blocking to prevent deadlock */
        	fcntl (wakeup_fds[0], F_SETFL, fcntl (wakeup_fds[0], F_GETFL) | O_NONBLOCK);
        	fcntl (wakeup_fds[1], F_SETFL, fcntl (wakeup_fds[1], F_GETFL) | O_NONBLOCK);
        }
        
        g_assert (wakeup_fds[0] >= 0);
        return wakeup_fds[0];
}

void
gkr_wakeup_unregister (void)
{
	if (--wakeup_n > 0)
		return;

	g_assert (wakeup_fds[0] >= 0);
	close (wakeup_fds[0]);
	wakeup_fds[0] = -1;

	g_assert (wakeup_fds[1] >= 0);
	close (wakeup_fds[1]);
	wakeup_fds[1] = -1;	
}

void
gkr_wakeup_now (void)
{
	#define SIG_MSG "couldn't write signal byte to pipe\n"
	guchar x = 0xAA;
	
	if (wakeup_fds[1] < 0)
		return;
	
	/* Could be called from a signal handler, so try to not use library functions */
	if (write (wakeup_fds[1], &x, 1) != 1)
		write (2, SIG_MSG, strlen (SIG_MSG) - 1);		
}

void
gkr_wakeup_drain (void)
{
	guchar x;
	
	if (wakeup_fds[0] < 0)
		return;
	
	while (read (wakeup_fds[0], &x, 1) > 0);
}
