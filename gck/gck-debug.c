/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2; -*- */
/*
 * Copyright (C) 2007 Collabora Ltd.
 * Copyright (C) 2007 Nokia Corporation
 * Copyright (C) 2011 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"

#include "gck.h"
#include "gck-debug.h"

#include <glib.h>
#include <glib/gstdio.h>

#include "pkcs11.h"

#ifdef WITH_DEBUG

static GckDebugFlags current_flags = 0;

static GDebugKey keys[] = {
	{ "session", GCK_DEBUG_SESSION },
	{ "enumerator", GCK_DEBUG_ENUMERATOR },
	{ 0, }
};

static void
debug_set_flags (GckDebugFlags new_flags)
{
	current_flags |= new_flags;
}

void
_gck_debug_set_flags (const gchar *flags_string)
{
	guint nkeys;

	for (nkeys = 0; keys[nkeys].value; nkeys++);

	if (flags_string)
		debug_set_flags (g_parse_debug_string (flags_string, keys, nkeys));
}

gboolean
_gck_debug_flag_is_set (GckDebugFlags flag)
{
	return (flag & current_flags) != 0;
}

void
_gck_debug_message (GckDebugFlags flag,
                    const gchar *format,
                    ...)
{
	static gsize initialized_flags = 0;
	gchar *message;
	va_list args;

	if (g_once_init_enter (&initialized_flags)) {
		_gck_debug_set_flags (g_getenv ("GCK_DEBUG"));
		g_once_init_leave (&initialized_flags, 1);
	}

	va_start (args, format);
	message = g_strdup_vprintf (format, args);
	va_end (args);

	if (flag & current_flags)
		g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", message);

	g_free (message);
}

#else /* !WITH_DEBUG */

gboolean
_gck_debug_flag_is_set (GckDebugFlags flag)
{
	return FALSE;
}

void
_gck_debug_message (GckDebugFlags flag,
                    const gchar *format,
                    ...)
{
}

void
_gck_debug_set_flags (const gchar *flags_string)
{
}

#endif /* !WITH_DEBUG */
