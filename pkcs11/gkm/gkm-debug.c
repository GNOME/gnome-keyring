/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2; -*- */
/*
 * Copyright (C) 2007 Collabora Ltd.
 * Copyright (C) 2007 Nokia Corporation
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

#include "gkm-debug.h"

#include <stdarg.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#ifdef WITH_DEBUG

static GkmDebugFlags current_flags = 0;

static GDebugKey keys[] = {
	{ "storage", GKM_DEBUG_STORAGE },
	{ "object", GKM_DEBUG_OBJECT },
	{ 0, }
};

static void
debug_set_flags (GkmDebugFlags new_flags)
{
	current_flags |= new_flags;
}

void
gkm_debug_set_flags (const gchar *flags_string)
{
	guint nkeys;

	for (nkeys = 0; keys[nkeys].value; nkeys++);

	if (flags_string)
		debug_set_flags (g_parse_debug_string (flags_string, keys, nkeys));
}

gboolean
gkm_debug_flag_is_set (GkmDebugFlags flag)
{
	return (flag & current_flags) != 0;
}

static void
on_gkm_log_debug (const gchar *log_domain,
                  GLogLevelFlags log_level,
                  const gchar *message,
                  gpointer user_data)
{
	GString *gstring;
	const gchar *progname;

	gstring = g_string_new (NULL);

	progname = g_get_prgname ();
	g_string_append_printf (gstring, "(%s:%lu): %s-DEBUG: %s\n",
	                        progname ? progname : "process",
	                        (gulong)getpid (), log_domain,
	                        message ? message : "(NULL) message");

	write (1, gstring->str, gstring->len);
	g_string_free (gstring, TRUE);
}

void
gkm_debug_message (GkmDebugFlags flag,
                   const gchar *format,
                   ...)
{
	static gsize initialized_flags = 0;
	const gchar *messages_env;
	const gchar *debug_env;
	va_list args;

	if (g_once_init_enter (&initialized_flags)) {
		messages_env = g_getenv ("G_MESSAGES_DEBUG");
		debug_env = g_getenv ("GKM_DEBUG");
#ifdef GKM_DEBUG
		if (debug_env == NULL)
			debug_env = G_STRINGIFY (GKM_DEBUG);
#endif

		/*
		 * If the caller is selectively asking for certain debug
		 * messages with the GKM_DEBUG environment variable, then
		 * we install our own output handler and only print those
		 * messages. This happens irrespective of G_MESSAGES_DEBUG
		 */
		if (messages_env == NULL && debug_env != NULL)
			g_log_set_handler (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
			                   on_gkm_log_debug, NULL);

		/*
		 * If the caller is using G_MESSAGES_DEBUG then we enable
		 * all our debug messages, and let Glib filter which ones
		 * to display.
		 */
		if (messages_env != NULL && debug_env == NULL)
			debug_env = "all";

		gkm_debug_set_flags (debug_env);

		g_once_init_leave (&initialized_flags, 1);
	}

	if (flag & current_flags) {
		va_start (args, format);
		g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, format, args);
		va_end (args);
	}
}

#else /* !WITH_DEBUG */

gboolean
gkm_debug_flag_is_set (GkmDebugFlags flag)
{
	return FALSE;
}

void
gkm_debug_message (GkmDebugFlags flag,
                   const gchar *format,
                   ...)
{
}

void
gkm_debug_set_flags (const gchar *flags_string)
{
}

#endif /* !WITH_DEBUG */
