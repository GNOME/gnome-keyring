/*
 * Copyright (C) 2007 Nokia Corporation
 * Copyright (C) 2007-2011 Collabora Ltd.
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

#ifndef GKM_DEBUG_H
#define GKM_DEBUG_H

#include "config.h"

#include "gkm-log.h"

#include <glib.h>

G_BEGIN_DECLS

/* Please keep this enum in sync with #keys in gcr-debug.c */
typedef enum {
	GKM_DEBUG_STORAGE = 1 << 1,
	GKM_DEBUG_OBJECT = 1 << 2,
} GkmDebugFlags;

gboolean           gkm_debug_flag_is_set              (GkmDebugFlags flag);

void               gkm_debug_set_flags                (const gchar *flags_string);

void               gkm_debug_message                  (GkmDebugFlags flag,
                                                       const gchar *format,
                                                       ...) G_GNUC_PRINTF (2, 3);

G_END_DECLS

#endif /* GKM_DEBUG_H */

/* -----------------------------------------------------------------------------
 * Below this point is outside the GKM_DEBUG_H guard - so it can take effect
 * more than once. So you can do:
 *
 * #define DEBUG_FLAG GKM_DEBUG_ONE_THING
 * #include "gcr-debug.h"
 * ...
 * DEBUG ("if we're debugging one thing");
 * ...
 * #undef DEBUG_FLAG
 * #define DEBUG_FLAG GKM_DEBUG_OTHER_THING
 * #include "gcr-debug.h"
 * ...
 * DEBUG ("if we're debugging the other thing");
 * ...
 */

#ifdef DEBUG_FLAG
#ifdef WITH_DEBUG

#undef gkm_debug
#define gkm_debug(format, ...) \
	gkm_debug_message (DEBUG_FLAG, "%s: " format, G_STRFUNC, ##__VA_ARGS__)

#undef gkm_debugging
#define gkm_debugging \
	gkm_debug_flag_is_set (DEBUG_FLAG)

#else /* !defined (WITH_DEBUG) */

#undef gkm_debug
#define gkm_debug(format, ...) \
	do {} while (0)

#undef gkm_debugging
#define gkm_debugging 0

#endif /* !defined (WITH_DEBUG) */

#endif /* defined (DEBUG_FLAG) */
