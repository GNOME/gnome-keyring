/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-location-watch.h - Watch for changes in all base locations

   Copyright (C) 2007, Stefan Walter

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

#ifndef __GKR_LOCATION_WATCH_H__
#define __GKR_LOCATION_WATCH_H__

#include <glib-object.h>

#include "gkr-location.h"

G_BEGIN_DECLS

#define GKR_TYPE_LOCATION_WATCH             (gkr_location_watch_get_type ())
#define GKR_LOCATION_WATCH(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_LOCATION_WATCH, GkrLocationWatch))
#define GKR_LOCATION_WATCH_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_LOCATION_WATCH, GObject))
#define GKR_IS_LOCATION_WATCH(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_LOCATION_WATCH))
#define GKR_IS_LOCATION_WATCH_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_LOCATION_WATCH))
#define GKR_LOCATION_WATCH_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_LOCATION_WATCH, GkrLocationWatchClass))

typedef struct _GkrLocationWatch GkrLocationWatch;
typedef struct _GkrLocationWatchClass GkrLocationWatchClass;

struct _GkrLocationWatch {
	GObject parent;
	GkrLocationManager *manager;
};

struct _GkrLocationWatchClass {
	GObjectClass parent_class;

	void (*location_added) (GkrLocationManager *locmgr, GQuark location);
	void (*location_changed) (GkrLocationManager *locmgr, GQuark location);
	void (*location_removed) (GkrLocationManager *locmgr, GQuark location);
};

GType                    gkr_location_watch_get_type             (void) G_GNUC_CONST;

GkrLocationWatch*        gkr_location_watch_new                  (GkrLocationManager *locmgr,
                                                                  GQuark only_volume, 
                                                                  const gchar *subdir,
                                                                  const gchar *include_pattern,
                                                                  const gchar *exclude_pattern);

void                     gkr_location_watch_refresh              (GkrLocationWatch *watch, 
                                                                  gboolean force_all);

G_END_DECLS

#endif /* __GKR_LOCATION_WATCH_H__ */

