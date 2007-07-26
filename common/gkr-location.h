/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-location.c - A filesystem location with some resiliency

   Copyright (C) 2007, Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRLOCATION_H_
#define GKRLOCATION_H_

#include <glib.h>

GQuark         gkr_location_from_path      (const gchar *path);

GQuark         gkr_location_from_string    (const gchar *str);

GQuark         gkr_location_from_child     (GQuark parent, const gchar *child);

const gchar*   gkr_location_to_string      (GQuark loc);
 
gchar*         gkr_location_to_path        (GQuark loc);

gboolean       gkr_location_is_descendant (GQuark parent, GQuark descendant);

#include <glib-object.h>

G_BEGIN_DECLS

#define GKR_TYPE_LOCATION_MANAGER             (gkr_location_manager_get_type ())
#define GKR_LOCATION_MANAGER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_LOCATION_MANAGER, GkrLocationManager))
#define GKR_LOCATION_MANAGER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_LOCATION_MANAGER, GObject))
#define GKR_IS_LOCATION_MANAGER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_LOCATION_MANAGER))
#define GKR_IS_LOCATION_MANAGER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_LOCATION_MANAGER))
#define GKR_LOCATION_MANAGER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_LOCATION_MANAGER, GkrLocationManagerClass))

typedef struct _GkrLocationManager GkrLocationManager;
typedef struct _GkrLocationManagerClass GkrLocationManagerClass;

struct _GkrLocationManager {
	GObject parent;
};

struct _GkrLocationManagerClass {
	GObjectClass parent_class;

	void (*location_added) (GkrLocationManager *locmgr, const gchar *prefix);
	
	void (*location_removed) (GkrLocationManager *locmgr, const gchar *prefix);
};

GType                    gkr_location_manager_get_type           (void) G_GNUC_CONST;

GkrLocationManager*      gkr_location_manager_get                (void);

void                     gkr_location_manager_register           (GkrLocationManager *locmgr, 
                                                                  const gchar *name, 
                                                                  const gchar *prefix);

void                     gkr_location_manager_unregister         (GkrLocationManager *locmgr, 
                                                                  const gchar *name);

GSList*	                 gkr_location_manager_get_locations      (GkrLocationManager *locmgr);

G_END_DECLS

#endif /*GKRLOCATION_H_*/
