/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-location.c - A filesystem location with some resiliency

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

#ifndef GKRLOCATION_H_
#define GKRLOCATION_H_

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

/* -----------------------------------------------------------------------------
 * GENERAL LOCATION FUNCTIONS
 */

#define        GKR_LOCATION_NAME_LOCAL     "LOCAL"
#define	       GKR_LOCATION_VOLUME_LOCAL_S "LOCAL:" 
#define        GKR_LOCATION_VOLUME_LOCAL   (gkr_location_from_string (GKR_LOCATION_VOLUME_LOCAL_S))

#define        GKR_LOCATION_NAME_HOME      "HOME"
#define        GKR_LOCATION_VOLUME_HOME_S  "HOME:"
#define        GKR_LOCATION_VOLUME_HOME    (gkr_location_from_string (GKR_LOCATION_VOLUME_HOME_S))

#define        GKR_LOCATION_NAME_FILE      "FILE"
#define        GKR_LOCATION_VOLUME_FILE_S  "FILE:"
#define        GKR_LOCATION_VOLUME_FILE    (gkr_location_from_string (GKR_LOCATION_VOLUME_FILE_S))

GQuark         gkr_location_from_path      (const gchar *path);

GQuark         gkr_location_from_string    (const gchar *str);

GQuark         gkr_location_from_child     (GQuark parent, const gchar *child);

GQuark         gkr_location_to_parent      (GQuark parent);

const gchar*   gkr_location_to_string      (GQuark loc);
 
gchar*         gkr_location_to_path        (GQuark loc);

gboolean       gkr_location_is_volume      (GQuark loc);

gboolean       gkr_location_is_descendant  (GQuark parent, GQuark descendant);

GQuark         gkr_location_get_volume     (GQuark loc);

gchar*         gkr_location_to_display     (GQuark loc);

/* -----------------------------------------------------------------------------
 * UTILITIES
 */
 
gboolean       gkr_location_test_file      (GQuark loc, GFileTest test);
 
gboolean       gkr_location_read_file      (GQuark loc, guchar **data, gsize *len, GError **err);

gboolean       gkr_location_write_file     (GQuark loc, const guchar *data, gssize len, GError **err);

gboolean       gkr_location_delete_file    (GQuark loc, GError **err);

/* -------------------------------------------------------------------------- */

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

	void (*volume_added) (GkrLocationManager *locmgr, GQuark volume);
	
	void (*volume_removed) (GkrLocationManager *locmgr, GQuark volume);
};

GType                    gkr_location_manager_get_type           (void) G_GNUC_CONST;

GkrLocationManager*      gkr_location_manager_get                (void);

void                     gkr_location_manager_register           (GkrLocationManager *locmgr, 
                                                                  const gchar *name, 
                                                                  const gchar *prefix, 
                                                                  const gchar *friendly);

void                     gkr_location_manager_unregister         (GkrLocationManager *locmgr, 
                                                                  const gchar *name);

gboolean                 gkr_location_manager_has_volume         (GkrLocationManager *locmgr, 
                                                                  GQuark volume);
                                                                  
GSList*	                 gkr_location_manager_get_volumes        (GkrLocationManager *locmgr);

const gchar*             gkr_location_manager_get_volume_display (GkrLocationManager *locmgr,
                                                                  GQuark volume);

gboolean                 gkr_location_manager_note_mtime         (GkrLocationManager *locmgr,
                                                                  GQuark location, 
                                                                  time_t mtime);

G_END_DECLS

#endif /*GKRLOCATION_H_*/
