/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* egg-file-tracker.h - Watch for changes in a directory

   Copyright (C) 2008, Stefan Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef __EGG_FILE_TRACKER_H__
#define __EGG_FILE_TRACKER_H__

#include <glib-object.h>

G_BEGIN_DECLS

#define EGG_TYPE_FILE_TRACKER             (egg_file_tracker_get_type ())
#define EGG_FILE_TRACKER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), EGG_TYPE_FILE_TRACKER, EggFileTracker))
#define EGG_FILE_TRACKER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), EGG_TYPE_FILE_TRACKER, GObject))
#define EGG_IS_FILE_TRACKER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), EGG_TYPE_FILE_TRACKER))
#define EGG_IS_FILE_TRACKER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), EGG_TYPE_FILE_TRACKER))
#define EGG_FILE_TRACKER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), EGG_TYPE_FILE_TRACKER, EggFileTrackerClass))

typedef struct _EggFileTracker EggFileTracker;
typedef struct _EggFileTrackerClass EggFileTrackerClass;

struct _EggFileTrackerClass {
	GObjectClass parent_class;

	void (*file_added) (EggFileTracker *locmgr, const gchar *path);
	void (*file_changed) (EggFileTracker *locmgr, const gchar *path);
	void (*file_removed) (EggFileTracker *locmgr, const gchar *path);
};

GType                    egg_file_tracker_get_type             (void) G_GNUC_CONST;

EggFileTracker*          egg_file_tracker_new                  (const gchar *directory,
                                                                const gchar *include_pattern,
                                                                const gchar *exclude_pattern);

void                     egg_file_tracker_refresh              (EggFileTracker *self,
                                                                gboolean force_all);

G_END_DECLS

#endif /* __EGG_FILE_TRACKER_H__ */
