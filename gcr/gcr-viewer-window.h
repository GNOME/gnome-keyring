/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gcr-viewer-window.h: Window for viewer

   Copyright (C) 2011 Collabora Ltd.

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

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#ifndef GCR_VIEWER_WINDOW_H
#define GCR_VIEWER_WINDOW_H

#include <gtk/gtk.h>

#define GCR_TYPE_VIEWER_WINDOW               (gcr_viewer_window_get_type ())
#define GCR_VIEWER_WINDOW(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_VIEWER_WINDOW, GcrViewerWindow))
#define GCR_VIEWER_WINDOW_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_VIEWER_WINDOW, GcrViewerWindowClass))
#define GCR_IS_VIEWER_WINDOW(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_VIEWER_WINDOW))
#define GCR_IS_VIEWER_WINDOW_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_VIEWER_WINDOW))
#define GCR_VIEWER_WINDOW_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_VIEWER_WINDOW, GcrViewerWindowClass))

typedef struct _GcrViewerWindow GcrViewerWindow;
typedef struct _GcrViewerWindowClass GcrViewerWindowClass;
typedef struct _GcrViewerWindowPrivate GcrViewerWindowPrivate;

struct _GcrViewerWindow {
	GtkWindow parent;
	GcrViewerWindowPrivate *pv;
};

struct _GcrViewerWindowClass {
	GtkWindowClass parent_class;
};

GType              gcr_viewer_window_get_type         (void);

GcrViewerWindow *  gcr_viewer_window_new              (void);

void               gcr_viewer_window_load             (GcrViewerWindow *self,
                                                       GFile *file);

#endif /* GCR_VIEWER_WINDOW_H */
