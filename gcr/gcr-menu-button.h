/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef GCR_MENU_BUTTON_H
#define GCR_MENU_BUTTON_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define GCR_TYPE_MENU_BUTTON               (_gcr_menu_button_get_type ())
#define GCR_MENU_BUTTON(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GCR_TYPE_MENU_BUTTON, GcrMenuButton))
#define GCR_MENU_BUTTON_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GCR_TYPE_MENU_BUTTON, GcrMenuButtonClass))
#define GCR_IS_MENU_BUTTON(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GCR_TYPE_MENU_BUTTON))
#define GCR_IS_MENU_BUTTON_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GCR_TYPE_MENU_BUTTON))
#define GCR_MENU_BUTTON_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GCR_TYPE_MENU_BUTTON, GcrMenuButtonClass))

typedef struct _GcrMenuButton GcrMenuButton;
typedef struct _GcrMenuButtonClass GcrMenuButtonClass;
typedef struct _GcrMenuButtonPrivate GcrMenuButtonPrivate;

struct _GcrMenuButton {
	GtkToggleButton parent;
	GcrMenuButtonPrivate *pv;
};

struct _GcrMenuButtonClass {
	GtkToggleButtonClass parent;
};

GType              _gcr_menu_button_get_type   (void);

GtkWidget *        _gcr_menu_button_new        (const gchar *label);

GtkMenu *          _gcr_menu_button_get_menu   (GcrMenuButton *self);

void               _gcr_menu_button_set_menu   (GcrMenuButton *self,
                                                GtkMenu *menu);
G_END_DECLS

#endif /* GCR_MENU_BUTTON_H */
