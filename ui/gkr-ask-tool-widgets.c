/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gnome-ask-tool-widgets.c - Some widget routines for gnome-keyring-ask

   Copyright (C) 2003 Red Hat, Inc

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

   Author: Alexander Larsson <alexl@redhat.com>
*/

#include "config.h"

#include "gkr-ask-tool.h"

#include <gtk/gtk.h>

#include <string.h>

static const gchar*
icon_for_location (const gchar *name)
{
	if (strcmp (name, "HOME:") == 0)
		return "gnome-fs-home";
	if (strcmp (name, "LOCAL:") == 0)
		return "gnome-fs-home";
	return "gnome-dev-removable";
}	
		
static GtkWidget*
create_location_label (GKeyFile *input_data)
{
	GtkWidget *widget = NULL;
	GtkWidget *label, *image;
	const gchar *display = NULL;
	gchar *location = NULL;
	gchar **loc_names = NULL;
	gsize i, n_loc_names, n_loc_displays;
	gchar **loc_displays = NULL;

	location = g_key_file_get_value (input_data, "location", "location", NULL);
	if (!location)
		return NULL;
		
	loc_names = g_key_file_get_string_list (input_data, "location", "names", 
	                                        &n_loc_names, NULL);
	if (!loc_names || !n_loc_names) {
		g_warning ("no 'names' found");
		goto done;
	}

	loc_displays = g_key_file_get_string_list (input_data, "location", "display-names", 
	                                           &n_loc_displays, NULL);
	
	for (i = 0; i < n_loc_names; ++i) {
		if (strcmp (location, loc_names[i]) == 0) {
			if (loc_displays && i < n_loc_displays) 
				display = loc_displays[i];
			break;
		}
	}
	
	widget = gtk_hbox_new (FALSE, 3);
	label = gtk_label_new (display ? display : location);
	image = gtk_image_new_from_icon_name (icon_for_location (location), 
	                                      GTK_ICON_SIZE_SMALL_TOOLBAR);
	
	gtk_box_pack_start (GTK_BOX (widget), image, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (widget), label, FALSE, TRUE, 0);
	gtk_widget_show_all (widget);	
		
done:
	g_strfreev (loc_names);
	g_strfreev (loc_displays);
	g_free (location);
	return widget;
}

enum {
	COLUMN_ICON,
	COLUMN_NAME,
	COLUMN_DISPLAY,
};

static void
selection_changed (GtkComboBox *box, gpointer unused)
{
	GtkTreeIter iter;
	const gchar *location = NULL;
	
	if (gtk_combo_box_get_active_iter (box, &iter)) {
		gtk_tree_model_get (gtk_combo_box_get_model (box), &iter, 
		                    COLUMN_NAME, &location, -1);
	} 
	
	g_object_set_data (G_OBJECT (box), "location-selected", (gpointer)location);
}

static GtkWidget*
create_location_selector (GKeyFile *input_data)
{
	GtkWidget *widget = NULL;
	const gchar *display;
	gchar *location = NULL;
	gchar **loc_names = NULL;
	gsize i, n_loc_names, n_loc_displays;
	gchar **loc_displays = NULL;
	GtkTreeIter iter;
	GtkListStore *store;
	GtkCellRenderer *renderer;
	gint selected = -1; 

	loc_names = g_key_file_get_string_list (input_data, "location", "names", 
	                                        &n_loc_names, NULL);
	if (!loc_names || !n_loc_names) {
		g_warning ("no 'names' found");
		goto done;
	}
	
	/* Only one, then just make a label */
	if (n_loc_names == 1) {
		widget = create_location_label (input_data);
		if (widget)
			g_object_set_data_full (G_OBJECT (widget), "location-selected", 
		                                g_strdup (loc_names[0]), g_free);
		goto done;
	}

	loc_displays = g_key_file_get_string_list (input_data, "location", "display-names", 
	                                           &n_loc_displays, NULL);
	location = g_key_file_get_value (input_data, "location", "location", NULL);
	
	/* Create and populate the store */
	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
	for (i = 0; i < n_loc_names; ++i) {
		gtk_list_store_append (store, &iter);
		
		/* Choose a selected row, for later use */
		if (selected < 0)
			selected = i;
		if (location && strcmp (location, loc_names[i]) == 0)
			selected = i;
		
		display = loc_names[i];
		if (loc_displays && n_loc_displays > i)
			display = loc_displays[i];
		
		gtk_list_store_set (store, &iter, 
		                    COLUMN_ICON, icon_for_location (loc_names[i]),
		                    COLUMN_NAME, loc_names[i],
		                    COLUMN_DISPLAY, display,
		                    -1);
	} 

	widget = gtk_combo_box_new_with_model (GTK_TREE_MODEL (store));
	
	renderer = gtk_cell_renderer_pixbuf_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (widget), renderer, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (widget), renderer, "icon-name", COLUMN_ICON);
	g_object_set (renderer, "xpad", 3, NULL);
	
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (widget), renderer, TRUE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (widget), renderer, "text", COLUMN_DISPLAY);
	
	g_signal_connect (widget, "changed", G_CALLBACK (selection_changed), NULL);

	if (selected >= 0)
		gtk_combo_box_set_active (GTK_COMBO_BOX (widget), selected);
		
done:
	g_strfreev (loc_names);
	g_strfreev (loc_displays);
	return widget;
}

GtkWidget*
gkr_ask_tool_create_location (GKeyFile *input_data)
{
	if (g_key_file_get_boolean (input_data, "location", "location-selector", NULL))
		return create_location_selector (input_data);
	else 
		return create_location_label (input_data);
}

const gchar*
gkr_ask_tool_get_location (GtkWidget *widget)
{
	return (const gchar*)g_object_get_data (G_OBJECT (widget), "location-selected"); 
}
