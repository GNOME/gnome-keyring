/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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
 */

#include "config.h"

#include "gcr-view.h"

#include "gck/gck.h"

#include <gtk/gtk.h>

typedef struct _GcrRegisteredView {
	GckAttributes *attrs;
	GType view_type;
} GcrRegisteredView;

static GArray *registered_views = NULL;
static gboolean registered_sorted = FALSE;

static void
gcr_view_base_init (gpointer gobject_iface)
{
	static gboolean initialized = FALSE;
	if (!initialized) {

		g_object_interface_install_property (gobject_iface,
		         g_param_spec_string ("label", "Label", "The label for the view",
		                              "", G_PARAM_READWRITE));

		g_object_interface_install_property (gobject_iface,
		         g_param_spec_boxed ("attributes", "Attributes", "The data displayed in the view",
		                             GCK_TYPE_ATTRIBUTES, G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

		initialized = TRUE;
	}
}

GType
gcr_view_get_type (void)
{
	static GType type = 0;
	if (!type) {
		static const GTypeInfo info = {
			sizeof (GcrViewIface),
			gcr_view_base_init,  /* base init */
			NULL,                /* base finalize */
		};
		type = g_type_register_static (G_TYPE_INTERFACE, "GcrViewIface", &info, 0);
		g_type_interface_add_prerequisite (type, GTK_TYPE_WIDGET);
	}

	return type;
}

static gint
sort_registered_by_n_attrs (gconstpointer a, gconstpointer b)
{
	const GcrRegisteredView *ra = a;
	const GcrRegisteredView *rb = b;
	gulong na, nb;

	g_assert (a);
	g_assert (b);

	na = gck_attributes_count (ra->attrs);
	nb = gck_attributes_count (rb->attrs);

	/* Note we're sorting in reverse order */
	if (na < nb)
		return 1;
	return (na == nb) ? 0 : -1;
}

GcrView*
gcr_view_create (const gchar *label, GckAttributes *attrs)
{
	GcrRegisteredView *registered;
	gboolean matched;
	gulong n_attrs;
	gulong j;
	gsize i;

	g_return_val_if_fail (attrs, NULL);

	if (!registered_views)
		return NULL;

	if (!registered_sorted) {
		g_array_sort (registered_views, sort_registered_by_n_attrs);
		registered_sorted = TRUE;
	}

	for (i = 0; i < registered_views->len; ++i) {
		registered = &(g_array_index (registered_views, GcrRegisteredView, i));
		n_attrs = gck_attributes_count (registered->attrs);

		matched = TRUE;

		for (j = 0; j < n_attrs; ++j) {
			if (!gck_attributes_contains (attrs, gck_attributes_at (registered->attrs, j))) {
				matched = FALSE;
				break;
			}
		}

		if (matched)
			return g_object_new (registered->view_type, "label", label,
			                     "attributes", attrs, NULL);
	}

	return NULL;
}

void
gcr_view_register (GType view_type, GckAttributes *attrs)
{
	GcrRegisteredView registered;

	if (!registered_views)
		registered_views = g_array_new (FALSE, FALSE, sizeof (GcrRegisteredView));

	registered.view_type = view_type;
	registered.attrs = gck_attributes_ref (attrs);
	g_array_append_val (registered_views, registered);
	registered_sorted = FALSE;
}
