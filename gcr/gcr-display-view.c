/*
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

#include "gcr-display-view.h"

#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include <gdk/gdk.h>
#if 0
#include <glib/gi18n-lib.h>
#endif

G_DEFINE_TYPE (GcrDisplayView, _gcr_display_view, GTK_TYPE_TEXT_VIEW);

#define NORMAL_MARGIN 5
#define FIELD_MARGIN 17
#define COLUMN_MARGIN 6
#define ICON_MARGIN 8

struct _GcrDisplayViewPrivate {
	GtkTextBuffer *buffer;
	GtkTextTag *field_tag;
	GtkTextTag *details_tag;
	GtkWidget *details_widget;
	GtkTextChildAnchor *details_anchor;
	const gchar *extra_tag;
	gint field_width;
	GdkPixbuf *pixbuf;
};

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static GtkTextTagTable*
create_tag_table (GcrDisplayView *self)
{
	GtkTextTagTable *tags;
	GtkTextTag *tag;
	gint width, height;

	g_assert (GCR_IS_DISPLAY_VIEW (self));

	tags = gtk_text_tag_table_new ();

	if (!gtk_icon_size_lookup (GTK_ICON_SIZE_DIALOG, &width, &height))
		width = 48;

	tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                    "name", "title",
	                    "scale", PANGO_SCALE_LARGE,
	                    "right-margin", (ICON_MARGIN * 2) + width,
	                    "pixels-above-lines", 9,
	                    "pixels-below-lines", 6,
	                    "weight", PANGO_WEIGHT_BOLD,
	                    NULL);
	gtk_text_tag_table_add (tags, tag);
	g_object_unref (tag);

	tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                    "name", "content",
	                    "right-margin", (ICON_MARGIN * 2) + width,
	                    "left-margin", FIELD_MARGIN,
	                    "pixels-below-lines", 3,
	                    NULL);
	gtk_text_tag_table_add (tags, tag);
	g_object_unref (tag);

	tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                    "name", "heading",
	                    "pixels-above-lines", 9,
	                    "pixels-below-lines", 3,
	                    "weight", PANGO_WEIGHT_BOLD,
	                    NULL);
	gtk_text_tag_table_add (tags, tag);
	g_object_unref (tag);

	tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                    "name", "monospace",
	                    "family", "monospace",
	                    NULL);
	gtk_text_tag_table_add (tags, tag);
	g_object_unref (tag);

	g_assert (!self->pv->field_tag);
	self->pv->field_width = 0;
	self->pv->field_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                    "name", "field",
	                                    "left-margin", self->pv->field_width + FIELD_MARGIN,
	                                    "indent", self->pv->field_width,
	                                    "pixels-below-lines", 3,
	                                    "wrap-mode", GTK_WRAP_WORD_CHAR,
	                                    NULL);
	gtk_text_tag_table_add (tags, self->pv->field_tag);

	g_assert (!self->pv->details_tag);
	self->pv->details_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                      "name", "details",
	                                      "foreground", "red",
	                                      NULL);
	gtk_text_tag_table_add (tags, self->pv->details_tag);

	return tags;
}


static void
on_expander_realize (GtkWidget *widget, gpointer user_data)
{
	GdkCursor *cursor = gdk_cursor_new (GDK_ARROW);
	g_printerr ("realize cursor\n");
	gdk_window_set_cursor (gtk_widget_get_window (widget), cursor);
	gdk_cursor_unref (cursor);
}

static void
on_expander_expanded (GObject *object, GParamSpec *param_spec, gpointer user_data)
{
	GtkExpander *expander = GTK_EXPANDER (object);
	GcrDisplayView *self = GCR_DISPLAY_VIEW (user_data);
	g_object_set (self->pv->details_tag,
	              "invisible", gtk_expander_get_expanded (expander) ? FALSE : TRUE,
	              NULL);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */

static GObject*
_gcr_display_view_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GObject *obj = G_OBJECT_CLASS (_gcr_display_view_parent_class)->constructor (type, n_props, props);
	GcrDisplayView *self = NULL;
	GtkTextView *view = NULL;
	GtkTextTagTable *tags;
	GdkColor color;
	GtkWidget *widget;

	g_return_val_if_fail (obj, NULL);

	self = GCR_DISPLAY_VIEW (obj);
	view = GTK_TEXT_VIEW (obj);

	tags = create_tag_table (self);
	self->pv->buffer = gtk_text_buffer_new (tags);
	g_object_unref (tags);

	gtk_text_view_set_buffer (view, self->pv->buffer);
	gtk_text_view_set_editable (view, FALSE);
	gtk_text_view_set_left_margin (view, NORMAL_MARGIN);
	gtk_text_view_set_right_margin (view, NORMAL_MARGIN);
	gtk_text_view_set_cursor_visible (view, FALSE);

	widget = gtk_expander_new_with_mnemonic ("_Details");
	g_signal_connect_object (widget, "notify::expanded",
	                         G_CALLBACK (on_expander_expanded), self, 0);
	g_signal_connect_object (widget, "realize",
	                         G_CALLBACK (on_expander_realize), self, 0);
	on_expander_expanded (G_OBJECT (widget), NULL, self);
	/* TODO: We need to retrieve the background color of the text view */
	gdk_color_parse ("white", &color);
	gtk_widget_modify_bg (widget, GTK_STATE_NORMAL, &color);

	self->pv->details_widget = gtk_event_box_new ();
	gtk_container_add (GTK_CONTAINER (self->pv->details_widget), widget);
	g_signal_connect_object (self->pv->details_widget, "realize",
	                         G_CALLBACK (on_expander_realize), self, 0);
	g_object_ref (self->pv->details_widget);
	gtk_widget_show (widget);

	return obj;
}

static void
_gcr_display_view_init (GcrDisplayView *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_DISPLAY_VIEW, GcrDisplayViewPrivate));
}

static void
_gcr_display_view_finalize (GObject *obj)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (obj);

	if (self->pv->buffer)
		g_object_unref (self->pv->buffer);
	self->pv->buffer = NULL;

	if (self->pv->field_tag)
		g_object_unref (self->pv->field_tag);
	self->pv->field_tag = NULL;

	if (self->pv->pixbuf)
		g_object_unref (self->pv->pixbuf);
	self->pv->pixbuf = NULL;

	if (self->pv->details_widget)
		g_object_unref (self->pv->details_widget);
	self->pv->details_widget = NULL;

	G_OBJECT_CLASS (_gcr_display_view_parent_class)->finalize (obj);
}

static void
_gcr_display_view_realize (GtkWidget *widget)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	GtkStyle *style;

	if (GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->realize)
		GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->realize (widget);

	g_printerr ("setting color\n");
	style = gtk_widget_get_style (widget);
	gtk_widget_modify_bg (self->pv->details_widget, GTK_STATE_NORMAL, &style->base[GTK_STATE_NORMAL]);
}

static gboolean
_gcr_display_view_expose_event (GtkWidget *widget, GdkEventExpose *event)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	GtkTextView *view = GTK_TEXT_VIEW (widget);
	gboolean handled = FALSE;
	GdkRectangle visible;
	GdkRectangle position;
	GdkGC *gc;

	/* Have GtkTextView draw the text first. */
	if (GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->expose_event)
		handled = GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->expose_event (widget, event);

	if (self->pv->pixbuf == NULL)
		return handled;

	/* Render the pixbuf if it's available */
	if (event->window == gtk_text_view_get_window (view, GTK_TEXT_WINDOW_TEXT)) {

		position.height = gdk_pixbuf_get_height (self->pv->pixbuf);
		position.width = gdk_pixbuf_get_width (self->pv->pixbuf);

		gtk_text_view_get_visible_rect (view, &visible);

		gtk_text_view_buffer_to_window_coords (view, GTK_TEXT_WINDOW_TEXT,
		                                       visible.width - position.width - ICON_MARGIN, ICON_MARGIN,
		                                       &position.x, &position.y);

		gc = gdk_gc_new (event->window);
		gdk_draw_pixbuf (event->window, gc, self->pv->pixbuf,
		                 0, 0, position.x, position.y, position.width, position.height,
		                 GDK_RGB_DITHER_NORMAL, 0, 0);
		g_object_unref (gc);
	}

	return handled;
}

static void
_gcr_display_view_class_init (GcrDisplayViewClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	_gcr_display_view_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrDisplayViewPrivate));

	gobject_class->constructor = _gcr_display_view_constructor;
	gobject_class->finalize = _gcr_display_view_finalize;

	widget_class->realize = _gcr_display_view_realize;
	widget_class->expose_event = _gcr_display_view_expose_event;
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GcrDisplayView*
_gcr_display_view_new (void)
{
	return g_object_new (GCR_TYPE_DISPLAY_VIEW, NULL);
}

void
_gcr_display_view_clear (GcrDisplayView *self)
{
	GtkTextIter start, iter;
	if (gtk_widget_get_parent (self->pv->details_widget))
		gtk_container_remove (GTK_CONTAINER (self), self->pv->details_widget);
	gtk_text_buffer_get_start_iter (self->pv->buffer, &start);
	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_delete (self->pv->buffer, &start, &iter);
	self->pv->extra_tag = NULL;
	self->pv->field_width = 0;
}

void
_gcr_display_view_start_details (GcrDisplayView *self)
{
	GtkTextChildAnchor *anchor;
	GtkTextIter iter;

	self->pv->extra_tag = "details";

	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	anchor = gtk_text_buffer_create_child_anchor (self->pv->buffer, &iter);
	gtk_text_view_add_child_at_anchor (GTK_TEXT_VIEW (self), self->pv->details_widget, anchor);
	gtk_widget_show_all (self->pv->details_widget);
	gtk_text_buffer_insert (self->pv->buffer, &iter, "\n", 1);
}

void
_gcr_display_view_append_content (GcrDisplayView *self, const gchar *content, const gchar *details)
{
	GtkTextIter iter;
	gchar *memory = NULL;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (content);

	if (details)
		content = memory = g_strdup_printf ("%s: %s", content, details);

	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, content, -1,
	                                          "content", self->pv->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, "\n", 1,
	                                          self->pv->extra_tag, NULL);

	g_free (memory);
}

void
_gcr_display_view_append_value (GcrDisplayView *self, const gchar *field,
                                const gchar *value, gboolean monospace)
{
	PangoRectangle extents;
	PangoTabArray *tabs;
	PangoLayout *layout;
	GtkTextIter iter;
	gchar *text;

	text = g_strdup_printf ("%s:", field);
	if (value == NULL)
		value = "";

	/* Measure the width of the field */
	layout = gtk_widget_create_pango_layout (GTK_WIDGET (self), text);
	pango_layout_get_extents (layout, NULL, &extents);
	pango_extents_to_pixels (&extents, NULL);
	g_object_unref (layout);

	/* Make the tab wide enough to accomodate */
	if (extents.width > self->pv->field_width) {
		self->pv->field_width = extents.width + COLUMN_MARGIN;
		tabs = pango_tab_array_new (1, TRUE);
		pango_tab_array_set_tab (tabs, 0, PANGO_TAB_LEFT, self->pv->field_width);
		g_object_set (self->pv->field_tag,
		              "left-margin", FIELD_MARGIN,
		              "indent", 0 - self->pv->field_width,
		              "tabs", tabs,
		              NULL);
		pango_tab_array_free (tabs);
	}

	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, text, -1,
	                                          "field", self->pv->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, "\t", 1,
	                                          self->pv->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, value, -1, "field",
	                                          monospace ? "monospace" : self->pv->extra_tag,
	                                          monospace ? self->pv->extra_tag : NULL, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, "\n", 1,
	                                          self->pv->extra_tag, NULL);

	g_free (text);
}

void
_gcr_display_view_append_title (GcrDisplayView *self, const gchar *title)
{
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, title, -1,
	                                          "title", self->pv->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, "\n", 1,
	                                          self->pv->extra_tag, NULL);
}

void
_gcr_display_view_append_heading (GcrDisplayView *self, const gchar *heading)
{
	GtkTextIter iter;

	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, heading, -1,
	                                          "heading", self->pv->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags_by_name (self->pv->buffer, &iter, "\n", 1,
	                                          self->pv->extra_tag, NULL);
}

void
_gcr_display_view_append_fingerprint (GcrDisplayView *self, const guchar *data,
                                      gsize n_data, const gchar *name, GChecksumType type)
{
	GChecksum *checksum;
	guint8 *buffer;
	gsize n_buffer;
	gchar *display;

	checksum = g_checksum_new (type);
	g_return_if_fail (checksum);
	g_checksum_update (checksum, data, n_data);

	n_buffer = g_checksum_type_get_length (type);
	g_return_if_fail (n_buffer);
	buffer = g_malloc0 (n_buffer);

	g_checksum_get_digest (checksum, buffer, &n_buffer);
	g_checksum_free (checksum);

	display = egg_hex_encode_full (buffer, n_buffer, TRUE, ' ', 1);
	_gcr_display_view_append_value (self, name, display, TRUE);
	g_free (display);

	g_free (buffer);
}

void
_gcr_display_view_set_stock_image (GcrDisplayView *self, const gchar *stock_id)
{
	if (self->pv->pixbuf)
		g_object_unref (self->pv->pixbuf);
	self->pv->pixbuf = gtk_widget_render_icon (GTK_WIDGET (self), stock_id, GTK_ICON_SIZE_DIALOG, NULL);
}
