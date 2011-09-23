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
#include "gcr-renderer.h"
#include "gcr-viewer.h"

#include "egg/egg-oid.h"
#include "egg/egg-hex.h"

#include <gdk/gdk.h>
#include <glib/gi18n-lib.h>

static void _gcr_display_view_viewer_iface (GcrViewerIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrDisplayView, _gcr_display_view, GTK_TYPE_TEXT_VIEW,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_VIEWER, _gcr_display_view_viewer_iface));

#define ZWSP "\342\200\213"
#define NORMAL_MARGIN 10
#define FIELD_MARGIN 17
#define COLUMN_MARGIN 6
#define ICON_MARGIN 8
#define MESSAGE_PADDING 8

typedef struct _GcrDisplayItem {
	GcrDisplayView *display_view;
	GcrRenderer *renderer;
	gboolean expanded;
	gboolean details;
	GtkTextMark *beginning;
	GtkTextMark *ending;
	GtkWidget *details_widget;
	GtkTextChildAnchor *area_anchor;
	GtkTextTag *extra_tag;
	gint field_width;
	GdkPixbuf *pixbuf;
	GtkTextTag *field_tag;
	GtkTextTag *details_tag;
	gulong data_changed_id;
} GcrDisplayItem;

struct _GcrDisplayViewPrivate {
	GtkTextBuffer *buffer;
	GPtrArray *renderers;
	GHashTable *items;
	GtkTextTag *title_tag;
	GtkTextTag *content_tag;
	GtkTextTag *heading_tag;
	GtkTextTag *message_tag;
	GtkTextTag *monospace_tag;
	GtkTextTag *area_tag;
	GcrDisplayItem *current_item;
	gint text_height;
	GdkCursor *cursor;

	gboolean have_measurements;
	gint minimal_width;
	gint natural_width;
	gint minimal_height;
	gint natural_height;
};

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
ensure_measurements (GcrDisplayView *self)
{
	PangoLayout *layout;
	PangoRectangle extents;
	gint icon_width;
	gint icon_height;
	GHashTableIter iter;
	GcrDisplayItem *item;
	gpointer value;
	gboolean expanded;

	if (self->pv->have_measurements)
		return;

	/* See if anything is expanded? */
	expanded = FALSE;
	g_hash_table_iter_init (&iter, self->pv->items);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		item = value;
		if (item->expanded) {
			expanded = TRUE;
			break;
		}
	}

	/*
	 * We use a string in our widget font as the basis for our measurements.
	 * These are just estimates of what we need, and what looks goodish.
	 * There's room here for improvement. If this is causes problems for
	 * you or bothers you, scratch that itch:
	 */

	layout = gtk_widget_create_pango_layout (GTK_WIDGET (self), "0123456789");
	pango_layout_get_extents (layout, NULL, &extents);
	pango_extents_to_pixels (&extents, NULL);
	g_object_unref (layout);

	if (!gtk_icon_size_lookup (GTK_ICON_SIZE_DIALOG, &icon_width, &icon_height)) {
		icon_width = 48;
		icon_height = 48;
	}

	if (expanded) {
		/* If expanded, display more 10 lines at least */
		self->pv->minimal_height = extents.height * 14;
		self->pv->natural_height = extents.height * 25;
	} else {
		/* If not expanded we can get by with 9 lines */
		self->pv->minimal_height = extents.height * 8;
		self->pv->natural_height = extents.height * 9;
	}

	self->pv->minimal_width = icon_width + (extents.width * 5);
	self->pv->natural_width = icon_width + (extents.width * 8);
	self->pv->have_measurements = TRUE;
}

static void
ensure_text_height (GcrDisplayView *self)
{
	PangoRectangle extents;
	PangoLayout *layout;

	if (self->pv->text_height > 0)
		return;

	layout = gtk_widget_create_pango_layout (GTK_WIDGET (self), "Wp");
	pango_layout_get_extents (layout, NULL, &extents);
	pango_extents_to_pixels (&extents, NULL);
	g_object_unref (layout);

	self->pv->text_height = extents.height;
}

static void
recalculate_and_resize (GcrDisplayView *self)
{
	self->pv->have_measurements = FALSE;
	gtk_widget_queue_resize (GTK_WIDGET (self));
}

static GtkTextTagTable*
create_tag_table (GcrDisplayView *self)
{
	GtkTextTagTable *tags;
	gint width, height;

	g_assert (GCR_IS_DISPLAY_VIEW (self));

	tags = gtk_text_tag_table_new ();

	if (!gtk_icon_size_lookup (GTK_ICON_SIZE_DIALOG, &width, &height))
		width = 48;

	self->pv->title_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                    "name", "title",
	                                    "scale", PANGO_SCALE_LARGE,
	                                    "right-margin", (ICON_MARGIN * 2) + width,
	                                    "pixels-below-lines", 6,
	                                    "weight", PANGO_WEIGHT_BOLD,
	                                    NULL);
	gtk_text_tag_table_add (tags, self->pv->title_tag);

	self->pv->content_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                      "name", "content",
	                                      "right-margin", (ICON_MARGIN * 2) + width,
	                                      "left-margin", FIELD_MARGIN,
	                                      "pixels-below-lines", 3,
	                                      "wrap-mode", GTK_WRAP_WORD,
	                                      NULL);
	gtk_text_tag_table_add (tags, self->pv->content_tag);

	self->pv->message_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                      "name", "message",
	                                      "right-margin", (ICON_MARGIN * 2) + width,
	                                      "rise", 3 * PANGO_SCALE,
	                                      "pixels-below-lines", 3,
	                                      "wrap-mode", GTK_WRAP_WORD,
	                                      NULL);
	gtk_text_tag_table_add (tags, self->pv->message_tag);

	self->pv->heading_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                      "name", "heading",
	                                      "pixels-above-lines", 9,
	                                      "pixels-below-lines", 3,
	                                      "weight", PANGO_WEIGHT_BOLD,
	                                      NULL);
	gtk_text_tag_table_add (tags, self->pv->heading_tag);

	self->pv->monospace_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                        "name", "monospace",
	                                        "family", "monospace",
	                                        NULL);
	gtk_text_tag_table_add (tags, self->pv->monospace_tag);

	self->pv->area_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                   "name", "area",
	                                   "justification", GTK_JUSTIFY_CENTER,
	                                   NULL);
	gtk_text_tag_table_add (tags, self->pv->area_tag);

	return tags;
}

static void
on_expander_realize (GtkWidget *widget, gpointer user_data)
{
	GdkCursor *cursor = gdk_cursor_new (GDK_ARROW);
	gdk_window_set_cursor (gtk_widget_get_window (widget), cursor);
	g_object_unref (cursor);
}

static void
on_expander_expanded (GObject *object, GParamSpec *param_spec, gpointer user_data)
{
	GtkExpander *expander = GTK_EXPANDER (object);
	GcrDisplayItem *item = user_data;
	item->expanded = gtk_expander_get_expanded (expander);
	gcr_renderer_render_view (item->renderer, GCR_VIEWER (item->display_view));
	recalculate_and_resize (item->display_view);
}

static void
style_display_item (GtkWidget *widget, GcrDisplayItem *item)
{
	GtkStyleContext *style;
	GdkRGBA color;

	style = gtk_widget_get_style_context (GTK_WIDGET (widget));
	gtk_style_context_save (style);

	gtk_style_context_add_class (style, GTK_STYLE_CLASS_VIEW);
	gtk_style_context_get_background_color (style, GTK_STATE_FLAG_NORMAL, &color);

	gtk_style_context_restore (style);

	color.red = 255;
	color.green = 0;
	color.blue = 0;
	gtk_widget_override_background_color (item->details_widget, GTK_STATE_FLAG_NORMAL, &color);
}

static GcrDisplayItem*
create_display_item (GcrDisplayView *self, GcrRenderer *renderer)
{
	GcrDisplayItem *item;
	GtkTextTagTable *tags;
	GtkTextIter iter;
	GtkWidget *widget;
	GtkWidget *label;
	GtkWidget *alignment;
	gchar *text;

	item = g_new0 (GcrDisplayItem, 1);
	item->display_view = self;
	item->renderer = renderer;

	tags = gtk_text_buffer_get_tag_table (self->pv->buffer);

	g_assert (!item->field_tag);
	item->field_width = 0;
	item->field_tag = g_object_new (GTK_TYPE_TEXT_TAG,
	                                "left-margin", item->field_width + FIELD_MARGIN,
	                                "indent", item->field_width,
	                                "pixels-below-lines", 3,
	                                "wrap-mode", GTK_WRAP_WORD_CHAR,
	                                NULL);
	gtk_text_tag_table_add (tags, item->field_tag);

	g_assert (!item->details_tag);
	item->details_tag = g_object_new (GTK_TYPE_TEXT_TAG, NULL);
	gtk_text_tag_table_add (tags, item->details_tag);

	/*
	 * Add two lines space that delimit this from later items. The
	 * item will live between the two zero width spaces.
	 */
	gtk_text_buffer_get_end_iter (self->pv->buffer, &iter);
	gtk_text_buffer_insert (self->pv->buffer, &iter, "\n\n", -1);
	if (!gtk_text_iter_backward_char (&iter))
		g_assert_not_reached ();

	/* The mark that determines the beginning of this item, with left gravity. */
	item->beginning = gtk_text_buffer_create_mark (self->pv->buffer, NULL, &iter, TRUE);
	g_object_ref (item->beginning);

	/* The mark that determines the end of this item, with right gravity. */
	item->ending = gtk_text_buffer_create_mark (self->pv->buffer, NULL, &iter, FALSE);
	g_object_ref (item->ending);

	widget = gtk_expander_new_with_mnemonic ("");
	label = gtk_expander_get_label_widget (GTK_EXPANDER (widget));
	text = g_strdup_printf ("<b>%s</b>", _("_Details"));
	gtk_label_set_markup_with_mnemonic (GTK_LABEL (label), text);
	g_signal_connect (widget, "notify::expanded", G_CALLBACK (on_expander_expanded), item);
	g_signal_connect (widget, "realize", G_CALLBACK (on_expander_realize), NULL);
	item->expanded = gtk_expander_get_expanded (GTK_EXPANDER (widget));
	g_free (text);

	alignment = gtk_alignment_new (0.5, 0.5, 0.5, 0.5);
	gtk_alignment_set_padding (GTK_ALIGNMENT (alignment), 6, 9, 0, 0);
	gtk_container_add (GTK_CONTAINER (alignment), widget);
	gtk_widget_show_all (alignment);

	item->details_widget = gtk_event_box_new ();
	gtk_event_box_set_visible_window (GTK_EVENT_BOX (item->details_widget), FALSE);
	gtk_container_add (GTK_CONTAINER (item->details_widget), alignment);
	g_signal_connect (item->details_widget, "realize", G_CALLBACK (on_expander_realize), NULL);
	g_object_ref (item->details_widget);

	if (gtk_widget_get_realized (GTK_WIDGET (self)))
		style_display_item (GTK_WIDGET (self), item);

	return item;
}

static void
destroy_display_item (gpointer data)
{
	GcrDisplayItem *item = data;
	GtkTextIter iter, end;
	GtkTextTagTable *tags;
	GcrDisplayView *self;

	g_assert (item);

	g_assert (GCR_IS_DISPLAY_VIEW (item->display_view));
	self = item->display_view;

	tags = gtk_text_buffer_get_tag_table (self->pv->buffer);
	gtk_text_tag_table_remove (tags, item->field_tag);
	gtk_text_tag_table_remove (tags, item->details_tag);

	g_object_unref (item->field_tag);
	g_object_unref (item->details_tag);

	if (item->pixbuf)
		g_object_unref (item->pixbuf);
	item->pixbuf = NULL;

	g_assert (item->details_widget);
	g_object_unref (item->details_widget);
	item->details_widget = NULL;

	g_clear_object (&item->area_anchor);

	g_return_if_fail (!gtk_text_mark_get_deleted (item->beginning));
	g_return_if_fail (!gtk_text_mark_get_deleted (item->ending));

	/* Setup iters to encompass our delemiter characters see create_display_item() */
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->beginning);
	gtk_text_iter_backward_char (&iter);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &end, item->ending);
	gtk_text_iter_forward_char (&end);
	gtk_text_buffer_delete (self->pv->buffer, &iter, &end);

	gtk_text_buffer_delete_mark (self->pv->buffer, item->beginning);
	gtk_text_buffer_delete_mark (self->pv->buffer, item->ending);

	g_object_unref (item->beginning);
	g_object_unref (item->ending);

	g_free (item);
}

static GcrDisplayItem*
lookup_display_item (GcrDisplayView *self, GcrRenderer *renderer)
{
	GcrDisplayItem *item = g_hash_table_lookup (self->pv->items, renderer);
	g_return_val_if_fail (item, NULL);
	g_assert (item->display_view == self);
	return item;
}

static GcrDisplayItem*
find_item_at_iter (GcrDisplayView *self, GtkTextIter *iter)
{
	GHashTableIter hi;
	GcrDisplayItem *item;
	gpointer value;
	GtkTextIter start, end;

	g_hash_table_iter_init (&hi, self->pv->items);
	while (g_hash_table_iter_next (&hi, NULL, &value)) {
		item = value;

		gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &start, item->beginning);
		gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &end, item->ending);

		if (gtk_text_iter_compare (iter, &start) >= 0 &&
		    gtk_text_iter_compare (iter, &end) < 0)
			return item;
	}

	return NULL;
}

static void
on_renderer_data_changed (GcrRenderer *renderer,
                          gpointer user_data)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (user_data);

	/* Item may be removed, but not yet destroyed */
	if (!g_hash_table_lookup (self->pv->items, renderer))
		return;

	/* Just ask the renderer to render itself on us */
	gcr_renderer_render_view (renderer, GCR_VIEWER (self));
}

static void
paint_item_icon (GcrDisplayView *self,
                 GcrDisplayItem *item,
                 GdkRectangle *visible,
                 cairo_t *cr)
{
	GtkTextIter iter;
	GdkRectangle location;
	GtkTextView *view;

	if (item->pixbuf == NULL)
		return;

	view = GTK_TEXT_VIEW (self);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->beginning);
	gtk_text_view_get_iter_location (view, &iter, &location);

	location.height = gdk_pixbuf_get_height (item->pixbuf);
	location.width = gdk_pixbuf_get_width (item->pixbuf);
	location.x = visible->width - location.width - ICON_MARGIN;

	if (!gdk_rectangle_intersect (visible, &location, NULL))
		return;

	gtk_text_view_buffer_to_window_coords (view, GTK_TEXT_WINDOW_TEXT,
	                                       location.x, location.y,
	                                       &location.x, &location.y);

	cairo_save (cr);
	gdk_cairo_set_source_pixbuf (cr, item->pixbuf, location.x, location.y);
	cairo_rectangle (cr, location.x, location.y, location.width, location.height);
	cairo_fill (cr);
	cairo_restore (cr);
}

static void
paint_item_border (GcrDisplayView *self,
                   GcrDisplayItem *item,
                   GtkStyleContext *context,
                   GdkRectangle *visible,
                   gint index,
                   cairo_t *cr)
{
	GdkRGBA color;
	GtkTextView *view;
	GtkTextIter iter, end;
	GdkRectangle location;

	if (index == 0)
		return;

	view = GTK_TEXT_VIEW (self);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->beginning);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &end, item->ending);

	/* Don't paint for non-visible items */
	if (gtk_text_iter_compare (&iter, &end) == 0)
		return;

	ensure_text_height (self);

	gtk_style_context_get_background_color (context,
	                                        GTK_STATE_FLAG_SELECTED | GTK_STATE_FLAG_FOCUSED,
	                                        &color);

	gtk_text_view_get_iter_location (view, &iter, &location);

	location.height = 2;
	location.width = visible->width - (NORMAL_MARGIN * 2);
	location.x = NORMAL_MARGIN;
	location.y -= self->pv->text_height / 2;

	if (!gdk_rectangle_intersect (visible, &location, NULL))
		return;

	gtk_text_view_buffer_to_window_coords (view, GTK_TEXT_WINDOW_TEXT,
	                                       location.x, location.y,
	                                       &location.x, &location.y);

	cairo_save (cr);
	cairo_set_source_rgb (cr, color.red, color.green, color.blue);
	cairo_set_line_width (cr, 0.5);
	cairo_move_to (cr, location.x, location.y);
	cairo_line_to (cr, location.x + location.width, location.y);
	cairo_stroke (cr);
	cairo_restore (cr);
}

static void
paint_extras (GcrDisplayView *self, cairo_t *cr)
{
	GdkRectangle visible;
	GcrDisplayItem *item;
	GtkStyleContext *context;
	guint i;

	gtk_text_view_get_visible_rect (GTK_TEXT_VIEW (self), &visible);
	context = gtk_widget_get_style_context (GTK_WIDGET (self));

	for (i = 0; i < self->pv->renderers->len; i++) {
		item = g_hash_table_lookup (self->pv->items, self->pv->renderers->pdata[i]);
		g_assert (item != NULL);
		paint_item_icon (self, item, &visible, cr);
		paint_item_border (self, item, context, &visible, i, cr);
	}
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

	return obj;
}

static void
_gcr_display_view_init (GcrDisplayView *self)
{
	self->pv = (G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_DISPLAY_VIEW, GcrDisplayViewPrivate));
	self->pv->items = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, destroy_display_item);
	self->pv->renderers = g_ptr_array_new_with_free_func (g_object_unref);
}

static void
_gcr_display_view_dispose (GObject *obj)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (obj);
	GcrRenderer *renderer;
	GcrDisplayItem *item;

	while (self->pv->renderers->len) {
		renderer = g_ptr_array_index (self->pv->renderers, 0);
		item = g_hash_table_lookup (self->pv->items, renderer);
		g_return_if_fail (item);
		g_signal_handler_disconnect (renderer, item->data_changed_id);
		if (!g_hash_table_remove (self->pv->items, renderer))
			g_return_if_reached ();
		g_ptr_array_remove_index_fast (self->pv->renderers, 0);
	}

	if (self->pv->buffer)
		g_object_unref (self->pv->buffer);
	self->pv->buffer = NULL;

	g_assert (g_hash_table_size (self->pv->items) == 0);

	G_OBJECT_CLASS (_gcr_display_view_parent_class)->dispose (obj);
}

static void
_gcr_display_view_finalize (GObject *obj)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (obj);

	if (self->pv->buffer)
		g_object_unref (self->pv->buffer);
	self->pv->buffer = NULL;

	g_assert (g_hash_table_size (self->pv->items) == 0);
	g_hash_table_destroy (self->pv->items);
	self->pv->items = NULL;

	g_assert (self->pv->renderers);
	g_assert (self->pv->renderers->len == 0);
	g_ptr_array_free (self->pv->renderers, TRUE);
	self->pv->renderers = NULL;

	g_assert (self->pv->content_tag);
	g_object_unref (self->pv->content_tag);
	self->pv->content_tag = NULL;

	g_assert (self->pv->heading_tag);
	g_object_unref (self->pv->heading_tag);
	self->pv->heading_tag = NULL;

	g_assert (self->pv->monospace_tag);
	g_object_unref (self->pv->monospace_tag);
	self->pv->monospace_tag = NULL;

	g_assert (self->pv->title_tag);
	g_object_unref (self->pv->title_tag);
	self->pv->title_tag = NULL;

	g_clear_object (&self->pv->cursor);

	G_OBJECT_CLASS (_gcr_display_view_parent_class)->finalize (obj);
}

static void
_gcr_display_view_realize (GtkWidget *widget)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	GHashTableIter iter;
	GdkDisplay *display;
	gpointer value;

	if (GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->realize)
		GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->realize (widget);

	/* Set style on all the items */
	g_hash_table_iter_init (&iter, self->pv->items);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		style_display_item (widget, value);

	if (!self->pv->cursor) {
		display = gtk_widget_get_display (GTK_WIDGET (self));
		self->pv->cursor = gdk_cursor_new_for_display (display, GDK_ARROW);
	}

	gdk_window_set_cursor (gtk_text_view_get_window (GTK_TEXT_VIEW (self), GTK_TEXT_WINDOW_WIDGET),
	                       self->pv->cursor);
}

static gboolean
_gcr_display_view_button_press_event (GtkWidget *widget, GdkEventButton *event)
{
	GtkTextView *text_view = GTK_TEXT_VIEW (widget);
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	GcrDisplayItem *item;
	gboolean handled = FALSE;
	GtkTextIter iter;
	gint x, y;

	if (GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->button_press_event)
		handled = GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->button_press_event (
				widget, event);

	if (event->window == gtk_text_view_get_window (text_view, GTK_TEXT_WINDOW_TEXT)) {
		gtk_text_view_window_to_buffer_coords (text_view, GTK_TEXT_WINDOW_TEXT,
		                                       event->x, event->y, &x, &y);
		gtk_text_view_get_iter_at_location (text_view, &iter, x, y);

		item = find_item_at_iter (self, &iter);
		self->pv->current_item = item;
	}

	return handled;
}

static gboolean
_gcr_display_view_draw (GtkWidget *widget, cairo_t *cr)
{
	GdkWindow *window;
	gboolean handled = TRUE;

	/* Have GtkTextView draw the text first. */
	if (GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->draw)
		handled = GTK_WIDGET_CLASS (_gcr_display_view_parent_class)->draw (widget, cr);

	window = gtk_text_view_get_window (GTK_TEXT_VIEW (widget), GTK_TEXT_WINDOW_TEXT);
	if (gtk_cairo_should_draw_window (cr, window))
		paint_extras (GCR_DISPLAY_VIEW (widget), cr);

	return handled;
}

static void
_gcr_display_get_preferred_height (GtkWidget *widget, gint *minimal_height,
                                   gint *natural_height)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	ensure_measurements (self);
	*minimal_height = self->pv->minimal_height;
	*natural_height = self->pv->natural_height;
}

static void
_gcr_display_get_preferred_width (GtkWidget *widget, gint *minimal_width,
                                  gint *natural_width)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (widget);
	ensure_measurements (self);
	*minimal_width = self->pv->minimal_width;
	*natural_width = self->pv->natural_width;
}

static void
_gcr_display_view_populate_popup (GtkTextView *text_view, GtkMenu *menu)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (text_view);

	if (GTK_TEXT_VIEW_CLASS (_gcr_display_view_parent_class)->populate_popup)
		GTK_TEXT_VIEW_CLASS (_gcr_display_view_parent_class)->populate_popup (text_view, menu);

	/* Ask the current renderer to add menu items */
	if (self->pv->current_item)
		gcr_renderer_popuplate_popup (self->pv->current_item->renderer,
		                              GCR_VIEWER (self), menu);
}

static void
_gcr_display_view_class_init (GcrDisplayViewClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);
	GtkTextViewClass *text_view_class = GTK_TEXT_VIEW_CLASS (klass);

	_gcr_display_view_parent_class = g_type_class_peek_parent (klass);
	g_type_class_add_private (klass, sizeof (GcrDisplayViewPrivate));

	gobject_class->constructor = _gcr_display_view_constructor;
	gobject_class->dispose = _gcr_display_view_dispose;
	gobject_class->finalize = _gcr_display_view_finalize;

	widget_class->realize = _gcr_display_view_realize;
	widget_class->button_press_event = _gcr_display_view_button_press_event;
	widget_class->get_preferred_height = _gcr_display_get_preferred_height;
	widget_class->get_preferred_width = _gcr_display_get_preferred_width;
	widget_class->draw = _gcr_display_view_draw;

	text_view_class->populate_popup = _gcr_display_view_populate_popup;
}

static void
_gcr_display_view_real_insert_renderer (GcrViewer *viewer,
                                        GcrRenderer *renderer,
                                        GcrRenderer *before)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (viewer);
	GcrDisplayItem *item;
	guint i;

	if (before != NULL)
		g_return_if_fail (g_hash_table_lookup (self->pv->items, before) != NULL);

	item = create_display_item (self, renderer);
	g_object_ref (renderer);

	/* Insert it at the right place */
	if (before != NULL) {
		g_ptr_array_add (self->pv->renderers, NULL);
		for (i = self->pv->renderers->len; i > 0; i--) {
			self->pv->renderers->pdata[i] = self->pv->renderers->pdata[i - 1];
			if (self->pv->renderers->pdata[i] == before) {
				self->pv->renderers->pdata[i - 1] = renderer;
				break;
			}
		}

		/* Must have been found */
		g_assert (i > 0);

	/* No before, just add to end */
	} else {
		g_ptr_array_add (self->pv->renderers, renderer);
	}

	g_hash_table_insert (self->pv->items, renderer, item);

	gcr_renderer_render_view (renderer, viewer);
	item->data_changed_id = g_signal_connect (renderer, "data-changed",
	                                          G_CALLBACK (on_renderer_data_changed), self);
}

static void
_gcr_display_view_real_add_renderer (GcrViewer *viewer, GcrRenderer *renderer)
{
	_gcr_display_view_real_insert_renderer (viewer, renderer, NULL);
}

static void
_gcr_display_view_real_remove_renderer (GcrViewer *viewer, GcrRenderer *renderer)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (viewer);
	GcrDisplayItem *item;

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	/* Unhook the callback */
	g_signal_handler_disconnect (renderer, item->data_changed_id);

	/* Destroys the display item */
	g_assert (item->display_view == self);
	g_hash_table_remove (self->pv->items, renderer);

	/* Unrefs the renderer */
	if (!g_ptr_array_remove (self->pv->renderers, renderer))
		g_return_if_reached ();
}

static guint
_gcr_display_view_real_count_renderers (GcrViewer *viewer)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (viewer);
	return self->pv->renderers->len;
}

static GcrRenderer*
_gcr_display_view_real_get_renderer (GcrViewer *viewer, guint index_)
{
	GcrDisplayView *self = GCR_DISPLAY_VIEW (viewer);
	g_return_val_if_fail (index_ < self->pv->renderers->len, NULL);
	return g_ptr_array_index (self->pv->renderers, index_);
}

static void
_gcr_display_view_viewer_iface (GcrViewerIface *iface)
{
	iface->add_renderer = (gpointer)_gcr_display_view_real_add_renderer;
	iface->insert_renderer = (gpointer)_gcr_display_view_real_insert_renderer;
	iface->remove_renderer = (gpointer)_gcr_display_view_real_remove_renderer;
	iface->count_renderers = (gpointer)_gcr_display_view_real_count_renderers;
	iface->get_renderer = (gpointer)_gcr_display_view_real_get_renderer;
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
_gcr_display_view_begin (GcrDisplayView *self,
                         GcrRenderer *renderer)
{
	GtkTextIter start, iter;
	GcrDisplayItem *item;
	GList *widgets, *l;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	/* Remove the details widget so it doesn't get destroyed */
	if (gtk_widget_get_parent (item->details_widget))
		gtk_container_remove (GTK_CONTAINER (self), item->details_widget);

	/* Remove area widgets so they don't get destroyed unnecessarily */
	if (item->area_anchor) {
		g_assert (!gtk_text_child_anchor_get_deleted (item->area_anchor));
		widgets = gtk_text_child_anchor_get_widgets (item->area_anchor);
		for (l = widgets; l != NULL; l = g_list_next (l))
			gtk_container_remove (GTK_CONTAINER (self), l->data);
		g_list_free (widgets);
		g_object_unref (item->area_anchor);
		item->area_anchor = NULL;
	}

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &start, item->beginning);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	gtk_text_buffer_delete (self->pv->buffer, &start, &iter);

	item->extra_tag = NULL;
	item->field_width = 0;
	item->details = FALSE;
}

void
_gcr_display_view_end (GcrDisplayView *self,
                       GcrRenderer *renderer)
{
	GcrDisplayItem *item;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);
}

void
_gcr_display_view_start_details (GcrDisplayView *self, GcrRenderer *renderer)
{
	GtkTextChildAnchor *anchor;
	GcrDisplayItem *item;
	GtkTextIter iter;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->details) {
		g_warning ("A GcrRenderer implementation has called %s twice in one render",
		           G_STRFUNC);
		return;
	}

	item->extra_tag = item->details_tag;
	item->details = TRUE;

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	anchor = gtk_text_buffer_create_child_anchor (self->pv->buffer, &iter);
	gtk_text_view_add_child_at_anchor (GTK_TEXT_VIEW (self), item->details_widget, anchor);
	gtk_widget_show_all (item->details_widget);
	gtk_text_buffer_insert (self->pv->buffer, &iter, "\n", 1);
}

void
_gcr_display_view_append_content (GcrDisplayView *self, GcrRenderer *renderer,
                                  const gchar *content, const gchar *details)
{
	GcrDisplayItem *item;
	GtkTextIter iter;
	gchar *memory = NULL;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (content);

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->details && !item->expanded)
		return;

	if (details)
		content = memory = g_strdup_printf ("%s: %s", content, details);

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, content, -1,
	                                  self->pv->content_tag, item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n", 1,
	                                  item->extra_tag, NULL);

	g_free (memory);
}

void
_gcr_display_view_append_value (GcrDisplayView *self, GcrRenderer *renderer, const gchar *field,
                                const gchar *value, gboolean monospace)
{
	GcrDisplayItem *item;
	PangoRectangle extents;
	PangoTabArray *tabs;
	PangoLayout *layout;
	GtkTextIter iter;
	gchar *text;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (field);

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->details && !item->expanded)
		return;

	text = g_strdup_printf ("%s:", field);
	if (value == NULL)
		value = "";

	/* Measure the width of the field */
	layout = gtk_widget_create_pango_layout (GTK_WIDGET (self), text);
	pango_layout_get_extents (layout, NULL, &extents);
	pango_extents_to_pixels (&extents, NULL);
	g_object_unref (layout);

	/* An estimate of the text height */
	self->pv->text_height = extents.height;

	/* Make the tab wide enough to accomodate */
	if (extents.width > item->field_width) {
		item->field_width = extents.width + COLUMN_MARGIN;
		tabs = pango_tab_array_new (1, TRUE);
		pango_tab_array_set_tab (tabs, 0, PANGO_TAB_LEFT, item->field_width);
		g_object_set (item->field_tag,
		              "left-margin", FIELD_MARGIN,
		              "indent", 0 - item->field_width,
		              "tabs", tabs,
		              NULL);
		pango_tab_array_free (tabs);
	}

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, text, -1,
	                                  item->field_tag, item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\t", 1,
	                                  item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, value, -1, item->field_tag,
	                                  monospace ? self->pv->monospace_tag : item->extra_tag,
	                                  monospace ? item->extra_tag : NULL, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n", 1,
	                                  item->extra_tag, NULL);

	g_free (text);
}

void
_gcr_display_view_append_hex (GcrDisplayView *self, GcrRenderer *renderer,
                              const gchar *field, gconstpointer value, gsize n_value)
{
	gchar *display;

	display = egg_hex_encode_full (value, n_value, TRUE, ' ', 1);
	_gcr_display_view_append_value (self, renderer, field, display, TRUE);
	g_free (display);
}

void
_gcr_display_view_append_title (GcrDisplayView *self, GcrRenderer *renderer, const gchar *title)
{
	GcrDisplayItem *item;
	GtkTextIter iter;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (title);

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->details && !item->expanded)
		return;

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, title, -1,
	                                  self->pv->title_tag, item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n", 1,
	                                  item->extra_tag, NULL);
}

void
_gcr_display_view_append_heading (GcrDisplayView *self, GcrRenderer *renderer, const gchar *heading)
{
	GcrDisplayItem *item;
	GtkTextIter iter;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (heading);

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->details && !item->expanded)
		return;

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, heading, -1,
	                                  self->pv->heading_tag, item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n", 1,
	                                  item->extra_tag, NULL);
}

void
_gcr_display_view_append_fingerprint (GcrDisplayView *self, GcrRenderer *renderer, const guchar *data,
                                      gsize n_data, const gchar *name, GChecksumType type)
{
	GChecksum *checksum;
	guint8 *buffer;
	gsize n_buffer;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));

	checksum = g_checksum_new (type);
	g_return_if_fail (checksum);
	g_checksum_update (checksum, data, n_data);

	n_buffer = g_checksum_type_get_length (type);
	g_return_if_fail (n_buffer);
	buffer = g_malloc0 (n_buffer);

	g_checksum_get_digest (checksum, buffer, &n_buffer);
	g_checksum_free (checksum);

	_gcr_display_view_append_hex (self, renderer, name, buffer, n_buffer);

	g_free (buffer);
}

void
_gcr_display_view_append_message (GcrDisplayView *self,
                                  GcrRenderer *renderer,
                                  GtkMessageType message_type,
                                  const gchar *message)
{
	const gchar *stock_id = NULL;
	GtkWidget *image = NULL;
	GcrDisplayItem *item;
	GtkTextChildAnchor *anchor;
	GtkTextIter iter;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (GCR_IS_RENDERER (renderer));

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	switch (message_type) {
	case GTK_MESSAGE_INFO:
		stock_id = GTK_STOCK_DIALOG_INFO;
		break;

	case GTK_MESSAGE_QUESTION:
		stock_id = GTK_STOCK_DIALOG_QUESTION;
		break;

	case GTK_MESSAGE_WARNING:
		stock_id = GTK_STOCK_DIALOG_WARNING;
		break;

	case GTK_MESSAGE_ERROR:
		stock_id = GTK_STOCK_DIALOG_ERROR;
		break;

	case GTK_MESSAGE_OTHER:
		break;

	default:
		g_warning ("unknown GtkMessageType: %u", message_type);
		break;
	}

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);

	if (stock_id != NULL) {
		image = gtk_image_new_from_stock (stock_id, GTK_ICON_SIZE_MENU);
		gtk_misc_set_padding (GTK_MISC (image), MESSAGE_PADDING, 0);
		gtk_widget_show (image);

		anchor = gtk_text_buffer_create_child_anchor (self->pv->buffer, &iter);
		gtk_text_view_add_child_at_anchor (GTK_TEXT_VIEW (self), image, anchor);
	}

	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, message, -1,
	                                  self->pv->message_tag, item->extra_tag, NULL);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n", 1,
	                                  item->extra_tag, NULL);
}

void
_gcr_display_view_set_icon (GcrDisplayView *self, GcrRenderer *renderer, GIcon *icon)
{
	GcrDisplayItem *item;
	GdkScreen *screen;
	GtkIconTheme *icon_theme;
	GtkSettings *settings;
	gint width, height;
	GtkIconInfo *info;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	item = lookup_display_item (self, renderer);
	g_return_if_fail (item);

	if (item->pixbuf)
		g_object_unref (item->pixbuf);
	item->pixbuf = NULL;

	if (!icon)
		return;

	screen = gtk_widget_get_screen (GTK_WIDGET (self));
	icon_theme = gtk_icon_theme_get_for_screen (screen);
	settings = gtk_settings_get_for_screen (screen);

	if (!gtk_icon_size_lookup_for_settings (settings, GTK_ICON_SIZE_DIALOG, &width, &height))
		g_return_if_reached ();

	info = gtk_icon_theme_lookup_by_gicon (icon_theme, icon, MIN (width, height),
	                                       GTK_ICON_LOOKUP_USE_BUILTIN);

	if (info) {
		GtkStyleContext *style = gtk_widget_get_style_context (GTK_WIDGET (self));
		item->pixbuf = gtk_icon_info_load_symbolic_for_context (info, style, FALSE, NULL);
		gtk_icon_info_free (info);
	}
}

void
_gcr_display_view_add_widget_area (GcrDisplayView *self,
                                   GcrRenderer *renderer,
                                   GtkWidget *area)
{
	GtkTextIter iter, start;
	GcrDisplayItem *item;

	g_return_if_fail (GCR_IS_DISPLAY_VIEW (self));
	g_return_if_fail (GTK_IS_WIDGET (area));

	item = lookup_display_item (self, renderer);
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->area_anchor == NULL);

	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &start, item->ending);
	iter = start;

	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, "\n" ZWSP, -1, self->pv->area_tag, NULL);
	gtk_text_buffer_get_iter_at_mark (self->pv->buffer, &iter, item->ending);

	item->area_anchor = gtk_text_buffer_create_child_anchor (self->pv->buffer, &iter);
	g_object_ref (item->area_anchor);
	gtk_text_view_add_child_at_anchor (GTK_TEXT_VIEW (self), area, item->area_anchor);
	gtk_text_buffer_insert_with_tags (self->pv->buffer, &iter, ZWSP "\n", -1, self->pv->area_tag, NULL);
}
