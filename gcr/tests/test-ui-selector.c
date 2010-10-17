
#include "config.h"

#include "gcr.h"

#include <gtk/gtk.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

static void
chdir_base_dir (char* argv0)
{
	gchar *dir, *base;

	dir = g_path_get_dirname (argv0);
	if (chdir (dir) < 0)
		g_warning ("couldn't change directory to: %s: %s",
		           dir, g_strerror (errno));

	base = g_path_get_basename (dir);
	if (strcmp (base, ".libs") == 0) {
		if (chdir ("..") < 0)
			g_warning ("couldn't change directory to ..: %s",
			           g_strerror (errno));
	}

	g_free (base);
	g_free (dir);
}

static void
on_parser_parsed (GcrParser *parser, gpointer user_data)
{
	GcrSimpleCollection *collection = user_data;
	GcrRenderer *renderer;

	renderer = gcr_renderer_create (gcr_parser_get_parsed_label (parser),
	                                gcr_parser_get_parsed_attributes (parser));

	if (renderer) {
		gcr_simple_collection_add (collection, G_OBJECT (renderer));
		g_object_unref (renderer);
	}
}

static void
add_to_selector (GcrParser *parser, const gchar *path)
{
	GError *err = NULL;
	guchar *data;
	gsize n_data;

	if (!g_file_get_contents (path, (gchar**)&data, &n_data, NULL))
		g_error ("couldn't read file: %s", path);

	if (!gcr_parser_parse_data (parser, data, n_data, &err))
		g_error ("couldn't parse data: %s", err->message);

	g_free (data);
}

#if 1
static void
build_selector (GtkDialog *dialog, GcrCollection *collection)
{
	GcrCollectionModel *model;
	GtkWidget *combo;
	GtkCellRenderer *cell;

	model = gcr_collection_model_new (collection,
	                                  "icon", G_TYPE_ICON,
	                                  "markup", G_TYPE_STRING,
	                                  NULL);

	combo = gtk_combo_box_new_with_model (GTK_TREE_MODEL (model));
	cell = gtk_cell_renderer_pixbuf_new ();
	g_object_set (cell, "stock-size", GTK_ICON_SIZE_DND, NULL);
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), cell, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (combo), cell, "gicon", 0);

	cell = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), cell, TRUE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (combo), cell, "markup", 1);

	gtk_widget_show (GTK_WIDGET (combo));
	gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (dialog)), combo);

	gtk_window_set_default_size (GTK_WINDOW (dialog), 550, 400);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 20);

	g_object_unref (model);
}
#endif

#if 0
static void
build_selector (GtkDialog *dialog, GcrCollection *collection)
{
	GcrCollectionModel *model;
	const GcrModelColumn *columns;
	GtkWidget *combo;
	GtkCellRenderer *cell;

	columns = gcr_renderer_columns (GCR_TYPE_CERTIFICATE_RENDERER);
	model = gcr_collection_model_new_full (collection, columns);

	gtk_tree_view_new_with_model (GTK_TREE_MODEL (model));

	combo = gtk_combo_box_new_with_model (GTK_TREE_MODEL (model));
	cell = gtk_cell_renderer_pixbuf_new ();
	g_object_set (cell, "stock-size", GTK_ICON_SIZE_DND, NULL);
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), cell, FALSE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (combo), cell, "gicon", 0);

	cell = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), cell, TRUE);
	gtk_cell_layout_add_attribute (GTK_CELL_LAYOUT (combo), cell, "markup", 1);

	gtk_widget_show (GTK_WIDGET (combo));
	gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (dialog)), combo);

	gtk_window_set_default_size (GTK_WINDOW (dialog), 550, 400);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 20);

	g_object_unref (model);
}
#endif

int
main (int argc, char *argv[])
{
	GcrCollection *collection;
	GtkDialog *dialog;
	GcrParser *parser;
	int i;

	gtk_init (&argc, &argv);

	dialog = GTK_DIALOG (gtk_dialog_new ());
	g_object_ref_sink (dialog);

	collection = gcr_simple_collection_new ();
	build_selector (dialog, collection);

#if 0
	{
		GtkWidget *widget = gtk_file_chooser_button_new ("Tester", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
		gtk_widget_show (widget);
		gtk_container_add (GTK_CONTAINER (gtk_dialog_get_content_area (dialog)), widget);
	}
#endif

	parser = gcr_parser_new ();
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_parsed), collection);

	if (argc == 1) {
		chdir_base_dir (argv[0]);
		add_to_selector (parser, "test-data/ca-certificates.crt");
	} else {
		for (i = 1; i < argc; ++i)
			add_to_selector (parser, argv[i]);
	}

	g_object_unref (parser);
	g_object_unref (collection);

	gtk_dialog_run (dialog);
	gtk_widget_destroy (GTK_WIDGET (dialog));
	g_object_unref (dialog);

	return 0;
}
