
#include "config.h"

#include "gcr/gcr.h"

#include <gtk/gtk.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

#define TEST_TYPE_COLLECTION               (test_collection_get_type ())
#define TEST_COLLECTION(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), TEST_TYPE_COLLECTION, TestCollection))
#define TEST_IS_COLLECTION(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TEST_TYPE_COLLECTION))

typedef struct _TestCollection TestCollection;
typedef struct _TestCollectionClass TestCollectionClass;
typedef struct _TestCollectionPrivate TestCollectionPrivate;

struct _TestCollection {
	GcrSimpleCollection parent;
	gchar *label;
};

struct _TestCollectionClass {
	GcrSimpleCollectionClass parent_class;
};

GType test_collection_get_type (void) G_GNUC_CONST;

enum {
	PROP_0,
	PROP_LABEL,
};

G_DEFINE_TYPE (TestCollection, test_collection, GCR_TYPE_SIMPLE_COLLECTION);

static GHashTable *all_collections = NULL;

static void
test_collection_init (TestCollection *self)
{

}

static void
test_collection_finalize (GObject *obj)
{
	TestCollection *self = TEST_COLLECTION (obj);
	g_free (self->label);
	g_hash_table_remove (all_collections, self);
	G_OBJECT_CLASS (test_collection_parent_class)->finalize (obj);
}

static void
test_collection_get_property (GObject *obj,
                              guint prop_id,
                              GValue *value,
                              GParamSpec *pspec)
{
	TestCollection *self = TEST_COLLECTION (obj);
	switch (prop_id) {
	case PROP_LABEL:
		g_value_set_string (value, self->label);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
test_collection_class_init (TestCollectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->get_property = test_collection_get_property;
	gobject_class->finalize = test_collection_finalize;

	g_object_class_install_property (gobject_class, PROP_LABEL,
	           g_param_spec_string ("label", "label", "label", NULL, G_PARAM_READABLE));
}

static GcrSimpleCollection *
test_collection_instance (const gchar *label)
{
	TestCollection *collection = NULL;

	g_assert (label);

	if (!all_collections) {
		all_collections = g_hash_table_new (g_str_hash, g_str_equal);
	} else {
		collection = g_hash_table_lookup (all_collections, label);
		if (collection != NULL)
			return g_object_ref (collection);
	}

	collection = g_object_new (TEST_TYPE_COLLECTION, NULL);
	collection->label = g_strdup (label);
	g_hash_table_insert (all_collections, collection->label, collection);
	return GCR_SIMPLE_COLLECTION (collection);
}

static void
on_parser_parsed (GcrParser *parser, gpointer user_data)
{
	GcrSimpleCollection *collection = user_data;
	GcrSimpleCollection *testcol;
	GcrRenderer *renderer;
	gchar *group;

	renderer = gcr_renderer_create (gcr_parser_get_parsed_label (parser),
	                                gcr_parser_get_parsed_attributes (parser));
	if (renderer == NULL)
		return;

	if (GCR_IS_CERTIFICATE (renderer))
		group = gcr_certificate_get_subject_part (GCR_CERTIFICATE (renderer), "O");
	else
		group = g_strdup (G_OBJECT_TYPE_NAME (renderer));


	testcol = test_collection_instance (group);
	if (!gcr_simple_collection_contains (collection, G_OBJECT (testcol)))
		gcr_simple_collection_add (collection, G_OBJECT (testcol));

	gcr_simple_collection_add (GCR_SIMPLE_COLLECTION (testcol), G_OBJECT (renderer));
	g_object_unref (renderer);
	g_object_unref (testcol);
	g_free (group);
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

int
main (int argc, char *argv[])
{
	GcrCollection *collection;
	GcrTreeSelector *selector;
	GtkDialog *dialog;
	GcrParser *parser;
	GtkWidget *scroll;
	GList *selected, *l;
	int i;

	gtk_init (&argc, &argv);

	dialog = GTK_DIALOG (gtk_dialog_new ());
	g_object_ref_sink (dialog);

	collection = gcr_simple_collection_new ();
	selector = gcr_tree_selector_new (collection, GCR_CERTIFICATE_COLUMNS);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), GTK_WIDGET (selector));
	gtk_widget_show_all (scroll);

	gtk_widget_show (GTK_WIDGET (selector));
	gtk_box_pack_start (GTK_BOX (gtk_dialog_get_content_area (dialog)), GTK_WIDGET (scroll), TRUE, TRUE, 0);

	gtk_window_set_default_size (GTK_WINDOW (dialog), 550, 400);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 20);

	parser = gcr_parser_new ();
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_parsed), collection);

	if (argc == 1) {
		add_to_selector (parser, SRCDIR "/files/ca-certificates.crt");
	} else {
		for (i = 1; i < argc; ++i)
			add_to_selector (parser, argv[i]);
	}

	g_object_unref (parser);
	g_object_unref (collection);

	gtk_dialog_run (dialog);

	selected = gcr_tree_selector_get_selected (selector);
	for (l = selected; l; l = g_list_next (l)) {
		gchar *label;
		g_object_get (l->data, "label", &label, NULL);
		g_print ("selected: %s\n", label);
		g_free (label);
	}
	g_list_free (selected);

	gtk_widget_destroy (GTK_WIDGET (dialog));
	g_object_unref (dialog);

	return 0;
}
