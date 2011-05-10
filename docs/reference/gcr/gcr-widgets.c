
#include "gcr-shooter.h"
#include "gcr.h"

static GcrShooterInfo *
create_certificate_widget (const gchar *name)
{
	GError *error = NULL;
	GcrCertificate *certificate;
	GtkWidget *widget;
	GtkWidget *align;
	gchar *filename;
	gchar *contents;
	gsize length;

	filename = g_build_filename (TOPDIR, "gcr", "tests", "files", "cacert.org.cer", NULL);
	if (!g_file_get_contents (filename, &contents, &length, &error))
		g_error ("couldn't read file: %s: %s", filename, error->message);
	g_free (filename);

	certificate = gcr_simple_certificate_new (contents, length);
	g_free (contents);

	widget = GTK_WIDGET (gcr_certificate_widget_new (certificate));
	g_object_unref (certificate);

	align = gtk_alignment_new (0.5, 0.5, 0.0, 0.0);
	gtk_container_add (GTK_CONTAINER (align), widget);

	return gcr_shooter_info_new (name, align, GCR_SHOOTER_LARGE);
}

static void
on_parser_key_parsed (GcrParser *parser, gpointer unused)
{
	GckAttributes **attrs = unused;
	*attrs = gck_attributes_ref (gcr_parser_get_parsed_attributes (parser));
}

static GcrShooterInfo *
create_key_widget (const gchar *name)
{
	GError *error = NULL;
	GckAttributes *attrs = NULL;
	GtkWidget *widget;
	GtkWidget *align;
	GcrParser *parser;
	gchar *filename;
	gchar *contents;
	gsize length;

	filename = g_build_filename (TOPDIR, "gcr", "tests", "files", "der-dsa-1024.key", NULL);
	if (!g_file_get_contents (filename, &contents, &length, &error))
		g_error ("couldn't read file: %s: %s", filename, error->message);
	g_free (filename);

	parser = gcr_parser_new ();
	g_signal_connect (parser, "parsed", G_CALLBACK (on_parser_key_parsed), &attrs);
	if (!gcr_parser_parse_data (parser, contents, length, &error))
		g_error ("couldn't parse data: %s", error->message);
	g_object_unref (parser);
	g_free (contents);

	g_assert (attrs);
	widget = GTK_WIDGET (gcr_key_widget_new (attrs));
	gck_attributes_unref (attrs);

	align = gtk_alignment_new (0.5, 0.5, 0.0, 0.0);
	gtk_container_add (GTK_CONTAINER (align), widget);

	return gcr_shooter_info_new (name, align, GCR_SHOOTER_LARGE);
}


GcrShooterInfo*
gcr_widgets_create (const gchar *name)
{
	g_assert (name);

	if (g_str_equal (name, "certificate-widget"))
		return create_certificate_widget (name);
	else if (g_str_equal (name, "key-widget"))
		return create_key_widget (name);

	return NULL;
}
