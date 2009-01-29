
#include "config.h"

#include "gcr-certificate-details-widget.h"
#include "gcr-simple-certificate.h"

#include <gtk/gtk.h>

static void
test_details (void)
{
	GcrCertificateDetailsWidget *details;
	GcrCertificate *certificate;
	GtkDialog *dialog;
	guchar *data;
	gsize n_data;
	
	if (!g_file_get_contents ("test-data/der-certificate.crt", (gchar**)&data, &n_data, NULL))
		g_assert_not_reached ();
	
	certificate = gcr_simple_certificate_new (data, n_data);
	g_assert (certificate);
	g_free (data);
	
	dialog = GTK_DIALOG (gtk_dialog_new ());
	g_object_ref_sink (dialog);
	
	details = gcr_certificate_details_widget_new (certificate);
	gtk_widget_show (GTK_WIDGET (details));
	gtk_container_add (GTK_CONTAINER (dialog->vbox), GTK_WIDGET (details));

	gtk_window_set_default_size (GTK_WINDOW (dialog), 400, 400);
	gtk_dialog_run (dialog);
	
	g_object_unref (dialog);
	g_object_unref (certificate);
	g_object_unref (details);
}

int
main(int argc, char *argv[])
{
	gtk_init (&argc, &argv);
	test_details ();
	return 0;
}
