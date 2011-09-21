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

#include "config.h"

#include "gcr-gnupg-importer.h"
#include "gcr-gnupg-process.h"
#include "gcr-internal.h"

#include <glib/gi18n-lib.h>

enum {
	PROP_0,
	PROP_LABEL,
	PROP_ICON,
	PROP_IMPORTED,
	PROP_DIRECTORY
};

struct _GcrGnupgImporterPrivate {
	GcrGnupgProcess *process;
	GMemoryInputStream *packets;
	GArray *imported;
};

static void gcr_gnupg_importer_iface (GcrImporterIface *iface);

G_DEFINE_TYPE_WITH_CODE (GcrGnupgImporter, _gcr_gnupg_importer, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GCR_TYPE_IMPORTER, gcr_gnupg_importer_iface);
);

static void
_gcr_gnupg_importer_init (GcrGnupgImporter *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_GNUPG_IMPORTER, GcrGnupgImporterPrivate);
	self->pv->packets = G_MEMORY_INPUT_STREAM (g_memory_input_stream_new ());
	self->pv->imported = g_array_new (TRUE, TRUE, sizeof (gchar *));
}

static void
_gcr_gnupg_importer_dispose (GObject *obj)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (obj);

	if (self->pv->process)
		g_object_run_dispose (G_OBJECT (self->pv->process));
	g_clear_object (&self->pv->process);
	g_clear_object (&self->pv->packets);

	G_OBJECT_CLASS (_gcr_gnupg_importer_parent_class)->dispose (obj);
}

static void
_gcr_gnupg_importer_finalize (GObject *obj)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (obj);

	g_array_free (self->pv->imported, TRUE);

	G_OBJECT_CLASS (_gcr_gnupg_importer_parent_class)->finalize (obj);
}

static gchar *
calculate_label (GcrGnupgImporter *self)
{
	const gchar *directory;

	directory = _gcr_gnupg_process_get_directory (self->pv->process);
	if (directory == NULL)
		return g_strdup (_("GnuPG Keyring"));
	else
		return g_strdup_printf (_("GnuPG Keyring: %s"), directory);
}

static GIcon *
calculate_icon (GcrGnupgImporter *self)
{
	const gchar *directory;

	directory = _gcr_gnupg_process_get_directory (self->pv->process);
	if (directory == NULL)
		return g_themed_icon_new ("user-home");
	else
		return g_themed_icon_new ("folder");
}

static gboolean
on_process_status_record (GcrGnupgProcess *process,
                          GcrRecord *record,
                          gpointer user_data)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (user_data);
	const gchar *value;
	gchar *fingerprint;

	if (_gcr_record_get_schema (record) != GCR_RECORD_SCHEMA_IMPORT_OK)
		return TRUE;

	value = _gcr_record_get_raw (record, GCR_RECORD_IMPORT_FINGERPRINT);
	if (value != NULL && value[0] != 0) {
		fingerprint = g_strdup (value);
		g_array_append_val (self->pv->imported, fingerprint);
	}

	return TRUE;
}

static void
_gcr_gnupg_importer_set_property (GObject *obj,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (obj);

	switch (prop_id) {
	case PROP_DIRECTORY:
		self->pv->process = _gcr_gnupg_process_new (g_value_get_string (value),
		                                            NULL);
		_gcr_gnupg_process_set_input_stream (self->pv->process, G_INPUT_STREAM (self->pv->packets));
		g_signal_connect (self->pv->process, "status-record", G_CALLBACK (on_process_status_record), self);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_importer_get_property (GObject *obj,
                                  guint prop_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (obj);

	switch (prop_id) {
	case PROP_LABEL:
		g_value_take_string (value, calculate_label (self));
		break;
	case PROP_ICON:
		g_value_take_object (value, calculate_icon (self));
		break;
	case PROP_IMPORTED:
		g_value_set_boxed (value, _gcr_gnupg_importer_get_imported (self));
		break;
	case PROP_DIRECTORY:
		g_value_set_string (value, _gcr_gnupg_process_get_directory (self->pv->process));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
_gcr_gnupg_importer_class_init (GcrGnupgImporterClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckAttributes *registered;

	gobject_class->dispose = _gcr_gnupg_importer_dispose;
	gobject_class->finalize = _gcr_gnupg_importer_finalize;
	gobject_class->set_property = _gcr_gnupg_importer_set_property;
	gobject_class->get_property = _gcr_gnupg_importer_get_property;

	g_type_class_add_private (gobject_class, sizeof (GcrGnupgImporterPrivate));

	g_object_class_override_property (gobject_class, PROP_LABEL, "label");

	g_object_class_override_property (gobject_class, PROP_ICON, "icon");

	g_object_class_install_property (gobject_class, PROP_IMPORTED,
	           g_param_spec_boxed ("imported", "Imported", "Fingerprints of imported keys",
	                               G_TYPE_STRV, G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_DIRECTORY,
	           g_param_spec_string ("directory", "Directory", "Directory to import keys to",
	                                NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	registered = gck_attributes_new ();
	gck_attributes_add_ulong (registered, CKA_CLASS, CKO_GCR_GNUPG_RECORDS);
	gcr_importer_register (GCR_TYPE_GNUPG_IMPORTER, registered);
	gck_attributes_unref (registered);

	_gcr_initialize_library ();
}

static GList *
_gcr_gnupg_importer_create_for_parsed (GcrParser *parser)
{
	GcrImporter *self;

	if (gcr_parser_get_parsed_format (parser) != GCR_FORMAT_OPENPGP_PACKET)
		return FALSE;

	self = _gcr_gnupg_importer_new (NULL);
	if (!gcr_importer_queue_for_parsed (self, parser))
		g_assert_not_reached ();

	return g_list_append (NULL, self);
}

static gboolean
_gcr_gnupg_importer_queue_for_parsed (GcrImporter *importer,
                                      GcrParser *parser)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (importer);
	gconstpointer block;
	gsize n_block;

	if (gcr_parser_get_parsed_format (parser) != GCR_FORMAT_OPENPGP_PACKET)
		return FALSE;

	block = gcr_parser_get_parsed_block (parser, &n_block);
	g_return_val_if_fail (block, FALSE);

	g_memory_input_stream_add_data (self->pv->packets, g_memdup (block, n_block),
	                                n_block, g_free);
	return TRUE;
}

static void
on_process_run_complete (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GSimpleAsyncResult *res = G_SIMPLE_ASYNC_RESULT (user_data);
	GError *error = NULL;

	if (!_gcr_gnupg_process_run_finish (GCR_GNUPG_PROCESS (source), result, &error))
		g_simple_async_result_take_error (res, error);

	g_simple_async_result_complete (res);
	g_object_unref (res);
}

static void
_gcr_gnupg_importer_import_async (GcrImporter *importer,
                                  GCancellable *cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
	GcrGnupgImporter *self = GCR_GNUPG_IMPORTER (importer);
	GSimpleAsyncResult *res;
	const gchar *argv[] = { "--import", NULL };

	res = g_simple_async_result_new (G_OBJECT (importer), callback, user_data,
	                                 _gcr_gnupg_importer_import_async);

	_gcr_gnupg_process_run_async (self->pv->process, argv, NULL,
	                              GCR_GNUPG_PROCESS_WITH_STATUS,
	                              cancellable, on_process_run_complete,
	                              g_object_ref (res));

	g_object_unref (res);
}

static gboolean
_gcr_gnupg_importer_import_finish (GcrImporter *importer,
                                   GAsyncResult *result,
                                   GError **error)
{
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (importer),
	                      _gcr_gnupg_importer_import_async), FALSE);

	if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (result), error))
		return FALSE;

	return TRUE;
}

static void
gcr_gnupg_importer_iface (GcrImporterIface *iface)
{
	iface->create_for_parsed = _gcr_gnupg_importer_create_for_parsed;
	iface->queue_for_parsed = _gcr_gnupg_importer_queue_for_parsed;
	iface->import_async = _gcr_gnupg_importer_import_async;
	iface->import_finish = _gcr_gnupg_importer_import_finish;
}

GcrImporter *
_gcr_gnupg_importer_new (const gchar *directory)
{
	return g_object_new (GCR_TYPE_GNUPG_IMPORTER,
	                     "directory", directory,
	                     NULL);
}

const gchar **
_gcr_gnupg_importer_get_imported (GcrGnupgImporter *self)
{
	g_return_val_if_fail (GCR_IS_GNUPG_IMPORTER (self), NULL);
	return (const gchar **)self->pv->imported->data;
}
