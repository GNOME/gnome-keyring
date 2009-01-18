/* 
 * gnome-keyring
 * 
 * Copyright (C) 2008 Stefan Walter
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

#include "gcr-importer.h"

enum {
	PROP_0,
	PROP_IMPORTER
};

enum {
	SIGNAL,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (GcrImporter, gcr_importer, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

/* -----------------------------------------------------------------------------
 * OBJECT 
 */


static GObject* 
gcr_importer_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GcrImporter *self = GCR_IMPORTER (G_OBJECT_CLASS (gcr_importer_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);	


	
	return G_OBJECT (self);
}

static void
gcr_importer_init (GcrImporter *self)
{

}

static void
gcr_importer_dispose (GObject *obj)
{
	GcrImporter *self = GCR_IMPORTER (obj);
    
	G_OBJECT_CLASS (gcr_importer_parent_class)->dispose (obj);
}

static void
gcr_importer_finalize (GObject *obj)
{
	GcrImporter *self = GCR_IMPORTER (obj);

	G_OBJECT_CLASS (gcr_importer_parent_class)->finalize (obj);
}

static void
gcr_importer_set_property (GObject *obj, guint prop_id, const GValue *value, 
                           GParamSpec *pspec)
{
	GcrImporter *self = GCR_IMPORTER (obj);
	
	switch (prop_id) {
	case PROP_IMPORTER:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_importer_get_property (GObject *obj, guint prop_id, GValue *value, 
                           GParamSpec *pspec)
{
	GcrImporter *self = GCR_IMPORTER (obj);
	
	switch (prop_id) {
	case PROP_IMPORTER:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_importer_class_init (GcrImporterClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gobject_class->constructor = gcr_importer_constructor;
	gobject_class->dispose = gcr_importer_dispose;
	gobject_class->finalize = gcr_importer_finalize;
	gobject_class->set_property = gcr_importer_set_property;
	gobject_class->get_property = gcr_importer_get_property;
    
	g_object_class_install_property (gobject_class, PROP_IMPORTER,
	           g_param_spec_pointer ("importer", "Importer", "Importer.", G_PARAM_READWRITE));
    
	signals[SIGNAL] = g_signal_new ("signal", GCR_TYPE_IMPORTER, 
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GcrImporterClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT, 
	                                G_TYPE_NONE, 0);
	
	_gcr_initialize ();
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GcrImporter*
gcr_importer_new (void)
{
	return g_object_new (GCR_TYPE_IMPORTER, NULL);
}

gboolean
gcr_importer_import_data (GcrImporter *self, const guchar *data, gsize n_data, 
                          GError *err)
{
	GckParser *parser;
	gulong parsed_conn;
	gulong auth_conn;
	gboolean ret;
	
	g_return_val_if_fail (GCR_IS_IMPORTER (self), FALSE);
	g_return_val_if_fail (data || !n_data, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	
	
	xxxx;
	
	
	/* 
	 * Parse to see if it's something that needs a password
	 *   if we can't prompt, 
	 *     return an error
	 * Possibly prompt, if password needed, with all information necessary
	 *   
	 */
	
	
	g_object_ref (self);
	
	parser = gcr_importer_get_parser (self);
	
	/* Listen in to the parser */
	g_object_ref (parser);
	parsed_conn = g_signal_connect (parser, "parsed-item", G_CALLBACK (parser_parsed_item), self);
	auth_conn = g_signal_connect (parser, "authenticate", G_CALLBACK (parser_authenticate), self);
	
	/* Feed the parser the data */
	ret = gcr_parser_parse_data (parser, data, n_data, err);
	
	/* Now we should have all the data ready, check if we should prompt... */
	/* Import data one by one into module */
	
	g_signal_handler_disconnect (parser, parsed_conn);
	g_signal_handler_disconnect (parser, auth_conn);
	g_object_unref (parser);
	
	g_object_unref (self);
	
	return ret;
}

gboolean
gcr_importer_import_file (GcrImporter *self, const gchar *filename, 
                          GError *err)
{
	gboolean ret;
	gchar *data;
	gsize n_data;
	
	g_return_val_if_fail (GCR_IS_IMPORTER (self), FALSE);
	g_return_val_if_fail (filename, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);
	
	if (!g_file_get_contents (filename, &data, &n_data, err))
		return FALSE;
	
	ret = gcr_importer_import_data (self, (const guchar*)data, n_data, error);
	g_free (data);
	
	return ret;
}
