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

#include "gcr-import-interaction.h"

/**
 * SECTION:gcr-importer
 * @title: GcrImporter
 * @short_description: Import certificates and keys
 *
 * An interface which allows importing of certificates and keys. Each
 * #GcrImporter is registered with a set of PKCS\#11 attributes to match
 * stuff that it can import.
 *
 * An importer gets passed a #GcrParser and accesses the currently parsed
 * item. To create a set of importers that can import the currently parsed
 * item in a #GcrParser, use gcr_importer_create_for_parsed(). The list of
 * importers returned has the parsed item queued for import.
 *
 * To queue additional items with a importer use gcr_importer_queue_for_parsed().
 * In addition you can try and queue an additional item with a set of importers
 * using the gcr_importer_queue_and_filter_for_parsed().
 *
 * To start the import use gcr_importer_import() or the async variants.
 */

/**
 * GcrImporter:
 *
 * Imports certificates and keys
 */

/**
 * GcrImporterIface:
 * @parent: parent interface
 * @create_for_parsed: implementation of gcr_importer_create_for_parsed(), required
 * @queue_for_parsed: implementation of gcr_importer_queue_for_parsed(), required
 * @import_sync: optional implemantionon of gcr_importer_import()
 * @import_async: implementation of gcr_importer_import_async(), required
 * @import_finish: implementation of gcr_importer_import_finish()
 *
 * Interface implemented for a #GcrImporter.
 */

typedef GcrImportInteractionIface GcrImportInteractionInterface;

G_DEFINE_INTERFACE (GcrImportInteraction, gcr_import_interaction, G_TYPE_TLS_INTERACTION);

static void
gcr_import_interaction_default_init (GcrImportInteractionIface *iface)
{
	static volatile gsize initialized = 0;

	if (g_once_init_enter (&initialized)) {
		g_once_init_leave (&initialized, 1);
	}
}

/**
 * gcr_import_interaction_supplement_prep:
 * @interaction: the interaction
 * @attributes: attributes to supplement
 *
 * Prepare for supplementing the given attributes before import. This means
 * prompting the user for things like labels and the like. The attributes
 * will contain attributes for values that the importer needs, either empty
 * or prefilled with suggested values.
 *
 * This method does not prompt the user, but rather just prepares the
 * interaction that these are the attributes that are needed.
 */
void
gcr_import_interaction_supplement_prep (GcrImportInteraction *interaction,
                                        GckAttributes *attributes)
{
	GcrImportInteractionIface *iface;

	g_return_if_fail (GCR_IS_IMPORT_INTERACTION (interaction));
	g_return_if_fail (attributes != NULL);

	iface = GCR_IMPORT_INTERACTION_GET_INTERFACE (interaction);
	if (iface->supplement != NULL)
		(iface->supplement_prep) (interaction, attributes);
}

/**
 * gcr_import_interaction_supplement:
 * @interaction: the interaction
 * @attributes: supplemented attributes
 * @cancellable: optional cancellable object
 * @error: location to store error on failure
 *
 * Supplement attributes before import. This means prompting the user for
 * things like labels and the like. The needed attributes will have been passed
 * to gcr_import_interaction_supplement_prep().
 *
 * This method prompts the user and fills in the attributes. If the user or
 * cancellable cancels the operation the error should be set with %G_IO_ERROR_CANCELLED.
 *
 * Returns: %G_TLS_INTERACTION_HANDLED if successful or %G_TLS_INTERACTION_FAILED
 */
GTlsInteractionResult
gcr_import_interaction_supplement (GcrImportInteraction *interaction,
                                   GckAttributes *attributes,
                                   GCancellable *cancellable,
                                   GError **error)
{
	GcrImportInteractionIface *iface;

	g_return_val_if_fail (GCR_IS_IMPORT_INTERACTION (interaction), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (attributes != NULL, G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (error == NULL || *error == NULL, G_TLS_INTERACTION_UNHANDLED);

	iface = GCR_IMPORT_INTERACTION_GET_INTERFACE (interaction);
	g_return_val_if_fail (iface->supplement != NULL, G_TLS_INTERACTION_UNHANDLED);

	return (iface->supplement) (interaction, attributes, cancellable, error);
}


/**
 * gcr_import_interaction_supplement_async:
 * @interaction: the interaction
 * @attributes: supplemented attributes
 * @cancellable: optional cancellable object
 * @callback: called when the operation completes
 * @user_data: data to be passed to the callback
 *
 * Asynchronously supplement attributes before import. This means prompting the
 * user for things like labels and the like. The needed attributes will have
 * been passed to gcr_import_interaction_supplement_prep().
 *
 * This method prompts the user and fills in the attributes.
 */
void
gcr_import_interaction_supplement_async (GcrImportInteraction *interaction,
                                         GckAttributes *attributes,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	GcrImportInteractionIface *iface;

	g_return_if_fail (GCR_IS_IMPORT_INTERACTION (interaction));
	g_return_if_fail (attributes != NULL);
	g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

	iface = GCR_IMPORT_INTERACTION_GET_INTERFACE (interaction);
	g_return_if_fail (iface->supplement != NULL);

	(iface->supplement_async) (interaction, attributes, cancellable, callback, user_data);
}

/**
 * gcr_import_interaction_supplement_finish:
 * @interaction: the interaction
 * @result: the asynchronous result
 * @error: location to place an error on failure
 *
 * Complete operation to asynchronously supplement attributes before import.
 *
 * If the user or cancellable cancels the operation the error should be set
 * with %G_IO_ERROR_CANCELLED.
 *
 * Returns: %G_TLS_INTERACTION_HANDLED if successful or %G_TLS_INTERACTION_FAILED
 */
GTlsInteractionResult
gcr_import_interaction_supplement_finish (GcrImportInteraction *interaction,
                                          GAsyncResult *result,
                                          GError **error)
{
	GcrImportInteractionIface *iface;

	g_return_val_if_fail (GCR_IS_IMPORT_INTERACTION (interaction), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (G_IS_ASYNC_RESULT (result), G_TLS_INTERACTION_UNHANDLED);
	g_return_val_if_fail (error == NULL || *error == NULL, G_TLS_INTERACTION_UNHANDLED);

	iface = GCR_IMPORT_INTERACTION_GET_INTERFACE (interaction);
	g_return_val_if_fail (iface->supplement != NULL, G_TLS_INTERACTION_UNHANDLED);

	return (iface->supplement_finish) (interaction, result, error);
}
