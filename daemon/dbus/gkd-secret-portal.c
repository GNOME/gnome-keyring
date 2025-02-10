/*
 * gnome-keyring
 *
 * Copyright (C) 2019 Red Hat, Inc.
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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-portal.h"

#include <gck/gck.h>
#include "pkcs11/pkcs11i.h"
#include <gcrypt.h>

#include "gkd-portal-generated.h"
#include "gkd-portal-request-generated.h"
#include "gkd-secret-property.h"
#include "gkd-secret-service.h"
#include <gio/gunixfdlist.h>
#include <gio/gunixoutputstream.h>
#include <glib/gi18n.h>

#define PORTAL_DEFAULT_KEY_SIZE 64

static gboolean
portal_method_retrieve_secret (GkdExportedPortal *skeleton,
			       GDBusMethodInvocation *invocation,
			       GUnixFDList *fd_list,
			       const gchar *arg_handle,
			       const gchar *arg_app_id,
			       GVariant *arg_fd,
			       GVariant *arg_options,
			       GkdSecretPortal *self);

struct _GkdSecretPortal {
	GObject parent;
	GkdSecretService *service;
	GkdExportedPortal *skeleton;
	GkdExportedPortalRequest *request_skeleton;
	gchar *collection;
	GCancellable *cancellable;
};

G_DEFINE_TYPE (GkdSecretPortal, gkd_secret_portal, G_TYPE_OBJECT);

enum {
	PROP_0,
	PROP_SERVICE
};

static char *
get_default_collection ()
{
	char *default_path = NULL;
	char *contents = NULL;

	default_path = g_build_filename (g_get_user_data_dir (),
	                                 "keyrings",
	                                 "default",
	                                 NULL);
	if (g_file_get_contents (default_path, &contents, NULL, NULL)) {
		g_strstrip (contents);
		if (!contents[0]) {
			g_free (contents);
			contents = NULL;
		}
	}

	g_free (default_path);

	return (contents != NULL)? contents : g_strdup ("login");
}

static void
gkd_secret_portal_init (GkdSecretPortal *self)
{
#if WITH_DEBUG
	const gchar *collection = g_getenv ("GNOME_KEYRING_TEST_LOGIN");
	if (collection && collection[0])
		self->collection = g_strdup (collection);
	else
#endif
		self->collection = get_default_collection ();
	self->cancellable = g_cancellable_new ();
}

static void
gkd_secret_portal_constructed (GObject *object)
{
	GkdSecretPortal *self = GKD_SECRET_PORTAL (object);
	GDBusConnection *connection = gkd_secret_service_get_connection (self->service);
	GError *error = NULL;

	self->skeleton = gkd_exported_portal_skeleton_new ();
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->skeleton),
					  connection,
					  PORTAL_SERVICE_PATH,
					  &error);

	if (error != NULL) {
		g_warning ("could not register portal interface service on session bus: %s", error->message);
		g_clear_error (&error);
	}

	g_signal_connect (self->skeleton, "handle-retrieve-secret",
			  G_CALLBACK (portal_method_retrieve_secret), self);

	G_OBJECT_CLASS (gkd_secret_portal_parent_class)->constructed (object);
}

static void
gkd_secret_portal_set_property (GObject      *object,
                                guint         prop_id,
                                const GValue *value,
                                GParamSpec   *pspec)
{
	GkdSecretPortal *self = GKD_SECRET_PORTAL (object);

	switch (prop_id) {
	case PROP_SERVICE:
		self->service = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_portal_get_property (GObject    *object,
                                guint       prop_id,
                                GValue     *value,
                                GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
gkd_secret_portal_finalize (GObject *object)
{
	GkdSecretPortal *self = GKD_SECRET_PORTAL (object);

	g_clear_object (&self->skeleton);
	g_clear_object (&self->request_skeleton);
	g_free (self->collection);
	g_object_unref (self->cancellable);

	G_OBJECT_CLASS (gkd_secret_portal_parent_class)->finalize (object);
}

static void
gkd_secret_portal_class_init (GkdSecretPortalClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->constructed = gkd_secret_portal_constructed;
	gobject_class->set_property = gkd_secret_portal_set_property;
	gobject_class->get_property = gkd_secret_portal_get_property;
	gobject_class->finalize = gkd_secret_portal_finalize;

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Secret Service",
				     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static gboolean
request_method_close (GkdExportedPortalRequest *skeleton,
		      GDBusMethodInvocation *invocation,
		      GkdSecretPortal *self)
{
	g_cancellable_cancel (self->cancellable);
	g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (skeleton));
	return TRUE;
}

static gboolean
create_application_attributes (const char *app_id,
                               GckBuilder *builder,
                               gboolean    add_xdg_schema)
{
	GVariantBuilder attributes;
	g_autoptr(GVariant) variant = NULL;

	g_variant_builder_init (&attributes, G_VARIANT_TYPE ("a{ss}"));
	g_variant_builder_add (&attributes, "{ss}", "app_id", app_id);
	if (add_xdg_schema) {
		g_variant_builder_add (&attributes, "{ss}", "xdg:schema", "org.freedesktop.portal.Secret");
	}
	variant = g_variant_builder_end (&attributes);

	return gkd_secret_property_parse_fields (variant, builder);
}

static gboolean
unlock_collection (GkdSecretPortal *self,
		   GckObject *collection,
		   GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *session;
	GckObject *object;

	session = gkd_secret_service_internal_pkcs11_session (self->service);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
	gck_builder_add_ulong (&builder, CKA_G_OBJECT,
			       gck_object_get_handle (collection));
	gck_builder_add_boolean (&builder, CKA_GNOME_TRANSIENT, TRUE);
	gck_builder_add_data (&builder, CKA_VALUE, NULL, 0);

	object = gck_session_create_object (session, gck_builder_end (&builder),
					    self->cancellable, error);
	if (object == NULL)
		return FALSE;
	g_object_unref (object);

	return TRUE;
}

static gboolean
ensure_collection (GkdSecretPortal *self,
		   GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckSession *session;
	GList *objects = NULL;
	g_autofree void *data = NULL;
	gsize n_data;
	gboolean retval = TRUE;

	/* Find login collection */
	session = gkd_secret_service_internal_pkcs11_session (self->service);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_COLLECTION);
	gck_builder_add_string (&builder, CKA_ID, self->collection);
	objects = gck_session_find_objects (session, gck_builder_end (&builder),
					    NULL, error);
	if (*error != NULL)
		return FALSE;
	if (objects == NULL) {
		g_set_error (error,
			     G_DBUS_ERROR,
			     G_DBUS_ERROR_FAILED,
			     "Collection %s doesn't exist",
			     self->collection);
		retval = FALSE;
		goto out;
	}

	/* Check if it is locked */
	data = gck_object_get_data (objects->data, CKA_G_LOCKED,
				    self->cancellable, &n_data, error);
	if (data == NULL) {
		retval = FALSE;
		goto out;
	}
	if (n_data != 1) {
		g_set_error (error,
			     G_DBUS_ERROR,
			     G_DBUS_ERROR_FAILED,
			     "couldn't check if %s is locked",
			     self->collection);
		retval = FALSE;
		goto out;
	}

	/* Unlock the collection if it is locked */
	if (*((CK_BBOOL*)data) == CK_TRUE)
		retval = unlock_collection (self, objects->data, error);

out:
	if (objects)
		gck_list_unref_free (objects);

	return retval;
}

static guint8 *
lookup_secret_value (GkdSecretPortal *self,
		     const char *app_id,
		     gsize *n_value,
		     GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *search;
	GckSession *session;
	g_autofree guint8 *data = NULL;
	gsize n_data;

	if (!create_application_attributes (app_id, &builder, FALSE)) {
		gck_builder_clear (&builder);
		g_set_error (error,
			     G_DBUS_ERROR,
			     G_DBUS_ERROR_FAILED,
			     "Invalid data in attributes argument");
		return NULL;
	}

	/* Find items matching the collection and fields */
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_SEARCH);
	gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);
	gck_builder_add_string (&builder, CKA_G_COLLECTION, self->collection);

	/* Create the search object */
	session = gkd_secret_service_internal_pkcs11_session (self->service);
	search = gck_session_create_object (session,
					    gck_builder_end (&builder),
					    NULL, error);
	if (search == NULL)
		return NULL;

	/* Get the matched item handles, and delete the search object */
	data = gck_object_get_data (search, CKA_G_MATCHED, NULL, &n_data, error);
	gck_object_destroy (search, NULL, NULL);
	g_object_unref (search);

	if (data == NULL)
		return NULL;

	if (n_data > 0) {
		/* Return the first matching item if any */
		GList *items;
		guint8 *value;

		/* Build a list of object handles */
		items = gck_objects_from_handle_array (session,
		                                       (gulong *) data,
		                                       n_data / sizeof (CK_OBJECT_HANDLE));

		value = gck_object_get_data (GCK_OBJECT (items->data),
					     CKA_VALUE,
					     NULL,
					     n_value,
					     error);
		gck_list_unref_free (items);
		return value;
	}

	return NULL;
}

static guint8 *
create_secret_value (GkdSecretPortal *self,
		     const char *app_id,
		     gsize *n_value,
		     GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckObject *item;
	GckSession *session;
	guint8 *value;
	g_autofree char *label = NULL;

	value = g_new0 (guint8, PORTAL_DEFAULT_KEY_SIZE);
	*n_value = PORTAL_DEFAULT_KEY_SIZE;

	gcry_randomize (value, *n_value, GCRY_STRONG_RANDOM);

	/* Create a new item */
	if (!create_application_attributes (app_id, &builder, TRUE)) {
		gck_builder_clear (&builder);
		g_free (value);
		g_set_error (error,
			     G_DBUS_ERROR,
			     G_DBUS_ERROR_FAILED,
			     "Invalid data in attributes argument");
		return NULL;
	}

    /* TRANSLATORS: '%s' is an application id, for example "org.gnome.Maps" */
	label = g_strdup_printf (_("Application key for %s"), app_id);
	gck_builder_add_string (&builder, CKA_LABEL, label);

	gck_builder_add_string (&builder, CKA_G_COLLECTION, self->collection);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_boolean (&builder, CKA_TOKEN, TRUE);
	gck_builder_add_data (&builder, CKA_VALUE, value, *n_value);

	session = gkd_secret_service_internal_pkcs11_session (self->service);
	item = gck_session_create_object (session,
					  gck_builder_end (&builder),
					  self->cancellable,
					  error);
	if (item == NULL) {
		g_free (value);
		return NULL;
	}
	g_object_unref (item);

	return value;
}

static gboolean
portal_method_retrieve_secret (GkdExportedPortal *skeleton,
			       GDBusMethodInvocation *invocation,
			       GUnixFDList *fd_list,
			       const gchar *arg_handle,
			       const gchar *arg_app_id,
			       GVariant *arg_fd,
			       GVariant *arg_options,
			       GkdSecretPortal *self)
{
	int idx, fd;
	GError *error = NULL;
	guint8 *value = NULL;
	gsize n_value = 0;
	GOutputStream *stream;
	GVariantBuilder builder;

	g_variant_get (arg_fd, "h", &idx);
	fd = g_unix_fd_list_get (fd_list, idx, NULL);

	g_clear_object (&self->request_skeleton);
	self->request_skeleton = gkd_exported_portal_request_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->request_skeleton),
					       g_dbus_method_invocation_get_connection (invocation),
					       arg_handle, &error)) {
		g_warning ("error exporting request: %s\n", error->message);
		g_clear_error (&error);
	} else {
		g_signal_connect (self->request_skeleton, "handle-close",
				  G_CALLBACK (request_method_close), self);
	}

	if (!ensure_collection (self, &error)) {
		g_clear_object (&self->request_skeleton);
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	value = lookup_secret_value (self, arg_app_id, &n_value, &error);
	if (error != NULL) {
		g_clear_object (&self->request_skeleton);
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}

	/* If secret is not found, create a new random key */
	if (value == NULL) {
		value = create_secret_value (self, arg_app_id, &n_value, &error);
		if (value == NULL) {
			g_clear_object (&self->request_skeleton);
			g_dbus_method_invocation_take_error (invocation, error);
			return TRUE;
		}
	}

	/* Write the secret value to the file descriptor */
	stream = g_unix_output_stream_new (fd, TRUE);
	if (!g_output_stream_write_all (stream, value, n_value, NULL, NULL, &error)) {
		g_free (value);
		g_object_unref (stream);
		g_dbus_method_invocation_take_error (invocation, error);
		return TRUE;
	}
	g_free (value);
	g_object_unref (stream);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	gkd_exported_portal_complete_retrieve_secret (skeleton,
						      invocation,
						      NULL,
						      0,
						      g_variant_builder_end (&builder));

	return TRUE;
}
