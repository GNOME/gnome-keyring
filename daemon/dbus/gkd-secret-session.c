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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkd-secret-dispatch.h"
#include "gkd-secret-error.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"
#include "gkd-secret-types.h"
#include "gkd-secret-util.h"
#include "gkd-secrets-generated.h"

#include "egg/egg-dh.h"
#include "egg/egg-error.h"

#include "pkcs11/pkcs11i.h"

#include <string.h>

enum {
	PROP_0,
	PROP_CALLER,
	PROP_CALLER_EXECUTABLE,
	PROP_OBJECT_PATH,
	PROP_SERVICE
};

struct _GkdSecretSession {
	GObject parent;

	/* Information about this object */
	gchar *object_path;
	GkdSecretService *service;
	GkdOrgFreedesktopSecretSession *skeleton;
	gchar *caller_exec;
	gchar *caller;

	/* While negotiating with a prompt, set to private key */
	GckObject *private;

	/* Once negotiated set to key and mechanism */
	GckObject *key;
	CK_MECHANISM_TYPE mech_type;
};

static void gkd_secret_dispatch_iface (GkdSecretDispatchIface *iface);
G_DEFINE_TYPE_WITH_CODE (GkdSecretSession, gkd_secret_session, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GKD_SECRET_TYPE_DISPATCH, gkd_secret_dispatch_iface));

static guint unique_session_number = 0;

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

static void
take_session_key (GkdSecretSession *self, GckObject *key, CK_MECHANISM_TYPE mech)
{
	g_return_if_fail (!self->key);
	self->key = key;
	self->mech_type = mech;
}

static gboolean
aes_create_dh_keys (GckSession *session, const gchar *group,
                    GckObject **pub_key, GckObject **priv_key)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckAttributes *attrs;
	gconstpointer prime, base;
	gsize n_prime, n_base;
	GError *error = NULL;
	gboolean ret;

	if (!egg_dh_default_params_raw (group, &prime, &n_prime, &base, &n_base)) {
		g_warning ("couldn't load dh parameter group: %s", group);
		return FALSE;
	}

	gck_builder_add_data (&builder, CKA_PRIME, prime, n_prime);
	gck_builder_add_data (&builder, CKA_BASE, base, n_base);
	attrs = gck_attributes_ref_sink (gck_builder_end (&builder));

	/* Perform the DH key generation */
	ret = gck_session_generate_key_pair (session, CKM_DH_PKCS_KEY_PAIR_GEN, attrs, attrs,
	                                     pub_key, priv_key, NULL, &error);

	gck_attributes_unref (attrs);

	if (ret == FALSE) {
		g_warning ("couldn't generate dh key pair: %s", egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	return TRUE;
}

static gboolean
aes_derive_key (GckSession *session, GckObject *priv_key,
                gconstpointer input, gsize n_input, GckObject **aes_key)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GckMechanism mech;
	GckObject *dh_key;

	/*
	 * First we have to generate a secret key from the DH key. The
	 * length of this key depends on the size of our DH prime
	 */

	mech.type = CKM_DH_PKCS_DERIVE;
	mech.parameter = input;
	mech.n_parameter = n_input;

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_ulong (&builder, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
	dh_key = gck_session_derive_key_full (session, priv_key, &mech, gck_builder_end (&builder), NULL, &error);

	if (!dh_key) {
		g_warning ("couldn't derive key from dh key pair: %s", egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	/*
	 * Now use HKDF to generate our AES key.
	 */

	mech.type = CKM_G_HKDF_SHA256_DERIVE;
	mech.parameter = NULL;
	mech.n_parameter = 0;

	gck_builder_add_ulong (&builder, CKA_VALUE_LEN, 16UL);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_ulong (&builder, CKA_KEY_TYPE, CKK_AES);

	*aes_key = gck_session_derive_key_full (session, dh_key, &mech, gck_builder_end (&builder), NULL, &error);
	g_object_unref (dh_key);

	if (!*aes_key) {
		g_warning ("couldn't derive aes key from dh key: %s", egg_error_message (error));
		g_clear_error (&error);
		return FALSE;
	}

	return TRUE;
}

static gboolean
aes_negotiate (GkdSecretSession *self,
	       GVariant *input_variant,
	       GVariant **output_variant,
	       gchar **result,
	       GError **error_out)
{
	GckSession *session;
	GckObject *pub, *priv, *key;
	GError *error = NULL;
	gpointer output;
	gsize n_output;
        const gchar *input;
        gsize n_input;
	gboolean ret;

	session = gkd_secret_service_get_pkcs11_session (self->service, self->caller);
	g_return_val_if_fail (session, FALSE);

	if (!aes_create_dh_keys (session, "ietf-ike-grp-modp-1024", &pub, &priv)) {
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Failed to create necessary crypto keys.");
		return FALSE;
	}

	/* Get the output data */
	output = gck_object_get_data (pub, CKA_VALUE, NULL, &n_output, &error);
	gck_object_destroy (pub, NULL, NULL);
	g_object_unref (pub);

	if (output == NULL) {
		g_warning ("couldn't get public key DH value: %s", egg_error_message (error));
		g_clear_error (&error);
		g_object_unref (priv);
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Failed to retrieve necessary crypto keys.");
		return FALSE;
	}

        input = g_variant_get_fixed_array (input_variant, &n_input, sizeof (guint8));
	ret = aes_derive_key (session, priv, input, n_input, &key);

	gck_object_destroy (priv, NULL, NULL);
	g_object_unref (priv);

	if (ret == FALSE) {
		g_free (output);
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Failed to create necessary crypto key.");
		return FALSE;
	}

	take_session_key (self, key, CKM_AES_CBC_PAD);

	if (output_variant != NULL) {
		GVariantBuilder builder;

		g_variant_builder_init (&builder, G_VARIANT_TYPE ("ay"));
		g_variant_builder_add (&builder, "y", (const gchar *) output);
		*output_variant = g_variant_new_variant (g_variant_builder_end (&builder));
	}

	if (result != NULL) {
		*result = g_strdup (self->object_path);
	}

	g_free (output);

	return TRUE;
}

static gboolean
plain_negotiate (GkdSecretSession *self,
		 GVariant **output,
		 gchar **result,
		 GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GError *error = NULL;
	GckObject *key;
	GckSession *session;

	session = gkd_secret_service_get_pkcs11_session (self->service, self->caller);
	g_return_val_if_fail (session, FALSE);

	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);
	gck_builder_add_ulong (&builder, CKA_KEY_TYPE, CKK_G_NULL);

	key = gck_session_create_object (session, gck_builder_end (&builder), NULL, &error);

	if (key == NULL) {
		g_warning ("couldn't create null key: %s", egg_error_message (error));
		g_clear_error (&error);
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Failed to create necessary plain keys.");
		return FALSE;
	}

	take_session_key (self, key, CKM_G_NULL);

	if (output != NULL) {
		*output = g_variant_new_variant (g_variant_new_string (""));
	}

	if (result != NULL) {
		*result = g_strdup (self->object_path);
	}

	return TRUE;
}

/* -----------------------------------------------------------------------------
 * DBUS
 */
static gboolean
session_method_close (GkdOrgFreedesktopSecretSession *skeleton,
		      GDBusMethodInvocation *invocation,
		      GkdSecretSession *self)
{
	gkd_secret_service_close_session (self->service, self);
	gkd_org_freedesktop_secret_session_complete_close (skeleton, invocation);

	return TRUE;
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */
static GObject*
gkd_secret_session_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkdSecretSession *self = GKD_SECRET_SESSION (G_OBJECT_CLASS (gkd_secret_session_parent_class)->constructor(type, n_props, props));
	GError *error = NULL;

	g_return_val_if_fail (self, NULL);
	g_return_val_if_fail (self->caller, NULL);
	g_return_val_if_fail (self->service, NULL);

	/* Setup the path for the object */
	self->object_path = g_strdup_printf (SECRET_SESSION_PREFIX "/s%d", ++unique_session_number);

	self->skeleton = gkd_org_freedesktop_secret_session_skeleton_new ();
	g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (self->skeleton),
					  gkd_secret_service_get_connection (self->service),
					  self->object_path, &error);

	if (error != NULL) {
		g_warning ("could not register secret session on session bus: %s", error->message);
		g_error_free (error);
	}

	g_signal_connect (self->skeleton, "handle-close",
			  G_CALLBACK (session_method_close), self);

	return G_OBJECT (self);
}

static void
gkd_secret_session_init (GkdSecretSession *self)
{

}

static void
gkd_secret_session_dispose (GObject *obj)
{
	GkdSecretSession *self = GKD_SECRET_SESSION (obj);

	g_free (self->object_path);
	self->object_path = NULL;

	if (self->skeleton) {
		g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (self->skeleton));
		g_clear_object (&self->skeleton);
	}

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
		                              (gpointer*)&(self->service));
		self->service = NULL;
	}

	if (self->key) {
		g_object_unref (self->key);
		self->key = NULL;
	}

	G_OBJECT_CLASS (gkd_secret_session_parent_class)->dispose (obj);
}

static void
gkd_secret_session_finalize (GObject *obj)
{
	GkdSecretSession *self = GKD_SECRET_SESSION (obj);

	g_assert (!self->object_path);
	g_assert (!self->service);
	g_assert (!self->key);

	g_free (self->caller_exec);
	self->caller_exec = NULL;

	g_free (self->caller);
	self->caller = NULL;

	G_OBJECT_CLASS (gkd_secret_session_parent_class)->finalize (obj);
}

static void
gkd_secret_session_set_property (GObject *obj, guint prop_id, const GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretSession *self = GKD_SECRET_SESSION (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_return_if_fail (!self->caller);
		self->caller = g_value_dup_string (value);
		break;
	case PROP_CALLER_EXECUTABLE:
		g_return_if_fail (!self->caller_exec);
		self->caller_exec = g_value_dup_string (value);
		break;
	case PROP_SERVICE:
		g_return_if_fail (!self->service);
		self->service = g_value_get_object (value);
		g_return_if_fail (self->service);
		g_object_add_weak_pointer (G_OBJECT (self->service),
		                           (gpointer*)&(self->service));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_session_get_property (GObject *obj, guint prop_id, GValue *value,
                                 GParamSpec *pspec)
{
	GkdSecretSession *self = GKD_SECRET_SESSION (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_value_set_string (value, gkd_secret_session_get_caller (self));
		break;
	case PROP_CALLER_EXECUTABLE:
		g_value_set_string (value, gkd_secret_session_get_caller_executable (self));
		break;
	case PROP_OBJECT_PATH:
		g_value_set_pointer (value, self->object_path);
		break;
	case PROP_SERVICE:
		g_value_set_object (value, self->service);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkd_secret_session_class_init (GkdSecretSessionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkd_secret_session_constructor;
	gobject_class->dispose = gkd_secret_session_dispose;
	gobject_class->finalize = gkd_secret_session_finalize;
	gobject_class->set_property = gkd_secret_session_set_property;
	gobject_class->get_property = gkd_secret_session_get_property;

	g_object_class_install_property (gobject_class, PROP_CALLER,
		g_param_spec_string ("caller", "Caller", "DBus caller name",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_CALLER_EXECUTABLE,
		g_param_spec_string ("caller-executable", "Caller Executable", "Executable of caller",
		                     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_OBJECT_PATH,
	        g_param_spec_pointer ("object-path", "Object Path", "DBus Object Path",
		                      G_PARAM_READABLE));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this session",
		                     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
gkd_secret_dispatch_iface (GkdSecretDispatchIface *iface)
{
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkdSecretSession*
gkd_secret_session_new (GkdSecretService *service, const gchar *caller)
{
	g_return_val_if_fail (GKD_SECRET_IS_SERVICE (service), NULL);
	g_return_val_if_fail (caller, NULL);
	return g_object_new (GKD_SECRET_TYPE_SESSION,
	                     "caller", caller, "service", service, NULL);
}

gpointer
gkd_secret_session_begin (GkdSecretSession *self, const gchar *group,
                          gsize *n_output)
{
	GError *error = NULL;
	GckSession *session;
	GckObject *public;
	gpointer output;

	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), NULL);
	g_return_val_if_fail (group, NULL);
	g_return_val_if_fail (n_output, NULL);
	g_return_val_if_fail (self->private == NULL, NULL);

	session = gkd_secret_session_get_pkcs11_session (self);
	g_return_val_if_fail (session, NULL);

	if (!aes_create_dh_keys (session, group, &public, &self->private))
		return NULL;

	/* Get the output data */
	output = gck_object_get_data (public, CKA_VALUE, NULL, n_output, &error);
	gck_object_destroy (public, NULL, NULL);
	g_object_unref (public);

	if (output == NULL) {
		g_warning ("couldn't get public key DH value: %s", egg_error_message (error));
		g_clear_error (&error);
		return NULL;
	}

	return output;
}

gboolean
gkd_secret_session_complete (GkdSecretSession *self, gconstpointer peer,
                             gsize n_peer)
{
	GckSession *session;

	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), FALSE);
	g_return_val_if_fail (self->key == NULL, FALSE);

	session = gkd_secret_session_get_pkcs11_session (self);
	g_return_val_if_fail (session, FALSE);

	if (!aes_derive_key (session, self->private, peer, n_peer, &self->key))
		return FALSE;

	self->mech_type = CKM_AES_CBC_PAD;
	return TRUE;
}

gboolean
gkd_secret_session_handle_open (GkdSecretSession *self,
				const gchar *algorithm,
				GVariant *input,
				GVariant **output,
				gchar **result,
				GError **error)
{
	const GVariantType *variant_type;

	variant_type = g_variant_get_type (input);

	/* Plain transfers? just remove our session key */
	if (g_str_equal (algorithm, "plain")) {
		if (!g_variant_type_equal (variant_type, G_VARIANT_TYPE_STRING)) {
			g_set_error (error, G_DBUS_ERROR,
				     G_DBUS_ERROR_INVALID_ARGS,
				     "The session algorithm input argument (%s) was invalid",
				     algorithm);
			return FALSE;
		}

		return plain_negotiate (self, output, result, error);

	} else if (g_str_equal (algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7")) {
		if (!g_variant_type_equal (variant_type, G_VARIANT_TYPE_BYTESTRING)) {
			g_set_error (error, G_DBUS_ERROR,
                                     G_DBUS_ERROR_INVALID_ARGS,
                                     "The session algorithm input argument (%s) was invalid",
                                     algorithm);
			return FALSE;
		}

		return aes_negotiate (self, input, output, result, error);

	} else {
		g_set_error (error, G_DBUS_ERROR,
			     G_DBUS_ERROR_NOT_SUPPORTED,
			     "The algorithm '%s' is not supported", algorithm);
		return FALSE;
	}

	g_assert_not_reached ();
}


const gchar*
gkd_secret_session_get_caller (GkdSecretSession *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), NULL);
	return self->caller;
}

const gchar*
gkd_secret_session_get_caller_executable (GkdSecretSession *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), NULL);
	return self->caller_exec;
}

GckSession*
gkd_secret_session_get_pkcs11_session (GkdSecretSession *self)
{
	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), NULL);
	return gkd_secret_service_get_pkcs11_session (self->service, self->caller);
}

GkdSecretSecret*
gkd_secret_session_get_item_secret (GkdSecretSession *self, GckObject *item,
				    GError **error_out)
{
	GckMechanism mech = { 0UL, NULL, 0 };
	GckSession *session;
	gpointer value, iv;
	gsize n_value, n_iv;
	GError *error = NULL;

	g_assert (GCK_IS_OBJECT (self->key));

	session = gck_object_get_session (item);
	g_return_val_if_fail (session, NULL);

	if (self->mech_type == CKM_AES_CBC_PAD) {
		n_iv = 16;
		iv = g_malloc (n_iv);
		gcry_create_nonce (iv, n_iv);
	} else {
		n_iv = 0;
		iv = NULL;
	}

	mech.type = self->mech_type;
	mech.parameter = iv;
	mech.n_parameter = n_iv;

	value = gck_session_wrap_key_full (session, self->key, &mech, item, &n_value,
	                                   NULL, &error);

	if (error != NULL) {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN)) {
			g_set_error_literal (error_out, GKD_SECRET_ERROR,
					     GKD_SECRET_ERROR_IS_LOCKED,
					     "Cannot get secret of a locked object");
		} else {
			g_message ("couldn't wrap item secret: %s", egg_error_message (error));
			g_set_error_literal (error_out, G_DBUS_ERROR,
					     G_DBUS_ERROR_FAILED,
					     "Couldn't get item secret");
		}
		g_clear_error (&error);
		g_free (iv);
		return NULL;
	}

	return gkd_secret_secret_new_take_memory (self, iv, n_iv, value, n_value);
}

gboolean
gkd_secret_session_set_item_secret (GkdSecretSession *self, GckObject *item,
                                    GkdSecretSecret *secret, GError **error_out)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckMechanism mech;
	GckObject *object;
	GckSession *session;
	GError *error = NULL;
	GckAttributes *attrs;

	g_return_val_if_fail (GKD_SECRET_IS_SESSION (self), FALSE);
	g_return_val_if_fail (GCK_IS_OBJECT (item), FALSE);
	g_return_val_if_fail (secret, FALSE);

	g_assert (GCK_IS_OBJECT (self->key));

	/*
	 * By getting these attributes, and then using them in the unwrap,
	 * the unwrap won't generate a new object, but merely set the secret.
	 */

	attrs = gck_object_get (item, NULL, &error, CKA_ID, CKA_G_COLLECTION, GCK_INVALID);
	if (attrs == NULL) {
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Couldn't set item secret");
		g_clear_error (&error);
		return FALSE;
	}
	gck_builder_add_all (&builder, attrs);
	gck_attributes_unref (attrs);
	gck_builder_add_ulong (&builder, CKA_CLASS, CKO_SECRET_KEY);

	session = gkd_secret_service_get_pkcs11_session (self->service, self->caller);
	g_return_val_if_fail (session, FALSE);

	mech.type = self->mech_type;
	mech.parameter = secret->parameter;
	mech.n_parameter = secret->n_parameter;

	object = gck_session_unwrap_key_full (session, self->key, &mech, secret->value,
	                                      secret->n_value, gck_builder_end (&builder), NULL, &error);

	if (object == NULL) {
		if (g_error_matches (error, GCK_ERROR, CKR_USER_NOT_LOGGED_IN)) {
			g_set_error_literal (error_out, GKD_SECRET_ERROR,
					     GKD_SECRET_ERROR_IS_LOCKED,
					     "Cannot set secret of a locked item");
		} else if (g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_INVALID) ||
		           g_error_matches (error, GCK_ERROR, CKR_WRAPPED_KEY_LEN_RANGE) ||
		           g_error_matches (error, GCK_ERROR, CKR_MECHANISM_PARAM_INVALID)) {
			g_set_error_literal (error_out, G_DBUS_ERROR,
					     G_DBUS_ERROR_INVALID_ARGS,
					     "The secret was transferred or encrypted in an invalid way.");
		} else {
			g_message ("couldn't unwrap item secret: %s", egg_error_message (error));
			g_set_error_literal (error_out, G_DBUS_ERROR,
					     G_DBUS_ERROR_FAILED,
					     "Couldn't set item secret");
		}
		g_clear_error (&error);
		return FALSE;
	}

	if (!gck_object_equal (object, item)) {
		g_warning ("unwrapped secret went to new object, instead of item");
		g_set_error_literal (error_out, G_DBUS_ERROR,
				     G_DBUS_ERROR_FAILED,
				     "Couldn't set item secret");
		g_object_unref (object);
		return FALSE;
	}

	g_object_unref (object);
	return TRUE;
}

GckObject*
gkd_secret_session_create_credential (GkdSecretSession *self,
                                      GckSession *session,
                                      GckAttributes *attrs,
                                      GkdSecretSecret *secret,
                                      GError **error)
{
	GckBuilder builder = GCK_BUILDER_INIT;
	GckAttributes *alloc = NULL;
	GckMechanism mech;
	GckObject *object;

	g_assert (GCK_IS_OBJECT (self->key));
	g_assert (attrs != NULL);

	if (session == NULL)
		session = gkd_secret_service_get_pkcs11_session (self->service, self->caller);
	g_return_val_if_fail (session, NULL);

	if (attrs == NULL) {
		gck_builder_add_ulong (&builder, CKA_CLASS, CKO_G_CREDENTIAL);
		gck_builder_add_boolean (&builder, CKA_TOKEN, FALSE);
		alloc = attrs = gck_attributes_ref_sink (gck_builder_end (&builder));
	}

	mech.type = self->mech_type;
	mech.parameter = secret->parameter;
	mech.n_parameter = secret->n_parameter;

	object = gck_session_unwrap_key_full (session, self->key, &mech, secret->value,
	                                      secret->n_value, attrs, NULL, error);

	gck_attributes_unref (alloc);

	return object;
}
