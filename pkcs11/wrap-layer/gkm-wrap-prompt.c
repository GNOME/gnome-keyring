/*
 * gnome-keyring
 *
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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-wrap-login.h"
#include "gkm-wrap-prompt.h"

#include "egg/egg-error.h"
#include "egg/egg-secure-memory.h"

#include "gkm/gkm-attributes.h"
#include "gkm/gkm-log.h"
#include "gkm/gkm-util.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11i.h"

#include <gcr/gcr-base.h>

#include <glib/gi18n.h>

#include <string.h>

EGG_SECURE_DECLARE (wrap_prompt);

#define GKM_TYPE_WRAP_PROMPT               (gkm_wrap_prompt_get_type ())
#define GKM_WRAP_PROMPT(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKM_TYPE_WRAP_PROMPT, GkmWrapPrompt))
#define GKM_WRAP_PROMPT_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), GKM_TYPE_WRAP_PROMPT, GkmWrapPromptClass))
#define GKM_IS_WRAP_PROMPT(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKM_TYPE_WRAP_PROMPT))
#define GKM_IS_WRAP_PROMPT_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), GKM_TYPE_WRAP_PROMPT))
#define GKM_WRAP_PROMPT_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), GKM_TYPE_WRAP_PROMPT, GkmWrapPromptClass))

GType   gkm_wrap_prompt_get_type           (void);

typedef struct _GkmWrapPromptClass GkmWrapPromptClass;

struct _GkmWrapPromptClass {
	GcrSystemPromptClass parent_class;
};

struct _GkmWrapPrompt {
	GcrSystemPrompt parent;
	gboolean initialized;

	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;

	gpointer prompt_data;
	GDestroyNotify destroy_data;

	guint iteration;
	GQueue pool;
};

G_DEFINE_TYPE (GkmWrapPrompt, gkm_wrap_prompt, GCR_TYPE_SYSTEM_PROMPT);

static const gchar *the_prompter_name = NULL;

/* -----------------------------------------------------------------------------
 * UTILITIES
 */

static gpointer
pool_alloc (GkmWrapPrompt *self, gsize length)
{
	gpointer memory = g_malloc0 (length);

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_queue_push_tail (&self->pool, memory);
	return memory;
}

static gpointer
pool_dup (GkmWrapPrompt *self, gconstpointer original, gsize length)
{
	gpointer memory = pool_alloc (self, length);
	memcpy (memory, original, length);
	return memory;
}

/* -----------------------------------------------------------------------------
 * AUTO UNLOCK
 */

static gboolean
is_login_keyring (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	gboolean is_login = FALSE;
	if (!gkm_attributes_find_boolean (attrs, n_attrs, CKA_G_LOGIN_COLLECTION, &is_login))
		return FALSE;
	return is_login;
}

static gchar*
auto_unlock_keyring_location (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ATTRIBUTE_PTR attr;

	if (is_login_keyring (attrs, n_attrs))
		return NULL;

	attr = gkm_attributes_find (attrs, n_attrs, CKA_ID);
	if (attr == NULL)
		return NULL;

	/*
	 * COMPAT: Format it into a string. This is done this way for compatibility
	 * with old gnome-keyring releases. In the future this may change.
	 */

	return g_strdup_printf ("LOCAL:/keyrings/%s.keyring", (gchar*)attr->pValue);
}

static gchar*
auto_unlock_object_unique (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ATTRIBUTE_PTR attr;

	attr = gkm_attributes_find (attrs, n_attrs, CKA_GNOME_UNIQUE);
	if (attr == NULL)
		return NULL;

	return g_strndup (attr->pValue, attr->ulValueLen);
}

static void
convert_upper_case (gchar *str)
{
	for (; *str; ++str)
		*str = g_ascii_toupper (*str);
}

static gchar*
auto_unlock_object_digest (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_ATTRIBUTE_PTR attr;
	gchar *result;

	attr = gkm_attributes_find (attrs, n_attrs, CKA_GNOME_INTERNAL_SHA1);
	if (attr == NULL)
		return NULL;

	result = g_strndup (attr->pValue, attr->ulValueLen);
	convert_upper_case (result);
	return result;
}

static gchar*
auto_unlock_lookup_keyring (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	gchar *location;
	gchar *password;

	location = auto_unlock_keyring_location (attrs, n_attrs);
	if (location == NULL)
		return NULL;

	password = gkm_wrap_login_lookup_secret ("keyring", location, NULL);
	g_free (location);
	return password;
}


static gchar*
auto_unlock_lookup_object (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_OBJECT_CLASS klass;
	gchar *value;
	gchar *password;

	if (!gkm_attributes_find_ulong (attrs, n_attrs, CKA_CLASS, &klass))
		return NULL;

	if (klass == CKO_G_COLLECTION)
		return auto_unlock_lookup_keyring (attrs, n_attrs);

	value = auto_unlock_object_unique (attrs, n_attrs);
	if (value != NULL) {
		password = gkm_wrap_login_lookup_secret ("unique", value, NULL);
		g_free (value);
		if (password)
			return password;
	}

	/* COMPAT: Check old method of storing secrets for objects in login keyring */
	value = auto_unlock_object_digest (attrs, n_attrs);
	if (value != NULL) {
		password = gkm_wrap_login_lookup_secret ("object-digest", value, NULL);
		g_free (value);
		if (password)
			return password;
	}

	return NULL;
}

static gchar*
auto_unlock_lookup_token (CK_TOKEN_INFO_PTR info)
{
	gchar *password = NULL;
	gchar *manufacturer;
	gchar *serial;

	g_assert (info);

	manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
	g_strchomp (manufacturer);

	serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
	g_strchomp (serial);

	if (!g_str_equal (manufacturer, "") && !g_str_equal (serial, ""))
		password = gkm_wrap_login_lookup_secret ("manufacturer", manufacturer,
		                                         "serial-number", serial,
		                                         NULL);

	g_free (manufacturer);
	g_free (serial);

	return password;
}

static gboolean
auto_unlock_should_attach (GkmWrapPrompt *self)
{
	return gcr_prompt_get_choice_chosen (GCR_PROMPT (self));
}

static void
auto_unlock_attach_keyring (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, const gchar *password)
{
	gchar *location;
	gchar *label;

	if (!password)
		return;

	location = auto_unlock_keyring_location (attrs, n_attrs);
	if (location == NULL)
		return;

	if (!gkm_attributes_find_string (attrs, n_attrs, CKA_LABEL, &label))
		if (!gkm_attributes_find_string (attrs, n_attrs, CKA_ID, &label))
			label = g_strdup (location);

	gkm_wrap_login_attach_secret (label, password, "keyring", location, NULL);
	g_free (location);
	g_free (label);
}

static void
auto_unlock_attach_object (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs, const gchar *password)
{
	CK_OBJECT_CLASS klass;
	gchar *label;
	gchar *unique;

	if (!password)
		return;

	if (!gkm_attributes_find_ulong (attrs, n_attrs, CKA_CLASS, &klass))
		return;

	if (klass == CKO_G_COLLECTION) {
		auto_unlock_attach_keyring (attrs, n_attrs, password);
		return;
	}

	unique = auto_unlock_object_unique (attrs, n_attrs);
	if (unique == NULL)
		return;

	if (!gkm_attributes_find_string (attrs, n_attrs, CKA_LABEL, &label))
		label = g_strdup (unique);

	gkm_wrap_login_attach_secret (label, password, "unique", unique, NULL);
	g_free (unique);
	g_free (label);
}

static void
auto_unlock_attach_token (CK_TOKEN_INFO_PTR info, const gchar *password)
{
	gchar *manufacturer;
	gchar *serial;
	gchar *label;

	g_assert (info);

	if (!password)
		return;

	manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
	g_strchomp (manufacturer);

	serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
	g_strchomp (serial);

	label = g_strndup ((gchar*)info->label, sizeof (info->label));
	g_strchomp (label);

	if (g_str_equal (label, "")) {
		g_free (label);
		label = g_strdup (manufacturer);
	}

	if (!g_str_equal (manufacturer, "") && !g_str_equal (serial, ""))
		gkm_wrap_login_attach_secret (label, password,
		                              "manufacturer", manufacturer,
		                              "serial-number", serial,
		                              NULL);

	g_free (manufacturer);
	g_free (serial);
	g_free (label);
}

static void
auto_unlock_remove_keyring (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	gchar *location;

	location = auto_unlock_keyring_location (attrs, n_attrs);
	if (location == NULL)
		return;

	gkm_wrap_login_remove_secret ("keyring", location, NULL);
	g_free (location);
}

static void
auto_unlock_remove_object (CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
	CK_OBJECT_CLASS klass;
	gchar *value;

	if (!gkm_attributes_find_ulong (attrs, n_attrs, CKA_CLASS, &klass))
		return;

	if (klass == CKO_G_COLLECTION) {
		auto_unlock_remove_keyring (attrs, n_attrs);
		return;
	}

	value = auto_unlock_object_unique (attrs, n_attrs);
	if (value != NULL) {
		gkm_wrap_login_remove_secret ("unique", value, NULL);
		g_free (value);
	}

	/* COMPAT: Clear old method of storing secrets for objects in login keyring */
	value = auto_unlock_object_digest (attrs, n_attrs);
	if (value != NULL) {
		gkm_wrap_login_remove_secret ("object-digest", value, NULL);
		g_free (value);
	}

}

static void
auto_unlock_remove_token (CK_TOKEN_INFO_PTR info)
{
	gchar *manufacturer;
	gchar *serial;

	g_assert (info);

	manufacturer = g_strndup ((gchar*)info->manufacturerID, sizeof (info->manufacturerID));
	g_strchomp (manufacturer);

	serial = g_strndup ((gchar*)info->serialNumber, sizeof (info->serialNumber));
	g_strchomp (serial);

	if (!g_str_equal (manufacturer, "") && !g_str_equal (serial, ""))
		gkm_wrap_login_remove_secret ("manufacturer", manufacturer,
		                              "serial-number", serial,
		                              NULL);

	g_free (manufacturer);
	g_free (serial);
}

/* -----------------------------------------------------------------------------------------
 * PROMPTING
 */

static void
set_unlock_options_on_object (GkmWrapPrompt *self, CK_ATTRIBUTE_PTR options, CK_ULONG n_options)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->module);
	g_assert (options);

	attr.type = CKA_G_CREDENTIAL_TEMPLATE;
	attr.pValue = options;
	attr.ulValueLen = sizeof (CK_ATTRIBUTE) * n_options;

	rv = (self->module->C_SetAttributeValue) (self->session, self->object, &attr, 1);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		if (rv != CKR_TOKEN_WRITE_PROTECTED)
			g_warning ("Couldn't set credential template for prompt: %s",
			           gkm_log_rv (rv));
	}
}

static CK_ATTRIBUTE_PTR
get_unlock_options_from_prompt (GkmWrapPrompt *self, CK_ULONG_PTR n_options)
{
	CK_ATTRIBUTE_PTR options;
	CK_BBOOL bval;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (n_options);

	*n_options = 2;
	options = pool_alloc (self, sizeof (CK_ATTRIBUTE) * (*n_options));

	/* CKA_TOKEN */
	bval = TRUE;
	options[0].type = CKA_TOKEN;
	options[0].pValue = pool_dup (self, &bval, sizeof (bval));
	options[0].ulValueLen = sizeof (bval);

	/* CKA_GNOME_TRANSIENT */
	bval = TRUE;
	options[1].type = CKA_GNOME_TRANSIENT;
	options[1].pValue = pool_dup (self, &bval, sizeof (bval));
	options[1].ulValueLen = sizeof (bval);

	return options;
}

static void
set_unlock_options_on_prompt (GkmWrapPrompt *self)
{
	gboolean chosen = FALSE;

	g_assert (GKM_IS_WRAP_PROMPT (self));

	gcr_prompt_set_choice_chosen (GCR_PROMPT (self), chosen);
}

static CK_ATTRIBUTE_PTR
get_attributes_from_object (GkmWrapPrompt *self, CK_ULONG *n_attrs)
{
	CK_ATTRIBUTE attrs[6];
	CK_ULONG i;
	CK_RV rv;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (n_attrs);
	g_assert (self->module);

	memset (attrs, 0, sizeof (attrs));
	attrs[0].type = CKA_LABEL;
	attrs[1].type = CKA_ID;
	attrs[2].type = CKA_CLASS;
	attrs[3].type = CKA_G_LOGIN_COLLECTION;
	attrs[4].type = CKA_GNOME_UNIQUE;
	attrs[5].type = CKA_GNOME_INTERNAL_SHA1;

	rv = (self->module->C_GetAttributeValue) (self->session, self->object, attrs, G_N_ELEMENTS (attrs));
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		g_warning ("Couldn't retrieve information about object to unlock: %s",
		           gkm_log_rv (rv));
		return NULL;
	}

	/* Allocate for each value, note we're null terminating values */
	for (i = 0; i < G_N_ELEMENTS (attrs); ++i) {
		if (attrs[i].ulValueLen != (CK_ULONG)-1)
			attrs[i].pValue = pool_alloc (self, attrs[i].ulValueLen + 1);
	}

	/* Now get the actual values */
	rv = (self->module->C_GetAttributeValue) (self->session, self->object, attrs, G_N_ELEMENTS (attrs));
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		g_warning ("couldn't retrieve credential template for prompt: %s",
		           gkm_log_rv (rv));
		return NULL;
	}

	*n_attrs = G_N_ELEMENTS (attrs);
	return pool_dup (self, attrs, sizeof (attrs));

}

static gboolean
get_info_for_token (GkmWrapPrompt *self, CK_TOKEN_INFO_PTR tinfo)
{
	CK_SESSION_INFO sinfo;

	return (self->module->C_GetSessionInfo) (self->session, &sinfo) == CKR_OK &&
	       (self->module->C_GetTokenInfo) (sinfo.slotID, tinfo) == CKR_OK;
}

static void
setup_unlock_keyring_login (GkmWrapPrompt *self)
{
	GcrPrompt *prompt;
	const gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));

	prompt = GCR_PROMPT (self);

	gcr_prompt_set_title (prompt, _("Unlock Login Keyring"));
	gcr_prompt_set_message (prompt, _("Authentication required"));

	if (gkm_wrap_login_did_unlock_fail ())
		text = _("The password you use to log in to your computer no longer matches that of your login keyring.");
	else
		text = _("The login keyring did not get unlocked when you logged into your computer.");
	gcr_prompt_set_description (prompt, text);

	gcr_prompt_set_choice_label (prompt, NULL);
	gcr_prompt_set_continue_label (prompt, _("Unlock"));
}

static void
setup_unlock_keyring_other (GkmWrapPrompt *self,
                            const gchar *label)
{
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	prompt = GCR_PROMPT (self);

	gcr_prompt_set_title (prompt, _("Unlock Keyring"));
	gcr_prompt_set_message (prompt, _("Authentication required"));

	text = g_markup_printf_escaped (_("An application wants access to the keyring “%s”, but it is locked"), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkm_wrap_login_is_usable ())
		choice = _("Automatically unlock this keyring whenever I’m logged in");
	gcr_prompt_set_choice_label (prompt, choice);
	gcr_prompt_set_continue_label (prompt, _("Unlock"));
}


static const gchar*
calc_unlock_object_title (CK_OBJECT_CLASS klass)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		return _("Unlock private key");
	case CKO_CERTIFICATE:
		return _("Unlock certificate");
	case CKO_PUBLIC_KEY:
		return _("Unlock public key");
	default:
		return _("Unlock");
	}
}

static const gchar *
calc_unlock_object_choice (CK_OBJECT_CLASS klass)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
		return _("Automatically unlock this key whenever I’m logged in");
	case CKO_CERTIFICATE:
		return _("Automatically unlock this certificate whenever I’m logged in");
	default:
		return _("Automatically unlock whenever I’m logged in");
	}
}

static gchar*
calc_unlock_object_secondary (CK_OBJECT_CLASS klass,
                              const gchar *label)
{
	switch (klass) {
	case CKO_PRIVATE_KEY:
		/* TRANSLATORS: The private key is locked */
		return g_strdup_printf (_("An application wants access to the private key “%s”, but it is locked"), label);
	case CKO_CERTIFICATE:
		/* TRANSLATORS: The certificate is locked */
		return g_strdup_printf (_("An application wants access to the certificate “%s”, but it is locked"), label);
	case CKO_PUBLIC_KEY:
		/* TRANSLATORS: The public key is locked */
		return g_strdup_printf (_("An application wants access to the public key “%s”, but it is locked"), label);
	default:
		/* TRANSLATORS: The object '%s' is locked */
		return g_strdup_printf (_("An application wants access to “%s”, but it is locked"), label);
	}
}

static void
setup_unlock_object (GkmWrapPrompt *self,
                     const gchar *label,
                     CK_OBJECT_CLASS klass)
{
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	prompt = GCR_PROMPT (self);

	gcr_prompt_set_title (prompt, calc_unlock_object_title (klass));
	gcr_prompt_set_message (prompt, _("Authentication required"));

	text = calc_unlock_object_secondary (klass, label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkm_wrap_login_is_usable ())
		choice = calc_unlock_object_choice (klass);
	gcr_prompt_set_choice_label (prompt, choice);
	gcr_prompt_set_continue_label (prompt, _("Unlock"));
}

static void
setup_unlock_prompt (GkmWrapPrompt *self,
                     CK_ATTRIBUTE_PTR attrs,
                     CK_ULONG n_attrs,
                     gboolean first)
{
	CK_ATTRIBUTE_PTR attr;
	GcrPrompt *prompt;
	const gchar *label = NULL;
	CK_OBJECT_CLASS klass;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	prompt = GCR_PROMPT (self);

	/* Load up the object class */
	if (!gkm_attributes_find_ulong (attrs, n_attrs, CKA_CLASS, &klass))
		klass = (CK_ULONG)-1;

	/* Load up its label */
	attr = gkm_attributes_find (attrs, n_attrs, CKA_LABEL);
	if (attr != NULL)
		label = attr->pValue;

	/* Load up the identifier */
	attr = gkm_attributes_find (attrs, n_attrs, CKA_ID);
	if (attr != NULL && !label)
		label = attr->pValue;

	if (!label)
		label = _("Unnamed");

	if (klass == CKO_G_COLLECTION) {
		if (is_login_keyring (attrs, n_attrs))
			setup_unlock_keyring_login (self);
		else
			setup_unlock_keyring_other (self, label);
	} else {
		setup_unlock_object (self, label, klass);
	}

	if (!first)
		gcr_prompt_set_warning (prompt, _("The unlock password was incorrect"));

	gcr_prompt_set_continue_label (prompt, _("Unlock"));
}

static void
setup_unlock_token (GkmWrapPrompt *self,
                    CK_TOKEN_INFO_PTR tinfo)
{
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *label;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	prompt = GCR_PROMPT (self);

	label = g_strndup ((gchar*)tinfo->label, sizeof (tinfo->label));
	g_strchomp (label);

	/* Build up the prompt */
	gcr_prompt_set_title (prompt, _("Unlock certificate/key storage"));
	gcr_prompt_set_message (prompt, _("Authentication required"));

	/* TRANSLATORS: The storage is locked, and needs unlocking before the application can use it. */
	text = g_strdup_printf (_("An application wants access to the certificate/key storage “%s”, but it is locked"), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkm_wrap_login_is_usable ())
		choice = _("Automatically unlock whenever I’m logged in");
	gcr_prompt_set_choice_label (prompt, choice);

	gcr_prompt_set_continue_label (prompt, _("Unlock"));

	g_free (label);
}

static void
fix_login_keyring_if_unlock_failed (GkmWrapPrompt *self, const gchar *password)
{
	CK_OBJECT_CLASS klass = CKO_G_CREDENTIAL;
	CK_OBJECT_HANDLE cred;
	CK_BBOOL tval = CK_TRUE;
	CK_ATTRIBUTE attrs[4];
	gchar *failed;
	CK_RV rv;

	failed = gkm_wrap_login_steal_failed_password ();

	/* Do we have a failed unlock password? */
	if (!failed || !failed[0]) {
		egg_secure_strfree (failed);
		return;
	}

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &klass;
	attrs[0].ulValueLen = sizeof (klass);

	attrs[1].type = CKA_VALUE;
	attrs[1].pValue = failed;
	attrs[1].ulValueLen = strlen (failed);

	attrs[2].type = CKA_GNOME_TRANSIENT;
	attrs[2].pValue = &tval;
	attrs[2].ulValueLen = sizeof (tval);

	attrs[3].type = CKA_TOKEN;
	attrs[3].pValue = &tval;
	attrs[3].ulValueLen = sizeof (tval);

	/* Create a credential object for the failed password */
	rv = (self->module->C_CreateObject) (self->session, attrs, G_N_ELEMENTS (attrs), &cred);
	egg_secure_strfree (failed);

	if (rv != CKR_OK) {
		g_warning ("couldn't create credential to fix login password: %s",
		           gkm_log_rv (rv));
		return;
	}

	attrs[0].type = CKA_G_CREDENTIAL;
	attrs[0].pValue = &cred;
	attrs[0].ulValueLen = sizeof (cred);

	/* Set the credential on the object */
	rv = (self->module->C_SetAttributeValue) (self->session, self->object, attrs, 1);
	if (rv != CKR_OK) {
		g_warning ("couldn't change credential to fix login keyring password: %s",
		           gkm_log_rv (rv));
		return;
	}

	g_message ("fixed login keyring password to match login password");
}

static gboolean
gkm_wrap_prompt_prepare (GkmWrapPrompt *self)
{
	GError *error = NULL;

	if (!self->initialized) {
		if (!g_initable_init (G_INITABLE (self), NULL, &error)) {
			g_warning ("couldn't create system prompt: %s", egg_error_message (error));
			g_error_free (error);
			return FALSE;
		}
		self->initialized = TRUE;
	}

	return TRUE;
}

static const gchar *
gkm_wrap_prompt_request_password (GkmWrapPrompt *self)
{
	GError *error = NULL;
	const gchar *password;

	g_assert (GKM_IS_WRAP_PROMPT (self));

	if (!gkm_wrap_prompt_prepare (self))
		return NULL;

	password = gcr_prompt_password (GCR_PROMPT (self), NULL, &error);
	if (error != NULL) {
		g_warning ("couldn't prompt for password: %s", egg_error_message (error));
		g_error_free (error);
	}

	return password;
}

static void
gkm_wrap_prompt_init (GkmWrapPrompt *self)
{
	g_queue_init (&self->pool);
}

static void
gkm_wrap_prompt_clear_prompt_data (GkmWrapPrompt *self)
{
	if (self->destroy_data && self->prompt_data)
		(self->destroy_data) (self->prompt_data);
	self->destroy_data = NULL;
	self->prompt_data = NULL;
}

static void
gkm_wrap_prompt_set_prompt_data (GkmWrapPrompt *self,
				 gpointer prompt_data,
				 GDestroyNotify destroy_data)
{
	gkm_wrap_prompt_clear_prompt_data (self);
	self->destroy_data = destroy_data;
	self->prompt_data = prompt_data;
}

static void
gkm_wrap_prompt_finalize (GObject *obj)
{
	GkmWrapPrompt *self = GKM_WRAP_PROMPT (obj);

	gkm_wrap_prompt_clear_prompt_data (self);

	while (!g_queue_is_empty(&self->pool))
		g_free (g_queue_pop_head (&self->pool));

	G_OBJECT_CLASS (gkm_wrap_prompt_parent_class)->finalize (obj);
}


static void
gkm_wrap_prompt_class_init (GkmWrapPromptClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	gobject_class->finalize = gkm_wrap_prompt_finalize;
}

/* -----------------------------------------------------------------------------
 * CREDENTIAL
 */

typedef struct _CredentialPrompt {
	GArray *template;
	CK_ULONG n_template;
	gchar *password;
} CredentialPrompt;

static void
credential_prompt_free (gpointer user_data)
{
	CredentialPrompt *data = user_data;
	g_array_free (data->template, TRUE);
	egg_secure_strfree (data->password);
	g_slice_free (CredentialPrompt, data);
}

GkmWrapPrompt*
gkm_wrap_prompt_for_credential (CK_FUNCTION_LIST_PTR module, CK_SESSION_HANDLE session,
                                CK_ATTRIBUTE_PTR template, CK_ULONG n_template)
{
	CredentialPrompt *data;
	CK_ATTRIBUTE_PTR attr;
	CK_OBJECT_CLASS klass;
	CK_OBJECT_HANDLE object;
	GkmWrapPrompt *self;
	CK_ULONG i;

	g_return_val_if_fail (module, NULL);
	g_return_val_if_fail (session, NULL);
	g_return_val_if_fail (n_template || !template, NULL);

	/* Must be credential and have object for protected outh path */
	if (!gkm_attributes_find_ulong (template, n_template, CKA_CLASS, &klass) ||
	    !gkm_attributes_find_ulong (template, n_template, CKA_G_OBJECT, &object) ||
	    klass != CKO_G_CREDENTIAL || object == 0)
		return NULL;

	/* Must have CKA_VALUE with pValue set to null for protected auth path */
	attr = gkm_attributes_find (template, n_template, CKA_VALUE);
	if (attr == NULL || attr->pValue != NULL)
		return NULL;

	self = g_object_new (GKM_TYPE_WRAP_PROMPT,
	                     "timeout-seconds", -1,
	                     "bus-name", gkm_wrap_prompt_get_prompter_name (),
	                     NULL);

	/* Build up the prompt */
	data = g_slice_new0 (CredentialPrompt);
	gkm_wrap_prompt_set_prompt_data (self, data, credential_prompt_free);
	self->module = module;
	self->session = session;
	self->object = object;

	/* Build up a copy of the template with CKA_VALUE first */
	data->template = g_array_new (FALSE, FALSE, sizeof (CK_ATTRIBUTE));
	g_array_append_val (data->template, *attr);
	for (i = 0; i < n_template; ++i) {
		if (template[i].type != CKA_VALUE)
			g_array_append_val (data->template, template[i]);
	}

	data->n_template = n_template;

	return self;
}

gboolean
gkm_wrap_prompt_do_credential (GkmWrapPrompt *self, CK_ATTRIBUTE_PTR *template,
                               CK_ULONG *n_template)
{
	CK_ATTRIBUTE_PTR options;
	CK_ATTRIBUTE_PTR attrs;
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG n_attrs, n_options, i;
	CredentialPrompt *data;
	GError *error = NULL;

	g_return_val_if_fail (GKM_IS_WRAP_PROMPT (self), FALSE);
	g_return_val_if_fail (template, FALSE);
	g_return_val_if_fail (n_template, FALSE);

	g_assert (self->destroy_data == credential_prompt_free);
	data = self->prompt_data;

	attrs = get_attributes_from_object (self, &n_attrs);
	g_return_val_if_fail (attrs, FALSE);

	egg_secure_strfree (data->password);
	data->password = NULL;

	if (self->iteration == 0) {
		++(self->iteration);
		data->password = auto_unlock_lookup_object (attrs, n_attrs);

	} else if (self->iteration == 1) {
		auto_unlock_remove_object (attrs, n_attrs);
	}

	if (!data->password) {
		const char *password;
		setup_unlock_prompt (self, attrs, n_attrs, self->iteration == 1);

		/* Now load up the unlock options into the prompt*/
		if (self->iteration == 1)
			set_unlock_options_on_prompt (self);

		++(self->iteration);

		password = gkm_wrap_prompt_request_password (self);
		if (password == NULL) {
			if (error != NULL) {
				g_warning ("couldn't prompt for password: %s", egg_error_message (error));
				g_error_free (error);
			}
			return FALSE;
		}
		data->password = egg_secure_strdup (password);
	}

	/* Truncate any extra options off the end of template */
	g_assert (data->n_template > 0);
	g_assert (data->template->len >= data->n_template);
	g_array_set_size (data->template, data->n_template);

	/* Put the password into the template, always first */
	attr = &g_array_index (data->template, CK_ATTRIBUTE, 0);
	g_assert (attr->type == CKA_VALUE);
	attr->pValue = (gpointer)data->password;
	attr->ulValueLen = strlen (data->password);

	/* Tag any options onto the end of template */
	options = get_unlock_options_from_prompt (self, &n_options);
	for (i = 0; options && i < n_options; ++i)
		g_array_append_val (data->template, options[i]);

	*template = (CK_ATTRIBUTE_PTR)data->template->data;
	*n_template = data->template->len;
	return TRUE;
}

void
gkm_wrap_prompt_done_credential (GkmWrapPrompt *self, CK_RV call_result)
{
	CK_ATTRIBUTE_PTR options;
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_options, n_attrs;
	CredentialPrompt *data;

	g_return_if_fail (GKM_IS_WRAP_PROMPT (self));

	g_assert (self->destroy_data == credential_prompt_free);
	data = self->prompt_data;

	/* Save the options, and possibly auto unlock */
	if (call_result == CKR_OK) {

		attrs = get_attributes_from_object (self, &n_attrs);

		/*
		 * For the login keyring, we check for a previous unlock failure,
		 * that would have come from PAM, and try to change the password to
		 * the one that failed earlier.
		 */
		if (is_login_keyring (attrs, n_attrs))
			fix_login_keyring_if_unlock_failed (self, data->password);

		options = get_unlock_options_from_prompt (self, &n_options);
		if (options != NULL)
			set_unlock_options_on_object (self, options, n_options);

		if (auto_unlock_should_attach (self))
			auto_unlock_attach_object (attrs, n_attrs, data->password);
	}
}

/* ------------------------------------------------------------------------------------
 * INITPIN
 */

static void
setup_init_token (GkmWrapPrompt *self,
                  CK_TOKEN_INFO_PTR tinfo)
{
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *label;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (tinfo);

	prompt = GCR_PROMPT (self);

	label = g_strndup ((gchar*)tinfo->label, sizeof (tinfo->label));
	g_strchomp (label);

	/* Build up the prompt */
	gcr_prompt_set_password_new (prompt, TRUE);
	gcr_prompt_set_title (prompt, _("New Password Required"));
	gcr_prompt_set_message (prompt, _("New password required"));

	text = g_strdup_printf (_("In order to prepare “%s” for storage of certificates or keys, a password is required"), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkm_wrap_login_is_usable ())
		choice = _("Automatically unlock whenever I’m logged in");
	gcr_prompt_set_choice_label (prompt, choice);

	gcr_prompt_set_continue_label (prompt, _("Continue"));

	g_free (label);
}

GkmWrapPrompt*
gkm_wrap_prompt_for_init_pin (CK_FUNCTION_LIST_PTR module, CK_SESSION_HANDLE session,
                              CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	GkmWrapPrompt *self;

	g_assert (module != NULL);

	if (pin != NULL || pin_len != 0)
		return NULL;

	self = g_object_new (GKM_TYPE_WRAP_PROMPT,
	                     "timeout-seconds", -1,
	                     "bus-name", gkm_wrap_prompt_get_prompter_name (),
	                     NULL);

	/* Build up the prompt */
	self->module = module;
	self->session = session;

	return self;
}

gboolean
gkm_wrap_prompt_do_init_pin (GkmWrapPrompt *self, CK_RV last_result,
                             CK_UTF8CHAR_PTR *pin, CK_ULONG *n_pin)
{
	CK_TOKEN_INFO tinfo;
	gchar *password;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->module);
	g_assert (pin);
	g_assert (n_pin);

	if (!get_info_for_token (self, &tinfo))
		return FALSE;

	setup_init_token (self, &tinfo);

	password = (char *)gkm_wrap_prompt_request_password (self);
	if (password == NULL)
		return FALSE;

	g_assert (self->destroy_data == NULL);
	gkm_wrap_prompt_set_prompt_data (self, password, NULL);
	*pin = (gpointer)password;
	*n_pin = strlen (password);
	return TRUE;
}

void
gkm_wrap_prompt_done_init_pin (GkmWrapPrompt *self, CK_RV call_result)
{
	CK_TOKEN_INFO tinfo;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->destroy_data == NULL);

	/* Save auto auto unlock */
	if (call_result == CKR_OK && auto_unlock_should_attach (self)) {
		if (get_info_for_token (self, &tinfo))
			auto_unlock_attach_token (&tinfo, self->prompt_data);
	}
}

/* ------------------------------------------------------------------------------------
 * SETPIN
 */

typedef struct _SetPinPrompt {
	gchar *original;
	gchar *password;
} SetPinPrompt;

static void
set_pin_prompt_free (gpointer user_data)
{
	SetPinPrompt *data = user_data;
	egg_secure_strfree (data->original);
	egg_secure_strfree (data->password);
	g_slice_free (SetPinPrompt, data);
}

static void
setup_set_token_original (GkmWrapPrompt *self,
                          CK_TOKEN_INFO_PTR tinfo)
{
	GcrPrompt *prompt;
	gchar *label;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (tinfo != NULL);
	prompt = GCR_PROMPT (self);

	label = g_strndup ((gchar*)tinfo->label, sizeof (tinfo->label));
	g_strchomp (label);

	/* Build up the prompt */
	gcr_prompt_set_password_new (prompt, FALSE);
	gcr_prompt_set_title (prompt, _("Change Password"));
	gcr_prompt_set_message (prompt, _("Authentication required"));

	text = g_strdup_printf (_("To change the password for “%s”, the original password is required"), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	gcr_prompt_set_continue_label (prompt, _("Continue"));
	gcr_prompt_set_choice_label (prompt, NULL);
	g_free (label);
}


static void
setup_set_token_password (GkmWrapPrompt *self,
                          CK_TOKEN_INFO_PTR tinfo)
{
	GcrPrompt *prompt;
	const gchar *choice;
	gchar *label;
	gchar *text;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (tinfo != NULL);
	prompt = GCR_PROMPT (self);

	label = g_strndup ((gchar*)tinfo->label, sizeof (tinfo->label));
	g_strchomp (label);

	/* Build up the prompt */
	gcr_prompt_set_password_new (prompt, TRUE);
	gcr_prompt_set_title (prompt, _("Change Password"));
	gcr_prompt_set_message (prompt, _("Change password"));

	text = g_strdup_printf (_("Type a new password for “%s”"), label);
	gcr_prompt_set_description (prompt, text);
	g_free (text);

	choice = NULL;
	if (gkm_wrap_login_is_usable ())
		choice = _("Automatically unlock whenever I’m logged in");

	gcr_prompt_set_continue_label (prompt, _("Continue"));
	gcr_prompt_set_choice_label (prompt, choice);

	g_free (label);
}


GkmWrapPrompt*
gkm_wrap_prompt_for_set_pin (CK_FUNCTION_LIST_PTR module, CK_SESSION_HANDLE session,
                             CK_UTF8CHAR_PTR old_pin, CK_ULONG n_old_pin,
                             CK_UTF8CHAR_PTR new_pin, CK_ULONG n_new_pin)
{
	GkmWrapPrompt *self;

	g_assert (module != NULL);

	if (new_pin != NULL || n_new_pin != 0)
		return NULL;

	self = g_object_new (GKM_TYPE_WRAP_PROMPT,
	                     "timeout-seconds", -1,
	                     "bus-name", gkm_wrap_prompt_get_prompter_name (),
	                     NULL);

	/* Build up the prompt */
	self->module = module;
	self->session = session;
	gkm_wrap_prompt_set_prompt_data (self,
					 g_slice_new0 (SetPinPrompt),
					 set_pin_prompt_free);

	return self;
}

gboolean
gkm_wrap_prompt_do_set_pin (GkmWrapPrompt *self, CK_RV last_result,
                            CK_UTF8CHAR_PTR *old_pin, CK_ULONG *n_old_pin,
                            CK_UTF8CHAR_PTR *new_pin, CK_ULONG *n_new_pin)
{
	gboolean initializing = FALSE;
	CK_TOKEN_INFO tinfo;
	SetPinPrompt *data;
	const gchar *password;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->module);
	g_assert (old_pin);
	g_assert (n_old_pin);
	g_assert (new_pin);
	g_assert (n_new_pin);

	g_assert (self->destroy_data == set_pin_prompt_free);
	data = self->prompt_data;

	if (!get_info_for_token (self, &tinfo))
		return FALSE;

	initializing = !(tinfo.flags & CKF_USER_PIN_INITIALIZED);

	/* Prompt for the original password */
	if (!initializing || last_result != CKR_OK) {
		setup_set_token_original (self, &tinfo);
		password = gkm_wrap_prompt_request_password (self);
		if (password == NULL)
			return FALSE;
		egg_secure_strfree (data->original);
		data->original = egg_secure_strdup (password);
	}

	/* Prompt for the new password */
	if (data->password == NULL) {
		setup_set_token_password (self, &tinfo);
		password = gkm_wrap_prompt_request_password (self);
		if (password == NULL)
			return FALSE;
		data->password = egg_secure_strdup (password);
	}

	*new_pin = (guchar *)data->password;
	*n_new_pin = data->password ? strlen (data->password) : 0;
	*old_pin = (guchar *)data->original;
	*n_old_pin = data->original ? strlen (data->original) : 0;

	return TRUE;
}

void
gkm_wrap_prompt_done_set_pin (GkmWrapPrompt *self, CK_RV call_result)
{
	CK_TOKEN_INFO tinfo;
	SetPinPrompt *data;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->destroy_data == set_pin_prompt_free);
	data = self->prompt_data;

	/* Save auto auto unlock */
	if (call_result == CKR_OK && auto_unlock_should_attach (self)) {
		if (get_info_for_token (self, &tinfo))
			auto_unlock_attach_token (&tinfo, data->password);
	}
}

/* -----------------------------------------------------------------------------
 * LOGIN
 */

static GkmWrapPrompt*
login_prompt_for_specific (CK_FUNCTION_LIST_PTR module, CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE object)
{
	GkmWrapPrompt *self;
	CK_ATTRIBUTE attr;
	CK_BBOOL always;
	CK_RV rv;

	g_assert (module);

	/*
	 * Should have an object at this point, if none exists it's an
	 * indication of either a buggy PKCS#11 module, or bugs in this
	 * wrap-layer not stashing away the context specific object.
	 */
	g_return_val_if_fail (object != 0, NULL);

	/* Find out if the object is CKA_ALWAYS_AUTHENTICATE */
	always = CK_FALSE;
	attr.type = CKA_ALWAYS_AUTHENTICATE;
	attr.pValue = &always;
	attr.ulValueLen = sizeof (always);

	rv = (module->C_GetAttributeValue) (session, object, &attr, 1);
	if (rv != CKR_OK || always != CK_TRUE)
		return NULL;

	self = g_object_new (GKM_TYPE_WRAP_PROMPT,
	                     "timeout-seconds", -1,
	                     "bus-name", gkm_wrap_prompt_get_prompter_name (),
	                     NULL);

	/* Build up the prompt */
	self->module = module;
	self->session = session;
	self->object = object;

	return self;
}

static gboolean
login_prompt_do_specific (GkmWrapPrompt *self, CK_RV last_result,
                          CK_UTF8CHAR_PTR *pin, CK_ULONG *n_pin)
{
	gchar *password = NULL;
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_attrs;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (pin);
	g_assert (n_pin);
	attrs = get_attributes_from_object (self, &n_attrs);
	g_return_val_if_fail (attrs, FALSE);

	if (self->iteration == 0) {
		++(self->iteration);
		password = auto_unlock_lookup_object (attrs, n_attrs);
		if (password)
			gkm_wrap_prompt_set_prompt_data (self, password,
							 (GDestroyNotify)egg_secure_strfree);

	} else if (self->iteration == 1 && last_result == CKR_PIN_INCORRECT) {
		auto_unlock_remove_object (attrs, n_attrs);
	}

	if (!password) {
		setup_unlock_prompt (self, attrs, n_attrs, self->iteration == 1);

		password = (char *)gkm_wrap_prompt_request_password (self);
		if (password == NULL)
			return FALSE;
		gkm_wrap_prompt_set_prompt_data (self, password, NULL);
	}

	*pin = (guchar *)password;
	*n_pin = strlen (password);
	return TRUE;
}

static void
login_prompt_done_specific (GkmWrapPrompt *self, CK_RV call_result)
{
	CK_ATTRIBUTE_PTR attrs;
	CK_ULONG n_attrs;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->destroy_data == NULL ||
		  self->destroy_data == (GDestroyNotify)egg_secure_strfree);

	/* Possibly save away auto unlock */
	if (call_result == CKR_OK && auto_unlock_should_attach (self)) {
		attrs = get_attributes_from_object (self, &n_attrs);
		auto_unlock_attach_object (attrs, n_attrs, self->prompt_data);
	}
}

static GkmWrapPrompt*
login_prompt_for_user (CK_FUNCTION_LIST_PTR module, CK_SESSION_HANDLE session)
{
	GkmWrapPrompt *self;

	g_assert (module != NULL);

	self = g_object_new (GKM_TYPE_WRAP_PROMPT,
	                     "timeout-seconds", -1,
	                     "bus-name", gkm_wrap_prompt_get_prompter_name (),
	                     NULL);

	/* Build up the prompt */
	self->module = module;
	self->session = session;

	return self;
}

static gboolean
login_prompt_do_user (GkmWrapPrompt *self, CK_RV last_result,
                       CK_UTF8CHAR_PTR *pin, CK_ULONG *n_pin)
{
	CK_TOKEN_INFO tinfo;
	gchar *password = NULL;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->module);
	g_assert (pin);
	g_assert (n_pin);

	if (!get_info_for_token (self, &tinfo))
		return FALSE;

	if (self->iteration == 0) {
		++(self->iteration);
		password = auto_unlock_lookup_token (&tinfo);
		if (password)
			gkm_wrap_prompt_set_prompt_data (self, password,
							 (GDestroyNotify)egg_secure_strfree);

	} else if (self->iteration == 1 && last_result == CKR_PIN_INCORRECT) {
		auto_unlock_remove_token (&tinfo);
	}

	if (!password) {
		setup_unlock_token (self, &tinfo);

		password = (char *)gkm_wrap_prompt_request_password (self);
		if (password == NULL)
			return FALSE;
		gkm_wrap_prompt_set_prompt_data (self, password, NULL);
	}

	*pin = (guchar *)password;
	*n_pin = strlen (password);
	return TRUE;
}

static void
login_prompt_done_user (GkmWrapPrompt *self, CK_RV call_result)
{
	CK_TOKEN_INFO tinfo;

	g_assert (GKM_IS_WRAP_PROMPT (self));
	g_assert (self->destroy_data == NULL ||
		  self->destroy_data == (GDestroyNotify)egg_secure_strfree);

	/* Save the options, and possibly auto unlock */
	if (call_result == CKR_OK && auto_unlock_should_attach (self)) {
		if (get_info_for_token (self, &tinfo))
			auto_unlock_attach_token (&tinfo, self->prompt_data);
	}
}


GkmWrapPrompt*
gkm_wrap_prompt_for_login (CK_FUNCTION_LIST_PTR module, CK_USER_TYPE user_type,
                           CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                           CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	g_return_val_if_fail (module, NULL);

	if (pin != NULL || n_pin != 0)
		return NULL;

	switch (user_type) {
	case CKU_CONTEXT_SPECIFIC:
		return login_prompt_for_specific (module, session, object);
	case CKU_USER:
		return login_prompt_for_user (module, session);
	default:
		return NULL;
	}
}

gboolean
gkm_wrap_prompt_do_login (GkmWrapPrompt *self, CK_USER_TYPE user_type, CK_RV last_result,
                          CK_UTF8CHAR_PTR *pin, CK_ULONG *n_pin)
{
	g_return_val_if_fail (GKM_IS_WRAP_PROMPT (self), FALSE);
	g_return_val_if_fail (pin, FALSE);
	g_return_val_if_fail (n_pin, FALSE);

	switch (user_type) {
	case CKU_CONTEXT_SPECIFIC:
		return login_prompt_do_specific (self, last_result, pin, n_pin);
	case CKU_USER:
		return login_prompt_do_user (self, last_result, pin, n_pin);
	default:
		return FALSE;
	}
}

void
gkm_wrap_prompt_done_login (GkmWrapPrompt *self, CK_USER_TYPE user_type, CK_RV call_result)
{
	g_return_if_fail (GKM_IS_WRAP_PROMPT (self));

	switch (user_type) {
	case CKU_CONTEXT_SPECIFIC:
		login_prompt_done_specific (self, call_result);
		break;
	case CKU_USER:
		login_prompt_done_user (self, call_result);
		break;
	}
}

const gchar *
gkm_wrap_prompt_get_prompter_name (void)
{
	const gchar *prompter_name;

	if (the_prompter_name)
		return the_prompter_name;

	prompter_name = g_getenv ("GNOME_KEYRING_TEST_PROMPTER");
	if (prompter_name)
		return prompter_name;

	return NULL;
}

void
gkm_wrap_prompt_set_prompter_name (const gchar *prompter_name)
{
	the_prompter_name = g_intern_string (prompter_name);
}
