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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gkd-secret-exchange.h"
#include "gkd-secret-secret.h"
#include "gkd-secret-service.h"
#include "gkd-secret-session.h"

#include <gcr/gcr-base.h>

#include <glib/gi18n.h>

#include <string.h>

enum {
	PROP_0,
	PROP_CALLER,
	PROP_SERVICE,
};

struct _GkdSecretExchange {
	GcrSecretExchange parent;
	gchar *caller;
	GkdSecretService *service;
	GkdSecretSession *session;
	GkdSecretSecret *last_secret;
};

struct _GkdSecretExchangeClass {
	GcrSecretExchangeClass parent_class;
};

G_DEFINE_TYPE (GkdSecretExchange, gkd_secret_exchange, GCR_TYPE_SECRET_EXCHANGE);

static void
gkd_secret_exchange_init (GkdSecretExchange *self)
{

}

static void
gkd_secret_exchange_set_property (GObject *obj,
				  guint prop_id,
				  const GValue *value,
				  GParamSpec *pspec)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_return_if_fail (!self->caller);
		self->caller = g_value_dup_string (value);
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
gkd_secret_exchange_get_property (GObject *obj,
				  guint prop_id,
				  GValue *value,
				  GParamSpec *pspec)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (obj);

	switch (prop_id) {
	case PROP_CALLER:
		g_value_set_string (value, self->caller);
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
gkd_secret_exchange_finalize (GObject *obj)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (obj);

	if (self->service) {
		g_object_remove_weak_pointer (G_OBJECT (self->service),
					      (gpointer*)&(self->service));
		self->service = NULL;
	}

	g_clear_object (&self->session);
	gkd_secret_secret_free (self->last_secret);
	g_free (self->caller);

	G_OBJECT_CLASS (gkd_secret_exchange_parent_class)->finalize (obj);
}

static gboolean
gkd_secret_exchange_generate_exchange_key (GcrSecretExchange *exchange,
					   const gchar *scheme,
					   guchar **public_key,
					   gsize *n_public_key)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (exchange);

	g_return_val_if_fail (self->service != NULL, FALSE);

	g_clear_object (&self->session);
	self->session = gkd_secret_session_new (self->service, self->caller);
	*public_key = gkd_secret_session_begin (self->session,
						"ietf-ike-grp-modp-1536",
						n_public_key);
	return (*public_key != NULL) ? TRUE : FALSE;
}

static gboolean
gkd_secret_exchange_derive_transport_key (GcrSecretExchange *exchange,
					  const guchar *peer,
					  gsize n_peer)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (exchange);

	return gkd_secret_session_complete (self->session, peer, n_peer);
}

static gboolean
gkd_secret_exchange_encrypt_transport_data (GcrSecretExchange *exchange,
					    GckAllocator allocator,
					    const guchar *plain_text,
					    gsize n_plain_text,
					    guchar **parameter,
					    gsize *n_parameter,
					    guchar **cipher_text,
					    gsize *n_cipher_text)
{
	g_warning ("Not implemented: a GkdSecretExchange was used to encrypt a secret");
	return FALSE;
}

static gboolean
gkd_secret_exchange_decrypt_transport_data (GcrSecretExchange *exchange,
					    GckAllocator allocator,
					    const guchar *cipher_text,
					    gsize n_cipher_text,
					    const guchar *parameter,
					    gsize n_parameter,
					    guchar **plain_text,
					    gsize *n_plain_text)
{
	GkdSecretExchange *self = GKD_SECRET_EXCHANGE (exchange);

	gkd_secret_secret_free (self->last_secret);

	self->last_secret = gkd_secret_secret_new (self->session,
						   parameter, n_parameter,
						   cipher_text, n_cipher_text);

	*plain_text = NULL;
	*n_plain_text = 0;
	return TRUE;
}

static void
gkd_secret_exchange_class_init (GkdSecretExchangeClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GcrSecretExchangeClass *exchange_class = GCR_SECRET_EXCHANGE_CLASS (klass);

	gobject_class->finalize = gkd_secret_exchange_finalize;
	gobject_class->get_property = gkd_secret_exchange_get_property;
	gobject_class->set_property = gkd_secret_exchange_set_property;

	exchange_class->generate_exchange_key = gkd_secret_exchange_generate_exchange_key;
	exchange_class->derive_transport_key = gkd_secret_exchange_derive_transport_key;
	exchange_class->encrypt_transport_data = gkd_secret_exchange_encrypt_transport_data;
	exchange_class->decrypt_transport_data = gkd_secret_exchange_decrypt_transport_data;

	g_object_class_install_property (gobject_class, PROP_CALLER,
		g_param_spec_string ("caller", "Caller", "DBus caller name",
				     NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY ));

	g_object_class_install_property (gobject_class, PROP_SERVICE,
		g_param_spec_object ("service", "Service", "Service which owns this session",
				     GKD_SECRET_TYPE_SERVICE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

GkdSecretExchange *
gkd_secret_exchange_new (GkdSecretService *service,
			 const gchar *caller)
{
	return g_object_new (GKD_TYPE_SECRET_EXCHANGE,
			     "service", service,
			     "caller", caller,
			     NULL);
}

GkdSecretSecret *
gkd_secret_exchange_take_last_secret (GkdSecretExchange *self)
{
	GkdSecretSecret *secret;

	g_return_val_if_fail (GKD_IS_SECRET_EXCHANGE (self), NULL);

	secret = self->last_secret;
	self->last_secret = NULL;
	return secret;
}
