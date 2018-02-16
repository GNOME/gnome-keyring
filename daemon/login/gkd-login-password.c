/*
 * gnome-keyring
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
 * Author: Daiki Ueno
 */

#include "config.h"

#include "gkd-login-password.h"

#include <gcr/gcr-unlock-options.h>
#include "gkd-login.h"

enum {
	PROP_0,
	PROP_BASE,
	PROP_LOGIN_AVAILABLE
};

struct _GkdLoginPassword
{
	GTlsPassword password;

	GTlsPassword *base;
	gboolean login_available;
	gboolean store_password;
};

G_DEFINE_TYPE (GkdLoginPassword, gkd_login_password, G_TYPE_TLS_PASSWORD);

static void
gkd_login_password_init (GkdLoginPassword *self)
{
}

static const guchar *
gkd_login_password_get_value (GTlsPassword *password,
			      gsize *length)
{
	GkdLoginPassword *self = GKD_LOGIN_PASSWORD (password);

	return g_tls_password_get_value (self->base, length);
}

static void
gkd_login_password_set_value (GTlsPassword *password,
			      guchar *value,
			      gssize length,
			      GDestroyNotify destroy)
{
	GkdLoginPassword *self = GKD_LOGIN_PASSWORD (password);

	g_tls_password_set_value_full (self->base, value, length, destroy);
}

static void
gkd_login_password_set_property (GObject *object,
                                 guint prop_id,
                                 const GValue *value,
                                 GParamSpec *pspec)
{
	GkdLoginPassword *self = GKD_LOGIN_PASSWORD (object);

	switch (prop_id)
	{
	case PROP_BASE:
		self->base = g_value_dup_object (value);
		break;
	case PROP_LOGIN_AVAILABLE:
		self->login_available = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
gkd_login_password_dispose (GObject *object)
{
	GkdLoginPassword *self = GKD_LOGIN_PASSWORD (object);

	g_clear_object (&self->base);

	G_OBJECT_CLASS (gkd_login_password_parent_class)->dispose (object);
}

static void
gkd_login_password_class_init (GkdLoginPasswordClass *klass)
{
	GTlsPasswordClass *password_class = G_TLS_PASSWORD_CLASS (klass);
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	password_class->get_value = gkd_login_password_get_value;
	password_class->set_value = gkd_login_password_set_value;

	gobject_class->set_property = gkd_login_password_set_property;
	gobject_class->dispose = gkd_login_password_dispose;

	g_object_class_install_property (gobject_class, PROP_BASE,
					 g_param_spec_object ("base", "Base", "Base",
							      G_TYPE_TLS_PASSWORD,
							      G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
	g_object_class_install_property (gobject_class, PROP_LOGIN_AVAILABLE,
					 g_param_spec_boolean ("login-available", "Login-available", "Login-available",
							       FALSE,
							       G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));
}

gboolean
gkd_login_password_get_login_available (GkdLoginPassword *self)
{
	return self->login_available;
}

void
gkd_login_password_set_store_password (GkdLoginPassword *self,
				       gboolean store_password)
{
	self->store_password = store_password;
}

gboolean
gkd_login_password_get_store_password (GkdLoginPassword *self)
{
	return self->store_password;
}
