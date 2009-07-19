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

#include "gck-login.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

struct _GckLogin {
	GObject parent;
	gchar *password;
	gsize n_password;
};

G_DEFINE_TYPE (GckLogin, gck_login, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gck_login_init (GckLogin *self)
{

}

static void
gck_login_dispose (GObject *obj)
{
	GckLogin *self = GCK_LOGIN (obj);
	
	egg_secure_strfree (self->password);
	self->password = NULL;
	self->n_password = 0;
    
	G_OBJECT_CLASS (gck_login_parent_class)->dispose (obj);
}

static void
gck_login_finalize (GObject *obj)
{
	GckLogin *self = GCK_LOGIN (obj);
	
	g_assert (!self->password);
	g_assert (!self->n_password);

	G_OBJECT_CLASS (gck_login_parent_class)->finalize (obj);
}

static void
gck_login_set_property (GObject *obj, guint prop_id, const GValue *value, 
                        GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_login_get_property (GObject *obj, guint prop_id, GValue *value, 
                        GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_login_class_init (GckLoginClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gobject_class->dispose = gck_login_dispose;
	gobject_class->finalize = gck_login_finalize;
	gobject_class->set_property = gck_login_set_property;
	gobject_class->get_property = gck_login_get_property;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckLogin*
gck_login_new (CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	GckLogin *login = g_object_new (GCK_TYPE_LOGIN, NULL);
	
	if (pin) {
		if (n_pin == (CK_ULONG)-1) {
			login->password = egg_secure_strdup ((const gchar*)pin);
			login->n_password = strlen (login->password);
		} else {
			login->password = egg_secure_alloc (n_pin + 1);
			memcpy (login->password, pin, n_pin);
			login->n_password = n_pin;
		}
	} else {
		login->password = NULL;
		login->n_password = 0;
	}
	
	return login;
}

const gchar*
gck_login_get_password (GckLogin *self, gsize *n_password)
{
	g_return_val_if_fail (GCK_IS_LOGIN (self), NULL);
	g_return_val_if_fail (n_password, NULL);
	*n_password = self->n_password;
	return self->password;
}

gboolean
gck_login_equals (GckLogin *self, CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	g_return_val_if_fail (GCK_IS_LOGIN (self), FALSE);
	
	if (n_pin == (CK_ULONG)-1 && pin != NULL)
		n_pin = strlen ((const gchar*)pin);
	
	if (n_pin != self->n_password)
		return FALSE;
	if (!pin && !self->password)
		return TRUE;
	if (!pin || !self->password)
		return FALSE;
	return memcmp (pin, self->password, n_pin) == 0;
}
