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

#include "gck-secret.h"

#include "egg/egg-secure-memory.h"

#include <string.h>

struct _GckSecret {
	GObject parent;
	gchar *data;
	gsize n_data;
};

G_DEFINE_TYPE (GckSecret, gck_secret, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static void
gck_secret_init (GckSecret *self)
{

}

static void
gck_secret_dispose (GObject *obj)
{
	GckSecret *self = GCK_SECRET (obj);
	
	egg_secure_strfree (self->data);
	self->data = NULL;
	self->n_data = 0;
    
	G_OBJECT_CLASS (gck_secret_parent_class)->dispose (obj);
}

static void
gck_secret_finalize (GObject *obj)
{
	GckSecret *self = GCK_SECRET (obj);
	
	g_assert (!self->data);
	g_assert (!self->n_data);

	G_OBJECT_CLASS (gck_secret_parent_class)->finalize (obj);
}

static void
gck_secret_set_property (GObject *obj, guint prop_id, const GValue *value, 
                        GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_get_property (GObject *obj, guint prop_id, GValue *value, 
                        GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gck_secret_class_init (GckSecretClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    
	gobject_class->dispose = gck_secret_dispose;
	gobject_class->finalize = gck_secret_finalize;
	gobject_class->set_property = gck_secret_set_property;
	gobject_class->get_property = gck_secret_get_property;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckSecret*
gck_secret_new (const guchar *data, gssize n_data)
{
	GckSecret *secret = g_object_new (GCK_TYPE_SECRET, NULL);
	
	if (data) {
		if (n_data == -1) {
			secret->data = egg_secure_strdup ((const gchar*)data);
			secret->n_data = strlen (secret->data);
		} else {
			secret->data = egg_secure_alloc (n_data + 1);
			memcpy (secret->data, data, n_data);
			secret->n_data = n_data;
		}
	} else {
		secret->data = NULL;
		secret->n_data = 0;
	}
	
	return secret;
}

GckSecret*
gck_secret_new_from_login (CK_UTF8CHAR_PTR pin, CK_ULONG n_pin)
{
	if (n_pin == (CK_ULONG)-1)
		return gck_secret_new ((const guchar*)pin, -1);
	else
		return gck_secret_new ((const guchar*)pin, (gssize)n_pin);
}

const gchar*
gck_secret_get_password (GckSecret *self, gsize *n_data)
{
	g_return_val_if_fail (GCK_IS_SECRET (self), NULL);
	g_return_val_if_fail (n_data, NULL);
	*n_data = self->n_data;
	return self->data;
}

gboolean
gck_secret_equals (GckSecret *self, const guchar* pin, gssize n_pin)
{
	g_return_val_if_fail (GCK_IS_SECRET (self), FALSE);
	
	/* In case they're different somewhere */
	if (n_pin == (CK_ULONG)-1)
		n_pin = -1;
	
	if (n_pin == -1 && pin != NULL)
		n_pin = strlen ((const gchar*)pin);
	
	if (n_pin != self->n_data)
		return FALSE;
	if (!pin && !self->data)
		return TRUE;
	if (!pin || !self->data)
		return FALSE;
	return memcmp (pin, self->data, n_pin) == 0;
}
