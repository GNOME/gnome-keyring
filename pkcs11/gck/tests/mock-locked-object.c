/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU Lesser General  License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General  License for more details.
 *  
 * You should have received a copy of the GNU Lesser General 
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include "config.h"

#include "mock-locked-object.h"

#include "gck/gck-attributes.h"
#include "gck/gck-authenticator.h"

G_DEFINE_TYPE (MockLockedObject, mock_locked_object, GCK_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

/* -----------------------------------------------------------------------------
 * KEY 
 */

static CK_RV 
mock_locked_object_real_get_attribute (GckObject *base, GckSession *session, CK_ATTRIBUTE* attr)
{
	switch (attr->type) {
	case CKA_CLASS:
		return gck_attribute_set_ulong (attr, CKO_DATA);
	case CKA_ALWAYS_AUTHENTICATE:
		return gck_attribute_set_bool (attr, TRUE);
	};

	return GCK_OBJECT_CLASS (mock_locked_object_parent_class)->get_attribute (base, session, attr);
}

static CK_RV
mock_locked_object_real_unlock (GckObject *base, GckAuthenticator *auth)
{
	const gchar *password;
	gsize n_password;
	
	password = gck_authenticator_get_password (auth, &n_password);
	if (n_password == 4 && memcmp (password, "mock", 4) == 0)
		return CKR_OK;
	
	return CKR_USER_NOT_LOGGED_IN;
}

static void
mock_locked_object_init (MockLockedObject *self)
{

}

static void
mock_locked_object_class_init (MockLockedObjectClass *klass)
{
	GckObjectClass *gck_class = GCK_OBJECT_CLASS (klass);
	mock_locked_object_parent_class = g_type_class_peek_parent (klass);
	gck_class->get_attribute = mock_locked_object_real_get_attribute;
	gck_class->unlock = mock_locked_object_real_unlock;
}

/* -----------------------------------------------------------------------------
 * PUBLIC 
 */

GckObject*
mock_locked_object_new (GckModule *module)
{
	return g_object_new (MOCK_TYPE_LOCKED_OBJECT, "module", module, NULL);
}
