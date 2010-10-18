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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"

#include "test-suite.h"

#include "egg/egg-secure-memory.h"

#include "wrap-layer/gkm-wrap-layer.h"
#include "wrap-layer/gkm-wrap-login.h"

DEFINE_TEST (login_did_unlock_fail)
{
	gchar *password;
	gboolean ret;

	gkm_wrap_layer_mark_login_unlock_failure ("failure");

	ret = gkm_wrap_login_did_unlock_fail ();
	g_assert (ret == TRUE);

	password = gkm_wrap_login_steal_failed_password ();
	g_assert_cmpstr (password, ==, "failure");
	egg_secure_strfree (password);

	gkm_wrap_layer_mark_login_unlock_failure ("failed password");
	gkm_wrap_layer_mark_login_unlock_failure ("failed password");
	gkm_wrap_layer_mark_login_unlock_success ();

	ret = gkm_wrap_login_did_unlock_fail ();
	g_assert (ret == FALSE);
}
