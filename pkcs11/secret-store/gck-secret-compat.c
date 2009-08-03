/* 
 * gnome-keyring
 * 
 * Copyright (C) 2009 Stefan Walter
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

#include "gck-secret-compat.h"

void
gck_secret_compat_access_free (gpointer data)
{
	GckSecretAccess *ac = data;
	if (ac) {
		g_free (ac->display_name);
		g_free (ac->pathname);
		g_free (ac);
	}
}

void
gck_secret_compat_acl_free (gpointer acl)
{
	GList *l;
	for (l = acl; l; l = g_list_next (l)) 
		gck_secret_compat_access_free (l->data);
	g_list_free (acl);
}

