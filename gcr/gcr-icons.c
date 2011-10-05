/*
 * gnome-keyring
 *
 * Copyright (C) 2011 Collabora Ltd
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
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gcr-base.h"
#include "gcr-icons.h"

/**
 * gcr_icon_for_token:
 * @token_info: the token info
 *
 * Get an appropriate icon for the token
 *
 * Returns: (transfer full): the icon
 */
GIcon *
gcr_icon_for_token (GckTokenInfo *token_info)
{
	GIcon *icon;

	g_return_val_if_fail (token_info != NULL, NULL);

	if (g_strcmp0 (token_info->manufacturer_id, "Gnome Keyring") == 0)
		icon = g_themed_icon_new (GCR_ICON_HOME_DIRECTORY);

	else if (g_strcmp0 (token_info->manufacturer_id, "Mozilla Foundation") == 0 &&
	         g_strcmp0 (token_info->model, "NSS 3") == 0)
		icon = g_themed_icon_new (GCR_ICON_HOME_DIRECTORY);

	else
		icon = g_themed_icon_new (GCR_ICON_SMART_CARD);

	return icon;
}
