/*
 * gnome-keyring
 *
 * Copyright (C) 2010 Stefan Walter
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
 */

#ifndef __GCR_ICONS_H__
#define __GCR_ICONS_H__

#include "gcr-internal.h"

#include <gck/gck.h>

G_BEGIN_DECLS

#define GCR_ICON_CERTIFICATE    "application-certificate"
#define GCR_ICON_KEY            "gcr-key"
#define GCR_ICON_KEY_PAIR       "gcr-key-pair"
#define GCR_ICON_SMART_CARD     "gcr-smart-card"
#define GCR_ICON_HOME_DIRECTORY "user-home"

GIcon *          gcr_icon_for_token                (GckTokenInfo *token_info);

G_END_DECLS

#endif /* __GCR_SMART_CARD_H__ */
