/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pk-places.h - The directories to look for keys and certificates

   Copyright (C) 2007 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRPKPLACES_H_
#define GKRPKPLACES_H_

#include "config.h"

#include "common/gkr-location.h"

typedef struct _GkrPkPlace { 
	const gchar *volume;
	const gchar *directory;
	const gchar *include;
	const gchar *exclude;
	const gchar *defaults;
} GkrPkPlace;

static const GkrPkPlace gkr_pk_places[] = {
	
	/* The main key and certificate storage */
	{ NULL, "keystore", "*", "*.keystore", 
		"[default]\n" },
	
	/* The SSH directory, mark all keys as ssh-authentication capable */
	{ GKR_LOCATION_VOLUME_HOME_S, ".ssh", "id_?sa", NULL, 
		"[default]\npurposes=ssh-authentication" },

	/* The root certificates directory, mark as trusted anchors */
	{ GKR_LOCATION_VOLUME_FILE_S, "etc/certs", "*", "*.0"
		"[default]\ntrust-anchor=TRUE" }
};

#endif /*GKRPKPLACES_H_*/
