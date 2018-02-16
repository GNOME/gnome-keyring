/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* mock-interaction.h

   Copyright (C) 2011 Collabora Ltd

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
   see <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#ifndef MOCK_INTERACTION_H
#define MOCK_INTERACTION_H

#include <gio/gio.h>

G_BEGIN_DECLS

#define MOCK_TYPE_INTERACTION    (mock_interaction_get_type ())
#define MOCK_INTERACTION(obj)    (G_TYPE_CHECK_INSTANCE_CAST ((obj), MOCK_TYPE_INTERACTION, MockInteraction))
#define MOCK_IS_INTERACTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MOCK_TYPE_INTERACTION))

typedef struct _MockInteraction MockInteraction;

GType               mock_interaction_get_type               (void) G_GNUC_CONST;

GTlsInteraction *   mock_interaction_new                    (const gchar *password);

G_END_DECLS

#endif /* MOCK_INTERACTION_H */
