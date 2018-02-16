/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* mock-interaction.c

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

#include "config.h"

#include "mock-interaction.h"

#define MOCK_INTERACTION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), MOCK_TYPE_INTERACTION, MockInteraction))
#define MOCK_IS_INTERACTION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), MOCK_TYPE_INTERACTION))
#define MOCK_INTERACTION_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), MOCK_TYPE_INTERACTION, MockInteractionClass))

typedef struct _MockInteractionClass MockInteractionClass;

struct _MockInteraction {
	GTlsInteraction interaction;
	gchar *password;
};

struct _MockInteractionClass {
	GTlsInteractionClass parent;
};

G_DEFINE_TYPE (MockInteraction, mock_interaction, G_TYPE_TLS_INTERACTION);

static void
mock_interaction_init (MockInteraction *self)
{

}

static void
mock_interaction_finalize (GObject *obj)
{
	MockInteraction *self = MOCK_INTERACTION (obj);

	g_free (self->password);

	G_OBJECT_CLASS (mock_interaction_parent_class)->dispose (obj);
}

static GTlsInteractionResult
mock_interaction_ask_password (GTlsInteraction *interaction,
                               GTlsPassword *password,
                               GCancellable *cancellable,
                               GError **error)
{
	MockInteraction *self = MOCK_INTERACTION (interaction);

	if (self->password) {
		g_tls_password_set_value (password, (const guchar *)self->password, -1);
		return G_TLS_INTERACTION_HANDLED;
	} else {
		return G_TLS_INTERACTION_UNHANDLED;
	}
}

static void
mock_interaction_class_init (MockInteractionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	object_class->finalize = mock_interaction_finalize;

	interaction_class->ask_password = mock_interaction_ask_password;
}

GTlsInteraction *
mock_interaction_new (const gchar *password)
{
	MockInteraction *result;

	result = g_object_new (MOCK_TYPE_INTERACTION, NULL);
	result->password = g_strdup (password);

	return G_TLS_INTERACTION (result);
}
