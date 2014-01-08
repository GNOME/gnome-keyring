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
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include "gkm-xxx.h"

enum {
	PROP_0,
	PROP_XXX
};

enum {
	SIGNAL,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _GkmXxx {
	GObject parent;
};

G_DEFINE_TYPE (GkmXxx, gkm_xxx, G_TYPE_OBJECT);

/* -----------------------------------------------------------------------------
 * INTERNAL
 */

/* -----------------------------------------------------------------------------
 * OBJECT
 */


static GObject*
gkm_xxx_constructor (GType type, guint n_props, GObjectConstructParam *props)
{
	GkmXxx *self = GKM_XXX (G_OBJECT_CLASS (gkm_xxx_parent_class)->constructor(type, n_props, props));
	g_return_val_if_fail (self, NULL);



	return G_OBJECT (self);
}

static void
gkm_xxx_init (GkmXxx *self)
{

}

static void
gkm_xxx_dispose (GObject *obj)
{
	GkmXxx *self = GKM_XXX (obj);

	G_OBJECT_CLASS (gkm_xxx_parent_class)->dispose (obj);
}

static void
gkm_xxx_finalize (GObject *obj)
{
	GkmXxx *self = GKM_XXX (obj);

	G_OBJECT_CLASS (gkm_xxx_parent_class)->finalize (obj);
}

static void
gkm_xxx_set_property (GObject *obj, guint prop_id, const GValue *value,
                           GParamSpec *pspec)
{
	GkmXxx *self = GKM_XXX (obj);

	switch (prop_id) {
	case PROP_XXX:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_xxx_get_property (GObject *obj, guint prop_id, GValue *value,
                           GParamSpec *pspec)
{
	GkmXxx *self = GKM_XXX (obj);

	switch (prop_id) {
	case PROP_XXX:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gkm_xxx_class_init (GkmXxxClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructor = gkm_xxx_constructor;
	gobject_class->dispose = gkm_xxx_dispose;
	gobject_class->finalize = gkm_xxx_finalize;
	gobject_class->set_property = gkm_xxx_set_property;
	gobject_class->get_property = gkm_xxx_get_property;

	g_object_class_install_property (gobject_class, PROP_XXX,
	           g_param_spec_pointer ("xxx", "Xxx", "Xxx.", G_PARAM_READWRITE));

	signals[SIGNAL] = g_signal_new ("signal", GKM_TYPE_XXX,
	                                G_SIGNAL_RUN_FIRST, G_STRUCT_OFFSET (GkmXxxClass, signal),
	                                NULL, NULL, g_cclosure_marshal_VOID__OBJECT,
	                                G_TYPE_NONE, 0);
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkmXxx*
gkm_xxx_new (void)
{
	return g_object_new (GKM_TYPE_XXX, NULL);
}
