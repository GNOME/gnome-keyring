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

#include "gck-roots-store.h"
#include "gck-roots-module.h"
#include "gck-roots-certificate.h"

#include "gck/gck-file-tracker.h"
#include "gck/gck-serializable.h"

#include "egg/egg-openssl.h"

#include <string.h>

struct _GckRootsModule {
	GckModule parent;
	GckFileTracker *tracker;
	GHashTable *certificates;
	gchar *directory;
};

static const CK_SLOT_INFO gck_roots_module_slot_info = {
	"Root CA Certificates",
	"Gnome Keyring",
	CKF_TOKEN_PRESENT,
	{ 0, 0 },
	{ 0, 0 }
};

static const CK_TOKEN_INFO gck_roots_module_token_info = {
	"Root CA Certificates",
	"Gnome Keyring",
	"1.0",
	"1:ROOTS:DEFAULT", /* Unique serial number for manufacturer */
	CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	CK_EFFECTIVELY_INFINITE,
	1024,
	1,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	CK_UNAVAILABLE_INFORMATION,
	{ 0, 0 },
	{ 0, 0 },
	""
};

typedef struct _ParsePrivate {
	GckRootsModule *module;
	GHashTable *checks;
	const gchar *path;
	guint count;
} ParsePrivate;

G_DEFINE_TYPE (GckRootsModule, gck_roots_module, GCK_TYPE_MODULE);

/* -----------------------------------------------------------------------------
 * ACTUAL PKCS#11 Module Implementation 
 */

/* Include all the module entry points */
#include "gck/gck-module-ep.h"
GCK_DEFINE_MODULE (gck_roots_module, GCK_TYPE_ROOTS_MODULE);

/* -----------------------------------------------------------------------------
 * INTERNAL 
 */

static GckCertificate*
add_certificate_for_data (GckRootsModule *self, const guchar *data, 
                          gsize n_data, const gchar *path)
{
	GckCertificate *cert;
	GckManager *manager;
	gchar *hash, *unique;
	
	g_assert (GCK_IS_ROOTS_MODULE (self));
	g_assert (data);
	g_assert (path);
	
	manager = gck_module_get_manager (GCK_MODULE (self));
	g_return_val_if_fail (manager, NULL);

	/* Hash the certificate */
	hash = g_compute_checksum_for_data (G_CHECKSUM_MD5, data, n_data);
	unique = g_strdup_printf ("%s:%s", path, hash);
	g_free (hash);
	
	/* Try and find a certificate */
	cert = GCK_CERTIFICATE (gck_manager_find_one_by_string_property (manager, "unique", unique));
	if (cert != NULL) {
		g_free (unique);
		return cert;
	}

	/* Create a new certificate object */
	cert = GCK_CERTIFICATE (gck_roots_certificate_new (GCK_MODULE (self), unique, path));

	if (!gck_serializable_load (GCK_SERIALIZABLE (cert), NULL, data, n_data)) {
		g_message ("couldn't parse certificate(s): %s", path);
		g_object_unref (cert);
		return NULL;
	}
	
	/* Setup the right manager on the certificates */
	gck_manager_register_object (manager, GCK_OBJECT (cert));
	gck_manager_register_object (manager, GCK_OBJECT (gck_roots_certificate_get_netscape_trust (GCK_ROOTS_CERTIFICATE (cert))));
	
	/* And add to our wonderful table */
	g_hash_table_insert (self->certificates, cert, cert);
	return cert;
}

static void
parsed_pem_block (GQuark type, const guchar *data, gsize n_data,
                  GHashTable *headers, gpointer user_data)
{
	static GQuark PEM_CERTIFICATE;
	static volatile gsize quarks_inited = 0;
	
	ParsePrivate *ctx = (ParsePrivate*)user_data;
	GckCertificate *cert;
	
	g_assert (ctx);
	
	/* Initialize the first time through */
	if (g_once_init_enter (&quarks_inited)) {
		PEM_CERTIFICATE = g_quark_from_static_string ("CERTIFICATE");
		g_once_init_leave (&quarks_inited, 1);
	}
	
	if (type == PEM_CERTIFICATE) {
		cert = add_certificate_for_data (ctx->module, data, n_data, ctx->path);
		if (cert != NULL) {
			g_hash_table_remove (ctx->checks, cert);
			++ctx->count;
		}
	}
}

static void
remove_each_certificate (gpointer key, gpointer value, gpointer user_data)
{
	GckRootsModule *self = user_data;
	g_assert (GCK_IS_ROOTS_MODULE (self));
	if (!g_hash_table_remove (self->certificates, value))
		g_return_if_reached ();	
}

static void
file_load (GckFileTracker *tracker, const gchar *path, GckRootsModule *self)
{
	ParsePrivate ctx;
	GckManager *manager;
	GckCertificate *cert;
	guchar *data;
	GList *objects, *l;
	GError *error = NULL;
	gsize n_data;
	guint num;

	manager = gck_module_get_manager (GCK_MODULE (self));
	g_return_if_fail (manager);

	/* Read in the public key */
	if (!g_file_get_contents (path, (gchar**)&data, &n_data, &error)) {
		g_warning ("couldn't load root certificates: %s: %s",
		           path, error && error->message ? error->message : "");
		return;
	}
	
	memset (&ctx, 0, sizeof (ctx));
	ctx.path = path;
	ctx.module = self;
	ctx.count = 0;
	
	/* Checks for what was at this path */
	ctx.checks = g_hash_table_new (g_direct_hash, g_direct_equal);
	objects = gck_manager_find_by_string_property (manager, "path", path);
	for (l = objects; l; l = g_list_next (l))
		g_hash_table_insert (ctx.checks, l->data, l->data);
	g_list_free (objects);
	
	/* Try and parse the PEM */
	num = egg_openssl_pem_parse (data, n_data, parsed_pem_block, &ctx);

	/* If no PEM data, try to parse directly as DER  */
	if (ctx.count == 0) {
		cert = add_certificate_for_data (self, data, n_data, path);
		if (cert != NULL)
			g_hash_table_remove (ctx.checks, cert);
	}
	
	g_hash_table_foreach (ctx.checks, remove_each_certificate, self);
	g_hash_table_destroy (ctx.checks);
	
	g_free (data);
}

static void
file_remove (GckFileTracker *tracker, const gchar *path, GckRootsModule *self)
{
	GList *objects, *l;
	GckManager *manager;
	
	g_return_if_fail (path);
	g_return_if_fail (GCK_IS_ROOTS_MODULE (self));

	manager = gck_module_get_manager (GCK_MODULE (self));
	g_return_if_fail (manager);

	objects = gck_manager_find_by_string_property (manager, "path", path);
	for (l = objects; l; l = g_list_next (l))
		if (!g_hash_table_remove (self->certificates, l->data))
			g_return_if_reached ();
	g_list_free (objects);
}

/* -----------------------------------------------------------------------------
 * OBJECT 
 */

static const CK_SLOT_INFO* 
gck_roots_module_real_get_slot_info (GckModule *self)
{
	return &gck_roots_module_slot_info;
}

static const CK_TOKEN_INFO*
gck_roots_module_real_get_token_info (GckModule *self)
{
	return &gck_roots_module_token_info;
}

static void 
gck_roots_module_real_parse_argument (GckModule *base, const gchar *name, const gchar *value)
{
	GckRootsModule *self = GCK_ROOTS_MODULE (base);
	if (g_str_equal (name, "directory")) {
		g_free (self->directory);
		self->directory = g_strdup (value);
	}
}

static CK_RV
gck_roots_module_real_refresh_token (GckModule *base)
{
	GckRootsModule *self = GCK_ROOTS_MODULE (base);
	if (self->tracker)
		gck_file_tracker_refresh (self->tracker, FALSE);
	return CKR_OK;
}

static GObject* 
gck_roots_module_constructor (GType type, guint n_props, GObjectConstructParam *props) 
{
	GckRootsModule *self = GCK_ROOTS_MODULE (G_OBJECT_CLASS (gck_roots_module_parent_class)->constructor(type, n_props, props));
	GckManager *manager;

	g_return_val_if_fail (self, NULL);	

#ifdef ROOT_CERTIFICATES
	if (!self->directory)
		self->directory = g_strdup (ROOT_CERTIFICATES);
#endif
	if (self->directory) {
		self->tracker = gck_file_tracker_new (self->directory, "*", "*.0");
		g_signal_connect (self->tracker, "file-added", G_CALLBACK (file_load), self);
		g_signal_connect (self->tracker, "file-changed", G_CALLBACK (file_load), self);
		g_signal_connect (self->tracker, "file-removed", G_CALLBACK (file_remove), self);
	}
	
	manager = gck_module_get_manager (GCK_MODULE (self));
	gck_manager_add_property_index (manager, "unique", TRUE);
	gck_manager_add_property_index (manager, "path", FALSE);
	
	return G_OBJECT (self);
}

static void
gck_roots_module_init (GckRootsModule *self)
{
	self->certificates = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
	
}

static void
gck_roots_module_dispose (GObject *obj)
{
	GckRootsModule *self = GCK_ROOTS_MODULE (obj);
	
	if (self->tracker)
		g_object_unref (self->tracker);
	self->tracker = NULL;
	
	g_hash_table_remove_all (self->certificates);
    
	G_OBJECT_CLASS (gck_roots_module_parent_class)->dispose (obj);
}

static void
gck_roots_module_finalize (GObject *obj)
{
	GckRootsModule *self = GCK_ROOTS_MODULE (obj);
	
	g_assert (self->tracker == NULL);
	
	g_hash_table_destroy (self->certificates);
	self->certificates = NULL;
	
	g_free (self->directory);
	self->directory = NULL;

	G_OBJECT_CLASS (gck_roots_module_parent_class)->finalize (obj);
}

static void
gck_roots_module_class_init (GckRootsModuleClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GckModuleClass *module_class = GCK_MODULE_CLASS (klass);
	
	gobject_class->constructor = gck_roots_module_constructor;
	gobject_class->dispose = gck_roots_module_dispose;
	gobject_class->finalize = gck_roots_module_finalize;
	
	module_class->get_slot_info = gck_roots_module_real_get_slot_info;
	module_class->get_token_info = gck_roots_module_real_get_token_info;
	module_class->parse_argument = gck_roots_module_real_parse_argument;
	module_class->refresh_token = gck_roots_module_real_refresh_token;
}

/* ---------------------------------------------------------------------------------------
 * PUBLIC 
 */

CK_FUNCTION_LIST_PTR
gck_roots_store_get_functions (void)
{
	gck_crypto_initialize ();
	return gck_roots_module_function_list;
}
