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

#include "gcr-secret-exchange.h"

#include "egg/egg-dh.h"
#include "egg/egg-hkdf.h"
#include "egg/egg-libgcrypt.h"
#include "egg/egg-padding.h"
#include "egg/egg-secure-memory.h"

#include <string.h>
#include <gcrypt.h>

/**
 * SECTION:gcr-secret-exchange
 * @title: GcrSecretExchange
 * @short_description: Exchange secrets between processes in an unexposed way.
 *
 * Allows exchange of secrets between two processes on the same system without
 * exposing those secrets to things like loggers, non-pageable memory etc.
 *
 * This does not protect against active attacks like MITM attacks.
 *
 * Each side creates a #GcrSecretExchange object, and one of the sides calls
 * gcr_secret_exchange_begin(). This creates a string, which should be passed
 * to the other side. Each side passes the strings it receives into
 * gcr_secret_exchange_receive().
 *
 * In order to send a reply (either with or without a secret) use
 * gcr_secret_exchange_send(). A side must have had gcr_secret_exchange_receive()
 * successfully called before it can use gcr_secret_exchange_send().
 *
 * The #GcrSecretExchange objects can be used for multiple iterations of the
 * conversation, or for just one request/reply. The only limitation being that
 * the initial request cannot contain a secret.
 *
 * Caveat: Information about the approximate length (rounded up to the nearest
 * 16 bytes) may be leaked. If this is considered inacceptable, do not use
 * #GcrSecretExchange.
 */

/**
 * GcrSecretExchange:
 *
 * An object representing one side of a secret exchange.
 */

/**
 * GcrSecretExchangeClass:
 *
 * The class for #GcrSecretExchange
 */

/*
 * This is the only set we support so far. It includes:
 *  - DH with the 1536 ike modp group for key exchange
 *  - HKDF SHA256 for hashing of the key to appropriate size
 *  - AES 128 CBC for encryption
 *  - PKCS#7 style padding
 */

#define EXCHANGE_VERSION "secret-exchange-1"

#define EXCHANGE_1_IKE_NAME     "ietf-ike-grp-modp-1536"
#define EXCHANGE_1_KEY_LENGTH   16
#define EXCHANGE_1_IV_LENGTH    16
#define EXCHANGE_1_HASH_ALGO    "sha256"
#define EXCHANGE_1_CIPHER_ALGO  GCRY_CIPHER_AES128
#define EXCHANGE_1_CIPHER_MODE  GCRY_CIPHER_MODE_CBC

struct _GcrSecretExchangePrivate {
	gcry_mpi_t prime;
	gcry_mpi_t base;
	gcry_mpi_t pub;
	gcry_mpi_t priv;
	gpointer key;
	gchar *secret;
	gsize n_secret;
};

G_DEFINE_TYPE (GcrSecretExchange, gcr_secret_exchange, G_TYPE_OBJECT);

static void
key_file_set_base64 (GKeyFile *key_file, const gchar *section,
                     const gchar *field, gconstpointer data, gsize n_data)
{
	gchar *value;

	value = g_base64_encode (data, n_data);
	g_key_file_set_value (key_file, section, field, value);
	g_free (value);
}

static gpointer
key_file_get_base64 (GKeyFile *key_file, const gchar *section,
                     const gchar *field, gsize *n_result)
{
	gpointer result = NULL;
	gchar *data;

	g_return_val_if_fail (key_file, NULL);
	g_return_val_if_fail (section, NULL);
	g_return_val_if_fail (field, NULL);
	g_return_val_if_fail (n_result, NULL);

	data = g_key_file_get_value (key_file, section, field, NULL);
	if (data != NULL)
		result = g_base64_decode (data, n_result);
	g_free (data);
	return result;
}

static void
key_file_set_mpi (GKeyFile *key_file, const gchar *section,
                  const gchar *field, gcry_mpi_t mpi)
{
	gcry_error_t gcry;
	guchar *data;
	gsize n_data;

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &n_data, mpi);
	g_return_if_fail (gcry == 0);

	data = g_malloc0 (n_data);

	/* Write into buffer */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, data, n_data, &n_data, mpi);
	g_return_if_fail (gcry == 0);

	key_file_set_base64 (key_file, section, field, data, n_data);
	g_free (data);
}

static gcry_mpi_t
key_file_get_mpi (GKeyFile *key_file, const gchar *section,
                  const gchar *field)
{
	gcry_mpi_t mpi;
	gcry_error_t gcry;
	gpointer data;
	gsize n_data;

	g_return_val_if_fail (key_file, FALSE);
	g_return_val_if_fail (section, FALSE);
	g_return_val_if_fail (field, FALSE);

	data = key_file_get_base64 (key_file, section, field, &n_data);
	if (data == NULL)
		return FALSE;

	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, data, n_data, NULL);
	g_free (data);

	return (gcry == 0) ? mpi : NULL;
}

static void
gcr_secret_exchange_init (GcrSecretExchange *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_SECRET_EXCHANGE,
	                                        GcrSecretExchangePrivate);

	if (!egg_dh_default_params (EXCHANGE_1_IKE_NAME, &self->pv->prime, &self->pv->base))
		g_return_if_reached ();
}

static void
clear_secret_exchange (GcrSecretExchange *self)
{
	gcry_mpi_release (self->pv->priv);
	self->pv->priv = NULL;
	gcry_mpi_release (self->pv->pub);
	self->pv->pub = NULL;
	egg_secure_free (self->pv->key);
	self->pv->key = NULL;
	egg_secure_free (self->pv->secret);
	self->pv->secret = NULL;
	self->pv->n_secret = 0;
}

static void
gcr_secret_exchange_finalize (GObject *obj)
{
	GcrSecretExchange *self = GCR_SECRET_EXCHANGE (obj);

	clear_secret_exchange (self);
	gcry_mpi_release (self->pv->prime);
	gcry_mpi_release (self->pv->base);

	G_OBJECT_CLASS (gcr_secret_exchange_parent_class)->finalize (obj);
}

static void
gcr_secret_exchange_class_init (GcrSecretExchangeClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = gcr_secret_exchange_finalize;
	g_type_class_add_private (gobject_class, sizeof (GcrSecretExchangePrivate));

	egg_libgcrypt_initialize ();
}

/**
 * gcr_secret_exchange_new:
 *
 * Create a new secret exchange object.
 *
 * Returns: (transfer full): A new #GcrSecretExchange object
 */
GcrSecretExchange *
gcr_secret_exchange_new (void)
{
	return g_object_new (GCR_TYPE_SECRET_EXCHANGE, NULL);
}

/**
 * gcr_secret_exchange_begin:
 * @self: a #GcrSecretExchange object
 *
 * Begin the secret exchange. The resulting string should be sent to the other
 * side of the exchange. The other side should use gcr_secret_exchange_receive()
 * to process the string.
 *
 * Returns: (transfer full): A newly allocated string to be sent to the other
 *     side of the secret exchange
 */
gchar *
gcr_secret_exchange_begin (GcrSecretExchange *self)
{
	GKeyFile *output;
	gchar *result;

	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), NULL);

	clear_secret_exchange (self);
	g_assert (self->pv->priv == NULL);

	output = g_key_file_new ();

	if (!egg_dh_gen_pair (self->pv->prime, self->pv->base, 0,
	                      &self->pv->pub, &self->pv->priv))
		g_return_val_if_reached (NULL);

	key_file_set_mpi (output, EXCHANGE_VERSION, "public", self->pv->pub);

	result = g_key_file_to_data (output, NULL, NULL);
	g_return_val_if_fail (result != NULL, NULL);

	g_key_file_free (output);

	return result;
}

static gboolean
calculate_key (GcrSecretExchange *self,
               GKeyFile *input)
{
	gcry_mpi_t peer;
	gpointer ikm;
	gsize n_ikm;

	peer = key_file_get_mpi (input, EXCHANGE_VERSION, "public");
	if (peer == NULL) {
		g_message ("secret-exchange: invalid or missing 'public' argument");
		return FALSE;
	}

	/* Build up a key we can use */
	ikm = egg_dh_gen_secret (peer, self->pv->priv, self->pv->prime, &n_ikm);
	g_return_val_if_fail (ikm != NULL, FALSE);

	if (self->pv->key == NULL)
		self->pv->key = egg_secure_alloc (EXCHANGE_1_KEY_LENGTH);

	if (!egg_hkdf_perform (EXCHANGE_1_HASH_ALGO, ikm, n_ikm, NULL, 0,
	                       NULL, 0, self->pv->key, EXCHANGE_1_KEY_LENGTH))
		g_return_val_if_reached (FALSE);

	egg_secure_free (ikm);
	gcry_mpi_release (peer);

	return TRUE;
}

static gpointer
perform_aes_decrypt (GcrSecretExchange *self,
                     GKeyFile *input,
                     gsize *n_secret)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	guchar* padded;
	guchar* result;
	gpointer iv;
	gpointer value;
	gsize n_result;
	gsize n_iv;
	gsize n_value;
	gsize pos;

	iv = key_file_get_base64 (input, EXCHANGE_VERSION, "iv", &n_iv);
	if (iv == NULL || n_iv != EXCHANGE_1_IV_LENGTH) {
		g_message ("secret-exchange: invalid or missing iv");
		return NULL;
	}

	value = key_file_get_base64 (input, EXCHANGE_VERSION, "secret", &n_value);
	if (value == NULL) {
		g_message ("secret-exchange: invalid or missing value");
		g_free (iv);
		return NULL;
	}

	gcry = gcry_cipher_open (&cih, EXCHANGE_1_CIPHER_ALGO, EXCHANGE_1_CIPHER_MODE, 0);
	if (gcry != 0) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		g_free (iv);
		return FALSE;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, self->pv->key, EXCHANGE_1_KEY_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, EXCHANGE_1_IV_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	g_free (iv);

	/* Allocate memory for the result */
	padded = egg_secure_alloc (n_value);

	for (pos = 0; pos < n_value; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, padded + pos, 16, (guchar*)value + pos, 16);
		g_return_val_if_fail (gcry == 0, NULL);
	}

	gcry_cipher_close (cih);

	/* This does an extra null-terminator of output */
	if (!egg_padding_pkcs7_unpad (egg_secure_realloc, 16, padded, n_value,
	                              (gpointer*)&result, &n_result))
		result = NULL;

	egg_secure_free (padded);

	*n_secret = n_result;
	return result;
}

/**
 * gcr_secret_exchange_receive:
 * @self: a #GcrSecretExchange object
 * @exchange: the string received
 *
 * Receive a string from the other side of secret exchange. This string will
 * have been created by gcr_secret_exchange_begin() or gcr_secret_exchange_send()
 *
 * Returns: whether the string was successfully parsed and received
 */
gboolean
gcr_secret_exchange_receive (GcrSecretExchange *self,
                             const gchar *exchange)
{
	GKeyFile *input;
	gchar *secret;
	gsize n_secret;
	gboolean ret;

	/* Parse the input */
	input = g_key_file_new ();
	if (!g_key_file_load_from_data (input, exchange, strlen (exchange),
	                                G_KEY_FILE_NONE, NULL)) {
		g_key_file_free (input);
		g_message ("couldn't parse secret exchange data");
		return FALSE;
	}

	if (self->pv->priv == NULL) {
		if (!egg_dh_gen_pair (self->pv->prime, self->pv->base, 0,
		                      &self->pv->pub, &self->pv->priv))
			g_return_val_if_reached (FALSE);
	}

	if (!calculate_key (self, input))
		return FALSE;

	ret = TRUE;

	if (g_key_file_has_key (input, EXCHANGE_VERSION, "secret", NULL)) {
		secret = perform_aes_decrypt (self, input, &n_secret);
		if (secret == NULL) {
			ret = FALSE;
		} else {
			egg_secure_free (self->pv->secret);
			self->pv->secret = secret;
			self->pv->n_secret = n_secret;
		}
	}

	return ret;
}

/**
 * gcr_secret_exchange_get_secret:
 * @self: a #GcrSecretExchange object
 * @secret_len: (allow-none): optionally, a location to store the length of returned secret
 *
 * Returns the last secret received. If no secret has yet been received this
 * will return %NULL. The string is owned by the #GcrSecretExchange object
 * and will be valid until the next time that gcr_secret_exchange_receive()
 * is called on this object, or the object is destroyed.
 *
 * Depending on the secret passed into the other side of the secret exchange,
 * the resurt may be a binary string. It does however have a null terminator,
 * so if you're certain that it is does not contain arbitrary binary data,
 * it can be used as a string.
 *
 * Returns: (transfer none): The last secret received.
 */
const gchar *
gcr_secret_exchange_get_secret (GcrSecretExchange *self,
                                gsize *secret_len)
{
	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), NULL);

	if (secret_len)
		*secret_len = self->pv->n_secret;
	return self->pv->secret;
}

static gpointer
calculate_iv (GKeyFile *output)
{
	gpointer iv;

	iv = g_malloc0 (EXCHANGE_1_IV_LENGTH);
	gcry_create_nonce (iv, EXCHANGE_1_IV_LENGTH);
	key_file_set_base64 (output, EXCHANGE_VERSION, "iv", iv, EXCHANGE_1_IV_LENGTH);

	return iv;
}

static gboolean
perform_aes_encrypt (GKeyFile *output,
                     gconstpointer key,
                     const gchar *secret,
                     gsize n_secret)
{
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	guchar* padded;
	guchar* result;
	gpointer iv;
	gsize n_result;
	gsize pos;

	iv = calculate_iv (output);
	g_return_val_if_fail (iv != NULL, FALSE);

	gcry = gcry_cipher_open (&cih, EXCHANGE_1_CIPHER_ALGO, EXCHANGE_1_CIPHER_MODE, 0);
	if (gcry != 0) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		g_free (iv);
		return FALSE;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, key, EXCHANGE_1_KEY_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, EXCHANGE_1_IV_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	g_free (iv);

	/* Pad the text properly */
	if (!egg_padding_pkcs7_pad (egg_secure_realloc, 16, secret, n_secret,
	                            (gpointer*)&padded, &n_result))
		g_return_val_if_reached (FALSE);
	result = g_malloc0 (n_result);

	for (pos = 0; pos < n_result; pos += 16) {
		gcry = gcry_cipher_encrypt (cih, result + pos, 16, padded + pos, 16);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	egg_secure_clear (padded, n_result);
	egg_secure_free (padded);

	key_file_set_base64 (output, EXCHANGE_VERSION, "secret", result, n_result);
	g_free (result);

	return TRUE;
}

/**
 * gcr_secret_exchange_send:
 * @self: a #GcrSecretExchange object
 * @secret: (allow-none): optionally, a secret to send to the other side
 * @secret_len: length of @secret, or -1 if null terminated
 *
 * Send a reply to the other side of the secret exchange, optionally sending a
 * secret.
 *
 * gcr_secret_exchange_receive() must have been successfully called at least
 * once on this object. In other words this object must have received data
 * from the other side of the secret exchange, before we can send a secret.
 *
 * Returns: (transfer full): a newly allocated string to be sent to the other
 *     side of the secret exchange
 */
gchar *
gcr_secret_exchange_send (GcrSecretExchange *self,
                          const gchar *secret,
                          gssize secret_len)
{
	GKeyFile *output;
	gchar *result;

	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), NULL);

	if (self->pv->key == NULL) {
		g_warning ("gcr_secret_exchange_receive() must be called "
		           "before calling this function");
		return NULL;
	}

	output = g_key_file_new ();
	key_file_set_mpi (output, EXCHANGE_VERSION, "public", self->pv->pub);

	if (secret != NULL) {
		if (secret_len < 0)
			secret_len = strlen (secret);
		if (!perform_aes_encrypt (output, self->pv->key, secret, secret_len)) {
			g_key_file_free (output);
			return NULL;
		}
	}

	result = g_key_file_to_data (output, NULL, NULL);
	g_return_val_if_fail (result != NULL, NULL);
	g_key_file_free (output);
	return result;
}
