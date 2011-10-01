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

EGG_SECURE_DECLARE (secret_exchange);

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

/**
 * GCR_SECRET_EXCHANGE_PROTOCOL_1:
 *
 * The current secret exchange protocol. Key agreement is done using DH with the
 * 1536 bit IKE parameter group. Keys are derived using SHA256 with HKDF. The
 * transport encryption is done with 128 bit AES.
 */

#define SECRET_EXCHANGE_PROTOCOL_1_PREFIX "[" GCR_SECRET_EXCHANGE_PROTOCOL_1 "]\n"

enum {
	PROP_0,
	PROP_PROTOCOL
};

typedef struct _GcrSecretExchangeDefault GcrSecretExchangeDefault;

struct _GcrSecretExchangePrivate {
	GcrSecretExchangeDefault *default_exchange;
	GDestroyNotify destroy_exchange;
	gboolean explicit_protocol;
	gboolean generated;
	guchar *publi;
	gsize n_publi;
	gboolean derived;
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
gcr_secret_exchange_init (GcrSecretExchange *self)
{
	self->pv = G_TYPE_INSTANCE_GET_PRIVATE (self, GCR_TYPE_SECRET_EXCHANGE,
	                                        GcrSecretExchangePrivate);
}


static void
gcr_secret_exchange_set_property (GObject *obj,
                                  guint prop_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
	GcrSecretExchange *self = GCR_SECRET_EXCHANGE (obj);
	const gchar *protocol;

	switch (prop_id) {
	case PROP_PROTOCOL:
		protocol = g_value_get_string (value);
		if (protocol != NULL) {
			if (g_str_equal (protocol, GCR_SECRET_EXCHANGE_PROTOCOL_1))
				self->pv->explicit_protocol = TRUE;
			else
				g_warning ("the GcrSecretExchange protocol %s is unsupported defaulting to %s",
				           protocol, GCR_SECRET_EXCHANGE_PROTOCOL_1);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
gcr_secret_exchange_get_property (GObject *obj,
                                  guint prop_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
	GcrSecretExchange *self = GCR_SECRET_EXCHANGE (obj);

	switch (prop_id) {
	case PROP_PROTOCOL:
		g_value_set_string (value, gcr_secret_exchange_get_protocol (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
		break;
	}
}

static void
clear_secret_exchange (GcrSecretExchange *self)
{
	g_free (self->pv->publi);
	self->pv->publi = NULL;
	self->pv->n_publi = 0;
	self->pv->derived = FALSE;
	self->pv->generated = TRUE;
	egg_secure_free (self->pv->secret);
	self->pv->secret = NULL;
	self->pv->n_secret = 0;
}

static void
gcr_secret_exchange_finalize (GObject *obj)
{
	GcrSecretExchange *self = GCR_SECRET_EXCHANGE (obj);

	if (self->pv->destroy_exchange)
		(self->pv->destroy_exchange) (self->pv->default_exchange);

	clear_secret_exchange (self);

	G_OBJECT_CLASS (gcr_secret_exchange_parent_class)->finalize (obj);
}

/**
 * gcr_secret_exchange_new:
 * @protocol: (allow-none): the exchange protocol to use
 *
 * Create a new secret exchange object.
 *
 * Specify a protocol of %NULL to allow any protocol. This is especially
 * relevant on the side of the exchange that does not call
 * gcr_secret_exchange_begin(), that is the originator. Currently the only
 * protocol supported is %GCR_SECRET_EXCHANGE_PROTOCOL_1.
 *
 * Returns: (transfer full): A new #GcrSecretExchange object
 */
GcrSecretExchange *
gcr_secret_exchange_new (const gchar *protocol)
{
	return g_object_new (GCR_TYPE_SECRET_EXCHANGE,
	                     "protocol", protocol,
	                     NULL);
}

/**
 * gcr_secret_exchange_get_protocol:
 * @self: a #GcrSecretExchange object
 * Get the secret exchange protocol.
 *
 * Will return %NULL if no protocol was specified, and either
 * gcr_secret_exchange_begin() or gcr_secret_exchange_receive() have not been
 * called successfully.
 *
 * Returns: the protocol or %NULL
 */
const gchar *
gcr_secret_exchange_get_protocol (GcrSecretExchange *self)
{
	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), NULL);
	if (self->pv->explicit_protocol || self->pv->generated)
		return GCR_SECRET_EXCHANGE_PROTOCOL_1;
	return NULL;
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
	GcrSecretExchangeClass *klass;
	GKeyFile *output;
	gchar *result;

	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), NULL);

	klass = GCR_SECRET_EXCHANGE_GET_CLASS (self);
	g_return_val_if_fail (klass->generate_exchange_key, NULL);

	clear_secret_exchange (self);

	output = g_key_file_new ();

	if (!(klass->generate_exchange_key) (self, GCR_SECRET_EXCHANGE_PROTOCOL_1,
	                                     &self->pv->publi, &self->pv->n_publi))
		g_return_val_if_reached (NULL);
	self->pv->generated = TRUE;

	key_file_set_base64 (output, GCR_SECRET_EXCHANGE_PROTOCOL_1, "public",
	                     self->pv->publi, self->pv->n_publi);

	result = g_key_file_to_data (output, NULL, NULL);
	g_return_val_if_fail (result != NULL, NULL);

	g_strchomp (result);

	if (g_str_has_prefix (result, SECRET_EXCHANGE_PROTOCOL_1_PREFIX))
		g_warning ("the prepared data does not have the correct protocol prefix");

	g_key_file_free (output);

	return result;
}

static gboolean
derive_key (GcrSecretExchange *self,
            GKeyFile *input)
{
	GcrSecretExchangeClass *klass;
	gboolean ret;
	guchar *peer;
	gsize n_peer;

	klass = GCR_SECRET_EXCHANGE_GET_CLASS (self);
	g_return_val_if_fail (klass->derive_transport_key, FALSE);

	peer = key_file_get_base64 (input, GCR_SECRET_EXCHANGE_PROTOCOL_1, "public", &n_peer);
	if (peer == NULL) {
		g_message ("secret-exchange: invalid or missing 'public' argument");
		return FALSE;
	}

	ret = (klass->derive_transport_key) (self, peer, n_peer);
	self->pv->derived = ret;

	g_free (peer);
	return ret;
}

static gboolean
perform_decrypt (GcrSecretExchange *self,
                 GKeyFile *input,
                 guchar **secret,
                 gsize *n_secret)
{
	GcrSecretExchangeClass *klass;
	gpointer iv, value;
	guchar *result;
	gsize n_result, n_iv, n_value;
	gboolean ret;

	klass = GCR_SECRET_EXCHANGE_GET_CLASS (self);
	g_return_val_if_fail (klass->decrypt_transport_data, FALSE);

	iv = key_file_get_base64 (input, GCR_SECRET_EXCHANGE_PROTOCOL_1, "iv", &n_iv);

	value = key_file_get_base64 (input, GCR_SECRET_EXCHANGE_PROTOCOL_1, "secret", &n_value);
	if (value == NULL) {
		g_message ("secret-exchange: invalid or missing value");
		g_free (iv);
		return FALSE;
	}

	ret = (klass->decrypt_transport_data) (self, egg_secure_realloc, value, n_value,
	                                       iv, n_iv, &result, &n_result);

	g_free (value);
	g_free (iv);

	if (!ret)
		return FALSE;

	/* Reallocate a null terminator */
	if (result) {
		result = egg_secure_realloc (result, n_result + 1);
		result[n_result] = 0;
	}

	*secret = result;
	*n_secret = n_result;

	return TRUE;
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
	GcrSecretExchangeClass *klass;
	GKeyFile *input;
	gchar *secret;
	gsize n_secret;
	gboolean ret;

	g_return_val_if_fail (GCR_IS_SECRET_EXCHANGE (self), FALSE);
	g_return_val_if_fail (exchange != NULL, FALSE);

	klass = GCR_SECRET_EXCHANGE_GET_CLASS (self);
	g_return_val_if_fail (klass->generate_exchange_key, FALSE);
	g_return_val_if_fail (klass->derive_transport_key, FALSE);

	/* Parse the input */
	input = g_key_file_new ();
	if (!g_key_file_load_from_data (input, exchange, strlen (exchange),
	                                G_KEY_FILE_NONE, NULL)) {
		g_key_file_free (input);
		g_message ("couldn't parse secret exchange data");
		return FALSE;
	}

	if (!self->pv->generated) {
		if (!(klass->generate_exchange_key) (self, GCR_SECRET_EXCHANGE_PROTOCOL_1,
		                                     &self->pv->publi, &self->pv->n_publi))
			g_return_val_if_reached (FALSE);
		self->pv->generated = TRUE;
	}

	if (!self->pv->derived) {
		if (!derive_key (self, input))
			return FALSE;
	}

	ret = TRUE;

	if (g_key_file_has_key (input, GCR_SECRET_EXCHANGE_PROTOCOL_1, "secret", NULL)) {

		/* Remember that this can return a NULL secret */
		if (!perform_decrypt (self, input, (guchar **)&secret, &n_secret)) {
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
 * Returns: (transfer none) (array length=secret_len): the last secret received
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

static gboolean
perform_encrypt (GcrSecretExchange *self,
                 GKeyFile *output,
                 const gchar *secret,
                 gsize n_secret)
{
	GcrSecretExchangeClass *klass;
	guchar *result, *iv;
	gsize n_result, n_iv;

	klass = GCR_SECRET_EXCHANGE_GET_CLASS (self);
	g_return_val_if_fail (klass->encrypt_transport_data, FALSE);

	if (!(klass->encrypt_transport_data) (self, g_realloc, (const guchar *)secret,
	                                      n_secret, &iv, &n_iv, &result, &n_result))
		return FALSE;

	key_file_set_base64 (output, GCR_SECRET_EXCHANGE_PROTOCOL_1, "secret", result, n_result);
	key_file_set_base64 (output, GCR_SECRET_EXCHANGE_PROTOCOL_1, "iv", iv, n_iv);

	g_free (result);
	g_free (iv);

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

	if (!self->pv->derived) {
		g_warning ("gcr_secret_exchange_receive() must be called "
		           "before calling this function");
		return NULL;
	}

	output = g_key_file_new ();
	key_file_set_base64 (output, GCR_SECRET_EXCHANGE_PROTOCOL_1, "public", self->pv->publi,
	                     self->pv->n_publi);

	if (secret != NULL) {
		if (secret_len < 0)
			secret_len = strlen (secret);
		if (!perform_encrypt (self, output, secret, secret_len)) {
			g_key_file_free (output);
			return NULL;
		}
	}

	result = g_key_file_to_data (output, NULL, NULL);
	g_return_val_if_fail (result != NULL, NULL);

	g_strchomp (result);

	if (g_str_has_prefix (result, SECRET_EXCHANGE_PROTOCOL_1_PREFIX))
		g_warning ("the prepared data does not have the correct protocol prefix");

	g_key_file_free (output);
	return result;
}

/*
 * This is the only set we support so far. It includes:
 *  - DH with the 1536 ike modp group for key exchange
 *  - HKDF SHA256 for hashing of the key to appropriate size
 *  - AES 128 CBC for encryption
 *  - PKCS#7 style padding
 */

#define EXCHANGE_1_IKE_NAME     "ietf-ike-grp-modp-1536"
#define EXCHANGE_1_KEY_LENGTH   16
#define EXCHANGE_1_IV_LENGTH    16
#define EXCHANGE_1_HASH_ALGO    "sha256"
#define EXCHANGE_1_CIPHER_ALGO  GCRY_CIPHER_AES128
#define EXCHANGE_1_CIPHER_MODE  GCRY_CIPHER_MODE_CBC

struct _GcrSecretExchangeDefault {
	gcry_mpi_t prime;
	gcry_mpi_t base;
	gcry_mpi_t pub;
	gcry_mpi_t priv;
	gpointer key;
};

static guchar *
mpi_to_data (gcry_mpi_t mpi,
             gsize *n_data)
{
	gcry_error_t gcry;
	guchar *data;

	/* Get the size */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, n_data, mpi);
	g_return_val_if_fail (gcry == 0, NULL);

	data = g_malloc0 (*n_data);

	/* Write into buffer */
	gcry = gcry_mpi_print (GCRYMPI_FMT_USG, data, *n_data, n_data, mpi);
	g_return_val_if_fail (gcry == 0, NULL);

	return data;
}

static gcry_mpi_t
mpi_from_data (const guchar *data,
               gsize n_data)
{
	gcry_mpi_t mpi;
	gcry_error_t gcry;

	gcry = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, data, n_data, NULL);
	return (gcry == 0) ? mpi : NULL;
}

static void
gcr_secret_exchange_default_free (gpointer to_free)
{
	GcrSecretExchangeDefault *data = to_free;
	gcry_mpi_release (data->prime);
	gcry_mpi_release (data->base);
	gcry_mpi_release (data->pub);
	gcry_mpi_release (data->priv);
	if (data->key) {
		egg_secure_clear (data->key, EXCHANGE_1_KEY_LENGTH);
		egg_secure_free (data->key);
	}
	g_free (data);
}

static gboolean
gcr_secret_exchange_default_generate_exchange_key (GcrSecretExchange *exchange,
                                                   const gchar *scheme,
                                                   guchar **public_key,
                                                   gsize *n_public_key)
{
	GcrSecretExchangeDefault *data = exchange->pv->default_exchange;

	if (data == NULL) {
		data = g_new0 (GcrSecretExchangeDefault, 1);
		if (!egg_dh_default_params (EXCHANGE_1_IKE_NAME, &data->prime, &data->base))
			g_return_val_if_reached (FALSE);

		exchange->pv->default_exchange = data;
		exchange->pv->destroy_exchange = gcr_secret_exchange_default_free;
	}

	gcry_mpi_release (data->priv);
	data->priv = NULL;
	gcry_mpi_release (data->pub);
	data->pub = NULL;
	egg_secure_free (data->key);
	data->key = NULL;

	if (!egg_dh_gen_pair (data->prime, data->base, 0,
	                      &data->pub, &data->priv))
		g_return_val_if_reached (FALSE);

	*public_key = mpi_to_data (data->pub, n_public_key);
	return *public_key != NULL;
}

static gboolean
gcr_secret_exchange_default_derive_transport_key (GcrSecretExchange *exchange,
                                                  const guchar *peer,
                                                  gsize n_peer)
{
	GcrSecretExchangeDefault *data = exchange->pv->default_exchange;
	gpointer ikm;
	gsize n_ikm;
	gcry_mpi_t mpi;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->priv != NULL, FALSE);

	mpi = mpi_from_data (peer, n_peer);
	if (mpi == NULL)
		return FALSE;

	/* Build up a key we can use */
	ikm = egg_dh_gen_secret (mpi, data->priv, data->prime, &n_ikm);
	g_return_val_if_fail (ikm != NULL, FALSE);

	if (data->key == NULL)
		data->key = egg_secure_alloc (EXCHANGE_1_KEY_LENGTH);

	if (!egg_hkdf_perform (EXCHANGE_1_HASH_ALGO, ikm, n_ikm, NULL, 0,
	                       NULL, 0, data->key, EXCHANGE_1_KEY_LENGTH))
		g_return_val_if_reached (FALSE);

	egg_secure_free (ikm);
	gcry_mpi_release (mpi);

	return TRUE;
}

static gboolean
gcr_secret_exchange_default_encrypt_transport_data (GcrSecretExchange *exchange,
                                                    GckAllocator allocator,
                                                    const guchar *plain_text,
                                                    gsize n_plain_text,
                                                    guchar **iv,
                                                    gsize *n_iv,
                                                    guchar **cipher_text,
                                                    gsize *n_cipher_text)
{
	GcrSecretExchangeDefault *data = exchange->pv->default_exchange;
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;
	guchar *padded;
	gsize n_result;
	guchar *result;
	gsize pos;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->key != NULL, FALSE);

	gcry = gcry_cipher_open (&cih, EXCHANGE_1_CIPHER_ALGO, EXCHANGE_1_CIPHER_MODE, 0);
	if (gcry != 0) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		g_free (iv);
		return FALSE;
	}

	*iv = (allocator) (NULL, EXCHANGE_1_IV_LENGTH);
	g_return_val_if_fail (*iv != NULL, FALSE);
	gcry_create_nonce (*iv, EXCHANGE_1_IV_LENGTH);
	*n_iv = EXCHANGE_1_IV_LENGTH;

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, data->key, EXCHANGE_1_KEY_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, *iv, EXCHANGE_1_IV_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Pad the text properly */
	if (!egg_padding_pkcs7_pad (egg_secure_realloc, 16, plain_text, n_plain_text,
	                            (gpointer*)&padded, &n_result))
		g_return_val_if_reached (FALSE);
	result = (allocator) (NULL, n_result);
	g_return_val_if_fail (result != NULL, FALSE);

	for (pos = 0; pos < n_result; pos += 16) {
		gcry = gcry_cipher_encrypt (cih, result + pos, 16, padded + pos, 16);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	egg_secure_clear (padded, n_result);
	egg_secure_free (padded);

	*cipher_text = result;
	*n_cipher_text = n_result;
	return TRUE;
}

static gboolean
gcr_secret_exchange_default_decrypt_transport_data (GcrSecretExchange *exchange,
                                                    GckAllocator allocator,
                                                    const guchar *cipher_text,
                                                    gsize n_cipher_text,
                                                    const guchar *iv,
                                                    gsize n_iv,
                                                    guchar **plain_text,
                                                    gsize *n_plain_text)
{
	GcrSecretExchangeDefault *data = exchange->pv->default_exchange;
	guchar* padded;
	guchar* result;
	gsize n_result;
	gsize pos;
	gcry_cipher_hd_t cih;
	gcry_error_t gcry;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->key != NULL, FALSE);

	if (iv == NULL || n_iv != EXCHANGE_1_IV_LENGTH) {
		g_message ("secret-exchange: invalid or missing iv");
		return FALSE;
	}

	if (n_cipher_text % 16 != 0) {
		g_message ("secret-message: invalid length for cipher text");
		return FALSE;
	}

	gcry = gcry_cipher_open (&cih, EXCHANGE_1_CIPHER_ALGO, EXCHANGE_1_CIPHER_MODE, 0);
	if (gcry != 0) {
		g_warning ("couldn't create aes cipher context: %s", gcry_strerror (gcry));
		return FALSE;
	}

	/* 16 = 128 bits */
	gcry = gcry_cipher_setkey (cih, data->key, EXCHANGE_1_KEY_LENGTH);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* 16 = 128 bits */
	gcry = gcry_cipher_setiv (cih, iv, n_iv);
	g_return_val_if_fail (gcry == 0, FALSE);

	/* Allocate memory for the result */
	padded = (allocator) (NULL, n_cipher_text);
	g_return_val_if_fail (padded != NULL, FALSE);

	for (pos = 0; pos < n_cipher_text; pos += 16) {
		gcry = gcry_cipher_decrypt (cih, padded + pos, 16, (guchar *)cipher_text + pos, 16);
		g_return_val_if_fail (gcry == 0, FALSE);
	}

	gcry_cipher_close (cih);

	if (!egg_padding_pkcs7_unpad (allocator, 16, padded, n_cipher_text,
	                              (gpointer*)&result, &n_result))
		result = NULL;

	/* Free the padded text */
	(allocator) (padded, 0);

	*plain_text = result;
	*n_plain_text = n_result;
	return TRUE;
}

static void
gcr_secret_exchange_class_init (GcrSecretExchangeClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->get_property = gcr_secret_exchange_get_property;
	gobject_class->set_property = gcr_secret_exchange_set_property;
	gobject_class->finalize = gcr_secret_exchange_finalize;

	klass->generate_exchange_key = gcr_secret_exchange_default_generate_exchange_key;
	klass->derive_transport_key = gcr_secret_exchange_default_derive_transport_key;
	klass->decrypt_transport_data = gcr_secret_exchange_default_decrypt_transport_data;
	klass->encrypt_transport_data = gcr_secret_exchange_default_encrypt_transport_data;

	g_type_class_add_private (gobject_class, sizeof (GcrSecretExchangePrivate));

	egg_libgcrypt_initialize ();

	/**
	 * GcrSecretExchange:protocol:
	 *
	 * The protocol being used for the exchange.
	 *
	 * Will be %NULL if no protocol was specified when creating this object,
	 * and either gcr_secret_exchange_begin() or gcr_secret_exchange_receive()
	 * have not been called successfully.
	 */
	g_object_class_install_property (gobject_class, PROP_PROTOCOL,
	           g_param_spec_string ("protocol", "Protocol", "Exchange protocol",
	                                GCR_SECRET_EXCHANGE_PROTOCOL_1,
	                                G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
