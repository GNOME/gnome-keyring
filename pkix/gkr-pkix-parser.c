/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-parser.c - A parser for PKI objects

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

#include "config.h"

#include <string.h>

#include <glib.h>
#include <glib/gi18n.h>

#include <gcrypt.h>
#include <libtasn1.h>

#include "gkr-pkix-asn1.h"
#include "gkr-pkix-der.h"
#include "gkr-pkix-marshal.h"
#include "gkr-pkix-openssl.h"
#include "gkr-pkix-parser.h"
#include "gkr-pkix-pem.h"

#include "common/gkr-crypto.h"
#include "common/gkr-location.h"
#include "common/gkr-secure-memory.h"

#include "library/gnome-keyring.h"
#include "library/gnome-keyring-memory.h"

/* -----------------------------------------------------------------------------
 * QUARK DEFINITIONS
 */

/* 
 * PEM STRINGS 
 * The xxxxx in: ----- BEGIN xxxxx ------
 */ 
 
static GQuark PEM_CERTIFICATE;
static GQuark PEM_RSA_PRIVATE_KEY;
static GQuark PEM_DSA_PRIVATE_KEY;
static GQuark PEM_ANY_PRIVATE_KEY;
static GQuark PEM_ENCRYPTED_PRIVATE_KEY;
static GQuark PEM_PRIVATE_KEY;
static GQuark PEM_PKCS7;
static GQuark PEM_PKCS12;

/* 
 * OIDS
 */
static GQuark OID_PKIX1_RSA;
static GQuark OID_PKIX1_DSA;
static GQuark OID_PKCS7_DATA;
static GQuark OID_PKCS7_SIGNED_DATA;
static GQuark OID_PKCS7_ENCRYPTED_DATA;
static GQuark OID_PKCS12_BAG_PKCS8_KEY;
static GQuark OID_PKCS12_BAG_PKCS8_ENCRYPTED_KEY;
static GQuark OID_PKCS12_BAG_CERTIFICATE;
static GQuark OID_PKCS12_BAG_CRL;

static void
init_quarks (void)
{
	#define QUARK(name, value) \
		name = g_quark_from_static_string(value)
 
	QUARK (OID_PKIX1_RSA, "1.2.840.113549.1.1.1");
	QUARK (OID_PKIX1_DSA, "1.2.840.10040.4.1");
	QUARK (OID_PKCS7_DATA, "1.2.840.113549.1.7.1");
	QUARK (OID_PKCS7_SIGNED_DATA, "1.2.840.113549.1.7.2");
	QUARK (OID_PKCS7_ENCRYPTED_DATA, "1.2.840.113549.1.7.6");
	QUARK (OID_PKCS12_BAG_PKCS8_KEY, "1.2.840.113549.1.12.10.1.1");
	QUARK (OID_PKCS12_BAG_PKCS8_ENCRYPTED_KEY, "1.2.840.113549.1.12.10.1.2");
	QUARK (OID_PKCS12_BAG_CERTIFICATE, "1.2.840.113549.1.12.10.1.3");
	QUARK (OID_PKCS12_BAG_CRL, "1.2.840.113549.1.12.10.1.4");
	
	QUARK (PEM_CERTIFICATE, "CERTIFICATE");
	QUARK (PEM_PRIVATE_KEY, "PRIVATE KEY");
	QUARK (PEM_RSA_PRIVATE_KEY, "RSA PRIVATE KEY");
	QUARK (PEM_DSA_PRIVATE_KEY, "DSA PRIVATE KEY");
	QUARK (PEM_ANY_PRIVATE_KEY, "ANY PRIVATE KEY");
	QUARK (PEM_ENCRYPTED_PRIVATE_KEY, "ENCRYPTED PRIVATE KEY");
	QUARK (PEM_PKCS7, "PKCS7");
	QUARK (PEM_PKCS12, "PKCS12");
	
	#undef QUARK
}

/* -----------------------------------------------------------------------------
 * DEFINES
 */


typedef struct {
	GQuark location;
	gint ask_state;
	GSList *seen;
} PasswordState;

#define PASSWORD_STATE_INIT { 0, 0, NULL}

typedef struct {
	GSList *seen_passwords;
} GkrPkixParserPrivate;

enum {
	PARSED_PARTIAL,
	PARSED_SEXP,
	PARSED_ASN1,
	ASK_PASSWORD,
	LAST_SIGNAL
};

#define GKR_PKIX_PARSER_GET_PRIVATE(o) \
      (G_TYPE_INSTANCE_GET_PRIVATE((o), GKR_TYPE_PKIX_PARSER, GkrPkixParserPrivate))

G_DEFINE_TYPE (GkrPkixParser, gkr_pkix_parser, G_TYPE_OBJECT);

static guint signals[LAST_SIGNAL] = { 0 }; 

/* -----------------------------------------------------------------------------
 * HELPERS
 */
 
static gboolean
enum_next_password (GkrPkixParser *parser, GQuark loc, gkrid digest, 
                    GQuark type, const gchar *label, PasswordState *state, 
                    const gchar **password)
{
	GkrPkixParserPrivate *pv = GKR_PKIX_PARSER_GET_PRIVATE (parser);
	gboolean first = FALSE;
	gchar *display = NULL;
	gchar *prompted;
	gboolean result;
	GSList *l;

	if (gkr_async_is_stopping ())
		return FALSE;

	/* Is it a new location, reset stuff */
	if (loc != state->location) {
		state->seen = NULL;
		state->ask_state = 0;
		state->location = loc;
	}

	/* 
	 * Next passes we look through all the passwords that the parser 
	 * has seen so far. This is because different parts of a encrypted
	 * container (such as PKCS#12) often use the same password even 
	 * if with different algorithms. 
	 * 
	 * If we didn't do this and the user chooses enters a password, 
	 * but doesn't save it, they would get prompted for the same thing
	 * over and over, dumb.  
	 */
	if (!state->seen) {
		state->seen = pv->seen_passwords;
		first = TRUE;
	}

	l = state->seen;
	
	/* Return first seen password? */
	if (first && l && l->data) {
		*password = (const gchar*)l->data;
		return TRUE;
	}
	
	/* Return next seen password? */
	if (l && l->next) {
		l = state->seen = state->seen->next;
		if (l->data) {
			*password = (const gchar*)l->data;
			return TRUE;
		}
	}
	
	/* 
	 * And lastly we actually prompt for a password. This prompt might
	 * also lookup saved passwords for this location.
	 */
	if (!label) 
		label = display = gkr_location_to_display (loc);
	
	g_signal_emit (parser, signals[ASK_PASSWORD], 0, 
	               loc, digest, type, label, &state->ask_state, 
	               &prompted, &result);
	               
	g_free (display);
	
	/* Stash away any password */
	if (result) {
		if (prompted)
			pv->seen_passwords = g_slist_prepend (pv->seen_passwords, prompted);
		*password = prompted;
		return TRUE;
	}
	
	return FALSE;
}

static void
fire_parsed_partial (GkrPkixParser *parser, GQuark location, 
                     gkrconstid digest, GQuark type)
{
	gboolean owned = FALSE;
	
	g_assert (location);
	
	if (!gkr_async_is_stopping ())
		g_signal_emit (parser, signals[PARSED_PARTIAL], 0, location, digest, type, &owned);
}

static void
fire_parsed_sexp (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                  GQuark type, gcry_sexp_t sexp)
{
	gboolean owned = FALSE;
	
	g_assert (sexp);
	g_assert (type);
	
	if (!gkr_async_is_stopping ())
		g_signal_emit (parser, signals[PARSED_SEXP], 0, location, digest, type, sexp, &owned);
	if (!owned)
		gcry_sexp_release (sexp);
}

static void
fire_parsed_asn1 (GkrPkixParser *parser, GQuark location, gkrconstid digest, 
                  GQuark type, ASN1_TYPE asn1)
{
	gboolean owned = FALSE;
	
	g_assert (asn1);
	g_assert (type);
	
	if (!gkr_async_is_stopping ())
		g_signal_emit (parser, signals[PARSED_ASN1], 0, location, digest, type, asn1, &owned);
	if (!owned)
		asn1_delete_structure (&asn1);
}

/* -----------------------------------------------------------------------------
 * OBJECT
 */
 
static void
gkr_pkix_parser_init (GkrPkixParser *parser)
{
	GkrPkixParserPrivate *pv = GKR_PKIX_PARSER_GET_PRIVATE (parser);
	pv->seen_passwords = NULL;	
}

static gboolean 
gkr_pkix_parser_parsed_partial (GkrPkixParser *parser, GQuark loc, gkrconstid digest, 
                                GQuark type)
{
	/* Didn't take ownership of the data */
	return FALSE;
}

static gboolean 
gkr_pkix_parser_parsed_asn1 (GkrPkixParser *parser, GQuark loc, gkrconstid digest, 
                             GQuark type, ASN1_TYPE asn1)
{
	/* Didn't take ownership of the data */
	return FALSE;
}

static gboolean 
gkr_pkix_parser_parsed_sexp (GkrPkixParser *parser, GQuark loc, gkrconstid digest, 
                             GQuark type, gcry_sexp_t sexp)
{
	/* Didn't take ownership of the data */
	return FALSE;
}

static gboolean
gkr_pkix_parser_ask_password (GkrPkixParser *parser, GQuark loc, gkrconstid digest,
                              GQuark type, const gchar *details, gint *state, 
                              gchar **password)
{
	*password = NULL;
	return FALSE;
}
	
static void
gkr_pkix_parser_finalize (GObject *obj)
{
	GkrPkixParser *parser = GKR_PKIX_PARSER (obj);
	GkrPkixParserPrivate *pv = GKR_PKIX_PARSER_GET_PRIVATE (parser);
	GSList *l;
	
	for (l = pv->seen_passwords; l; l = g_slist_next (l))
		gkr_secure_strfree (l->data);
	g_slist_free (pv->seen_passwords);
	
	G_OBJECT_CLASS (gkr_pkix_parser_parent_class)->finalize (obj);
}

static void
gkr_pkix_parser_class_init (GkrPkixParserClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	
	init_quarks ();

	gkr_pkix_parser_parent_class = g_type_class_peek_parent (klass);
	
	klass->parsed_partial = gkr_pkix_parser_parsed_partial;
	klass->parsed_sexp = gkr_pkix_parser_parsed_sexp;
	klass->parsed_asn1 = gkr_pkix_parser_parsed_asn1;
	klass->ask_password = gkr_pkix_parser_ask_password;
	
	gobject_class->finalize = gkr_pkix_parser_finalize;

	signals[PARSED_PARTIAL] = g_signal_new ("parsed-partial", GKR_TYPE_PKIX_PARSER, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GkrPkixParserClass, parsed_partial),
			g_signal_accumulator_true_handled, NULL, gkr_pkix_marshal_BOOLEAN__UINT_POINTER_UINT, 
			G_TYPE_BOOLEAN, 3, G_TYPE_UINT, G_TYPE_POINTER, G_TYPE_UINT);
			
	signals[PARSED_ASN1] = g_signal_new ("parsed-asn1", GKR_TYPE_PKIX_PARSER, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GkrPkixParserClass, parsed_asn1),
			g_signal_accumulator_true_handled, NULL, gkr_pkix_marshal_BOOLEAN__UINT_POINTER_UINT_POINTER, 
			G_TYPE_BOOLEAN, 4, G_TYPE_UINT, G_TYPE_POINTER, G_TYPE_UINT, G_TYPE_POINTER);

	signals[PARSED_SEXP] = g_signal_new ("parsed-sexp", GKR_TYPE_PKIX_PARSER, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GkrPkixParserClass, parsed_sexp),
			g_signal_accumulator_true_handled, NULL, gkr_pkix_marshal_BOOLEAN__UINT_POINTER_UINT_POINTER, 
			G_TYPE_BOOLEAN, 4, G_TYPE_UINT, G_TYPE_POINTER, G_TYPE_UINT, G_TYPE_POINTER);

	/* Due to our use of secure memory, we use a pointer as the signal return type */
	signals[ASK_PASSWORD] = g_signal_new ("ask-password", GKR_TYPE_PKIX_PARSER, 
			G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (GkrPkixParserClass, ask_password),
			g_signal_accumulator_true_handled, NULL, gkr_pkix_marshal_BOOLEAN__UINT_POINTER_UINT_STRING_POINTER_POINTER, 
			G_TYPE_BOOLEAN, 6, G_TYPE_UINT, G_TYPE_POINTER, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_POINTER);
			
	g_type_class_add_private (klass, sizeof (GkrPkixParserPrivate));
}

/* -----------------------------------------------------------------------------
 * PUBLIC
 */

GkrPkixParser*
gkr_pkix_parser_new (void)
{
	return g_object_new (GKR_TYPE_PKIX_PARSER, NULL);
}

GQuark
gkr_pkix_parser_get_error_domain (void)
{
	static GQuark domain = 0;
	if (domain == 0)
		domain = g_quark_from_static_string ("gkr-pkix-parse-error");
	return domain;
}

gboolean
gkr_pkix_parser_parse (GkrPkixParser *parser, GQuark loc, const guchar *data, 
                       gsize n_data, GError **err)
{
	GkrPkixResult ret;

	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), FALSE);
	g_return_val_if_fail (loc != 0, FALSE);
	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	if (n_data > 0) {
		ret = gkr_pkix_parser_der (parser, loc, data, n_data);
		if (ret == GKR_PKIX_UNRECOGNIZED)
			ret = gkr_pkix_parser_pem (parser, loc, data, n_data);
	}
	
	if (ret == GKR_PKIX_SUCCESS)
		return TRUE;
		
	switch (ret) {
	case GKR_PKIX_UNRECOGNIZED:
		g_set_error (err, GKR_PKIX_PARSE_ERROR, ret, "%s",
		             _("Unrecognized or unsupported file."));
		return FALSE;
	case GKR_PKIX_FAILURE:
		g_set_error (err, GKR_PKIX_PARSE_ERROR, ret, "%s",
		             _("Could not parse invalid or corrupted file."));
		return FALSE;
	default:
		g_assert_not_reached ();
		return FALSE;
	}
}


GkrPkixResult
gkr_pkix_parser_der (GkrPkixParser *parser, GQuark loc, 
                     const guchar *data, gsize n_data)
{
	GkrPkixResult ret = GKR_PKIX_UNRECOGNIZED;
	
	/*
	 * It's pretty much impossible to know what DER data belongs to 
	 * without parsing the entire thing. A few bytes of random data 
	 * will be valid for some ASN.1 spec most of the time.
	 * 
	 * So it's not unreasonable for us to just try and parse all the 
	 * different formats without trying to determine which one it 
	 * really is before hand.
	 */
	
	ret = gkr_pkix_parser_der_pkcs12 (parser, loc, data, n_data);
	if (ret != GKR_PKIX_UNRECOGNIZED)
		goto done;

	ret = gkr_pkix_parser_der_certificate (parser, loc, data, n_data);
	if (ret != GKR_PKIX_UNRECOGNIZED)
		goto done;

	ret = gkr_pkix_parser_der_private_key (parser, loc, data, n_data);
	if (ret != GKR_PKIX_UNRECOGNIZED)
		goto done;
		
	ret = gkr_pkix_parser_der_pkcs8 (parser, loc, data, n_data);
	if (ret != GKR_PKIX_UNRECOGNIZED)
		goto done;
		
	ret = gkr_pkix_parser_der_pkcs7 (parser, loc, data, n_data);
	if (ret != GKR_PKIX_UNRECOGNIZED)
		goto done;
		
done:
	return ret;
}

gboolean
gkr_pkix_parser_parse_location (GkrPkixParser *parser, GQuark loc, GError **err)
{
	GMappedFile *mapped;
	gboolean ret;
	const guchar *data;
	gsize n_data; 
	gchar *path;
	
	g_return_val_if_fail (GKR_IS_PKIX_PARSER (parser), FALSE);
	g_return_val_if_fail (loc != 0, FALSE);
	g_return_val_if_fail (!err || !*err, FALSE);
	
	path = gkr_location_to_path (loc);
	if (!path) {
		g_set_error (err, G_FILE_ERROR, G_FILE_ERROR_NODEV, "%s",  
		             _("The disk or drive this file is located on is not present"));
		return FALSE;
	}

	mapped = g_mapped_file_new (path, FALSE, err);
	g_free (path);
	
	if (!mapped) {
		/* err is already set */
		return FALSE;
	} 

	data = (const guchar*)g_mapped_file_get_contents (mapped);
	n_data = g_mapped_file_get_length (mapped);
	
	ret = gkr_pkix_parser_parse (parser, loc, data, n_data, err);
		
	g_mapped_file_free (mapped);
	
	return ret;
}

/* -----------------------------------------------------------------------------
 * PRIVATE KEYS
 */

GkrPkixResult
gkr_pkix_parser_der_private_key (GkrPkixParser *parser, GQuark loc,
                                 const guchar *data, gsize n_data)
{
	gkrid digest;
	GkrPkixResult ret;
	gcry_sexp_t s_key = NULL;
	
	digest = gkr_id_new_digest (data, n_data);
	
	ret = gkr_pkix_der_read_private_key_rsa (data, n_data, &s_key);
	if (ret == GKR_PKIX_UNRECOGNIZED)
		ret = gkr_pkix_der_read_private_key_dsa (data, n_data, &s_key);
	if (ret == GKR_PKIX_SUCCESS)
		fire_parsed_sexp (parser, loc, digest, GKR_PKIX_PRIVATE_KEY, s_key);
		
	gkr_id_free (digest);
	
	return ret;
}

static GkrPkixResult
parse_der_pkcs8_plain (GkrPkixParser *parser, GQuark loc, 
                       gkrid digest, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret;
	int algorithm;
	GQuark key_algo;
	const guchar *keydata;
	gsize n_keydata;
	const guchar *params;
	gsize n_params;
	gcry_sexp_t s_key = NULL;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-8-PrivateKeyInfo", data, n_data);
	if (!asn)
		goto done;

	ret = GKR_PKIX_FAILURE;
	algorithm = 0;
		
	key_algo = gkr_pkix_asn1_read_oid (asn, "privateKeyAlgorithm.algorithm");
  	if (!key_algo)
  		goto done;
  	else if (key_algo == OID_PKIX1_RSA)
  		algorithm = GCRY_PK_RSA;
  	else if (key_algo == OID_PKIX1_DSA)
  		algorithm = GCRY_PK_DSA;
  		
  	if (!algorithm) {
  		ret = GKR_PKIX_UNRECOGNIZED;
  		goto done;
  	}

	keydata = gkr_pkix_asn1_read_content (asn, data, n_data, "privateKey", &n_keydata);
	if (!keydata)
		goto done;
		
	params = gkr_pkix_asn1_read_element (asn, data, n_data, "privateKeyAlgorithm.parameters", 
	                                     &n_params);
		
	ret = GKR_PKIX_SUCCESS;
	
done:
	if (ret == GKR_PKIX_SUCCESS) {		
		switch (algorithm) {
		case GCRY_PK_RSA:
			ret = gkr_pkix_der_read_private_key_rsa (keydata, n_keydata, &s_key);
			break;
		case GCRY_PK_DSA:
			/* Try the normal sane format */
			ret = gkr_pkix_der_read_private_key_dsa (keydata, n_keydata, &s_key);
			
			/* Otherwise try the two part format that everyone seems to like */
			if (ret == GKR_PKIX_UNRECOGNIZED && params && n_params)
				ret = gkr_pkix_der_read_private_key_dsa_parts (keydata, n_keydata, 
				                                               params, n_params, &s_key);
			
			break;
		default:
			g_message ("invalid or unsupported key type in PKCS#8 key");
			ret = GKR_PKIX_UNRECOGNIZED;
			break;
		};
		
		if (ret == GKR_PKIX_SUCCESS)
			fire_parsed_sexp (parser, loc, digest, GKR_PKIX_PRIVATE_KEY, s_key);
		
	} else if (ret == GKR_PKIX_FAILURE) {
		g_message ("invalid PKCS#8 key");
	}
	
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

GkrPkixResult
gkr_pkix_parser_der_pkcs8_plain (GkrPkixParser *parser, GQuark location, 
                                 const guchar *data, gsize n_data)
{
	gkrid digest;
	GkrPkixResult ret;
	
	digest = gkr_id_new_digest (data, n_data);
	ret = parse_der_pkcs8_plain (parser, location, digest, data, n_data);
	gkr_id_free (digest);
	
	return ret;
}

static GkrPkixResult
parse_der_pkcs8_encrypted (GkrPkixParser *parser, GQuark location, 
                           gkrid digest, const guchar *data, gsize n_data)
{
	PasswordState pstate = PASSWORD_STATE_INIT;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_cipher_hd_t cih = NULL;
	gcry_error_t gcry;
	GkrPkixResult ret, r;
	GQuark scheme;
	guchar *crypted = NULL;
	const guchar *params;
	gsize n_crypted, n_params;
	const gchar *password;
	gint l;

	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-8-EncryptedPrivateKeyInfo", data, n_data);
	if (!asn)
		goto done;

	ret = GKR_PKIX_FAILURE;

	/* Figure out the type of encryption */
	scheme = gkr_pkix_asn1_read_oid (asn, "encryptionAlgorithm.algorithm");
	if (!scheme)
		goto done;
		
	params = gkr_pkix_asn1_read_element (asn, data, n_data, "encryptionAlgorithm.parameters", &n_params);

	/* Loop to try different passwords */                       
	for (;;) {
		
		g_assert (cih == NULL);
		
    	/* If no password is available, we still know it's a key, so 'partial' parse */
        if (!enum_next_password (parser, location, digest, GKR_PKIX_PRIVATE_KEY, NULL, &pstate, &password)) {
        	fire_parsed_partial (parser, location, digest, GKR_PKIX_PRIVATE_KEY);
        	ret = GKR_PKIX_SUCCESS;
        	goto done; 
        }
	        
		/* 
		 * Parse the encryption stuff into a cipher. 
		 */
		r = gkr_pkix_der_read_cipher (scheme, password, params, n_params, &cih);
		if (r == GKR_PKIX_UNRECOGNIZED) {
			ret = GKR_PKIX_FAILURE;
			goto done;
		} else if (r != GKR_PKIX_SUCCESS) {
			ret = r;
			goto done;
		}
			
		crypted = gkr_pkix_asn1_read_value (asn, "encryptedData", &n_crypted, 
		                                    gkr_secure_realloc);
		if (!crypted)
			goto done;
	
		gcry = gcry_cipher_decrypt (cih, crypted, n_crypted, NULL, 0);
		gcry_cipher_close (cih);
		cih = NULL;
		
		if (gcry != 0) {
			g_warning ("couldn't decrypt pkcs8 data: %s", gcry_strerror (gcry));
			goto done;
		}
		
		/* Unpad the DER data */
		l = gkr_pkix_asn1_element_length (crypted, n_crypted);
		if (l > 0)
			n_crypted = l;
		
		/* Try to parse the resulting key */
		r = parse_der_pkcs8_plain (parser, location, digest, crypted, n_crypted);
		gkr_secure_free (crypted);
		crypted = NULL;
		
		if (r != GKR_PKIX_UNRECOGNIZED) {
			ret = r;
			break;
		}
		
		/* We assume unrecognized data, is a bad encryption key */	
	}
		
done:
	if (cih)
		gcry_cipher_close (cih);
	if (asn)
		asn1_delete_structure (&asn);
	gkr_secure_free (crypted);
		
	return ret;
}

GkrPkixResult
gkr_pkix_parser_der_pkcs8_encrypted (GkrPkixParser *parser, GQuark location, 
                                     const guchar *data, gsize n_data)
{
	gkrid digest;
	GkrPkixResult ret;
	
	digest = gkr_id_new_digest (data, n_data);
	ret = parse_der_pkcs8_encrypted (parser, location, digest, data, n_data);
	gkr_id_free (digest);
	
	return ret;
}

GkrPkixResult
gkr_pkix_parser_der_pkcs8 (GkrPkixParser *parser, GQuark loc, const guchar *data, 
                           gsize n_data)
{
	gkrid digest;
	GkrPkixResult ret;
	
	digest = gkr_id_new_digest (data, n_data);
	ret = parse_der_pkcs8_plain (parser, loc, digest, data, n_data);
	if (ret == GKR_PKIX_UNRECOGNIZED)
		ret = parse_der_pkcs8_encrypted (parser, loc, digest, data, n_data);
	gkr_id_free (digest);
	
	return ret;
}

/* -----------------------------------------------------------------------------
 * X509 stuff
 */

GkrPkixResult
gkr_pkix_parser_der_certificate (GkrPkixParser *parser, GQuark loc, 
                                 const guchar *data, gsize n_data)
{
	gkrid digest;
	GkrPkixResult ret;
	ASN1_TYPE asn1;
	
	digest = gkr_id_new_digest (data, n_data);

	ret = gkr_pkix_der_read_certificate (data, n_data, &asn1);	
	if(ret == GKR_PKIX_SUCCESS)
		fire_parsed_asn1 (parser, loc, digest, GKR_PKIX_CERTIFICATE, asn1);
	gkr_id_free (digest);
	
	return ret;
}

/* -----------------------------------------------------------------------------
 * CONTAINER FORMATS
 */

static GkrPkixResult
parse_pkcs12_cert_bag (GkrPkixParser *parser, GQuark loc, gkrid digest, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	ASN1_TYPE casn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret;
	const guchar *certificate;
	gsize n_certificate;

	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-12-CertBag", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PKIX_FAILURE;
	
	certificate = gkr_pkix_asn1_read_content (asn, data, n_data, "certValue", &n_certificate);
	if (!certificate)
		goto done;

	/* 
	 * Wrapped in an OCTET STRING, so unwrap here, rather than allocating 
	 * a whole bunch more memory for a full ASN.1 parsing context.
	 */ 
	certificate = gkr_pkix_asn1_element_content (certificate, n_certificate, &n_certificate);
	if (!certificate)
		goto done;
	
	ret = gkr_pkix_der_read_certificate (certificate, n_certificate, &casn);
	if(ret == GKR_PKIX_SUCCESS)
		fire_parsed_asn1 (parser, loc, digest, GKR_PKIX_CERTIFICATE, casn);
		
done:
	if (asn)
		asn1_delete_structure (&asn);
		
	return ret;
}

static GkrPkixResult
parse_pkcs12_bag (GkrPkixParser *parser, GQuark loc, gkrid digest, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret, r;
	int res, count = 0;
	GQuark oid;
	const guchar *element;
	gsize n_element;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-12-SafeContents", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PKIX_FAILURE;
	
	/* Get the number of elements in this bag */
	res = asn1_number_of_elements (asn, "", &count);
	if (res != ASN1_SUCCESS)
		goto done;	
	
	/* 
	 * Now inside each bag are multiple elements. Who comes up 
	 * with this stuff?
	 * 
	 * But this is where we draw the line. We only support one
	 * element per bag, not multiple elements, not strange
	 * nested bags, not fairy queens with magical wands in bags...
	 * 
	 * Just one element per bag.
	 */
	if (count >= 1) {

		oid = gkr_pkix_asn1_read_oid (asn, "?1.bagId");
		if (!oid)
			goto done;
		
		element = gkr_pkix_asn1_read_content (asn, data, n_data, "?1.bagValue", &n_element); 	
		if (!element)
			goto done;

		/* A normal unencrypted key */
		if (oid == OID_PKCS12_BAG_PKCS8_KEY) {
			r = parse_der_pkcs8_plain (parser, loc, digest, element, n_element);
			
		/* A properly encrypted key */
		} else if (oid == OID_PKCS12_BAG_PKCS8_ENCRYPTED_KEY) {
			r = parse_der_pkcs8_encrypted (parser, loc, digest, element, n_element);
			
		/* A certificate */
		} else if (oid == OID_PKCS12_BAG_CERTIFICATE) {
			r = parse_pkcs12_cert_bag (parser, loc, digest, element, n_element);
								
		/* TODO: OID_PKCS12_BAG_CRL */
		} else {
			r = GKR_PKIX_UNRECOGNIZED;
		}
		 
		if (r == GKR_PKIX_FAILURE) {
			ret = r;
			goto done;
		}
	}

	ret = GKR_PKIX_SUCCESS;	
		
done:
	if (asn)
		asn1_delete_structure (&asn);
		
	return ret;
}

static GkrPkixResult
parse_pkcs12_encrypted_bag (GkrPkixParser *parser, GQuark loc, gkrid digest, 
                            const guchar *data, gsize n_data)
{
	PasswordState pstate = PASSWORD_STATE_INIT;
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	gcry_cipher_hd_t cih = NULL;
	gcry_error_t gcry;
	GkrPkixResult ret, r;
	guchar *crypted = NULL;
	const guchar *params;
	gsize n_params, n_crypted;
	const gchar *password;
	GQuark scheme;
	gint l;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-7-EncryptedData", data, n_data);
	if (!asn)
		goto done;
	
	ret = GKR_PKIX_FAILURE;
		
	/* Check the encryption schema OID */
	scheme = gkr_pkix_asn1_read_oid (asn, "encryptedContentInfo.contentEncryptionAlgorithm.algorithm");
	if (!scheme) 
		goto done;	

	params = gkr_pkix_asn1_read_element (asn, data, n_data, "encryptedContentInfo.contentEncryptionAlgorithm.parameters", &n_params);
	if (!params)
		goto done;

	/* Loop to try different passwords */                       
	for (;;) {
		
		g_assert (cih == NULL);
		
	        if (!enum_next_password (parser, loc, digest, 0, NULL, &pstate, &password)) {
	        	fire_parsed_partial (parser, loc, digest, 0);
	        	ret = GKR_PKIX_SUCCESS;
	        	goto done; 
	        }
	        
		/* Parse the encryption stuff into a cipher. */
		r = gkr_pkix_der_read_cipher (scheme, password, params, n_params, &cih);
		if (r == GKR_PKIX_UNRECOGNIZED) {
			ret = GKR_PKIX_FAILURE;
			goto done;
		} else if (r != GKR_PKIX_SUCCESS) {
			ret = r;
			goto done;
		}
			
		crypted = gkr_pkix_asn1_read_value (asn, "encryptedContentInfo.encryptedContent", 
		                                    &n_crypted, gkr_secure_realloc);
		if (!crypted)
			goto done;
	
		gcry = gcry_cipher_decrypt (cih, crypted, n_crypted, NULL, 0);
		gcry_cipher_close (cih);
		cih = NULL;
		
		if (gcry != 0) {
			g_warning ("couldn't decrypt pkcs7 data: %s", gcry_strerror (gcry));
			goto done;
		}
		
		/* Unpad the DER data */
		l = gkr_pkix_asn1_element_length (crypted, n_crypted);
		if (l > 0)
			n_crypted = l;

		/* Try to parse the resulting key */
		r = parse_pkcs12_bag (parser, loc, digest, crypted, n_crypted);
		gkr_secure_free (crypted);
		crypted = NULL;
		
		if (r != GKR_PKIX_UNRECOGNIZED) {
			ret = r;
			break;
		}
		
		/* We assume unrecognized data is a bad encryption key */	
	}
		
done:
	if (cih)
		gcry_cipher_close (cih);
	if (asn)
		asn1_delete_structure (&asn);
	gkr_secure_free (crypted);
	
	return ret;
}

static GkrPkixResult
parse_pkcs12_safe (GkrPkixParser *parser, GQuark loc, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret, r;
	const guchar *bag;
	gkrid digest = NULL;
	gsize n_bag;
	gchar *part;
	GQuark oid;
	guint i;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-12-AuthenticatedSafe", data, n_data);
	if (!asn)
		goto done;
		
	ret = GKR_PKIX_FAILURE;
	
	/*
	 * Inside each PKCS12 safe there are multiple bags. 
	 */
	for (i = 0; TRUE; ++i) {
		
		part = g_strdup_printf ("?%u.contentType", i + 1);
		oid = gkr_pkix_asn1_read_oid (asn, part);
		g_free (part);
		
		/* All done? no more bags */
		if (!oid) 
			break;
		
		part = g_strdup_printf ("?%u.content", i + 1);
		bag = gkr_pkix_asn1_read_content (asn, data, n_data, part, &n_bag);
		g_free (part);
		
		if (!bag) /* A parse error */
			goto done;
			
		gkr_id_free (digest);
		digest = gkr_id_new_digest (bag, n_bag);
			
		/* A non encrypted bag, just parse */
		if (oid == OID_PKCS7_DATA) {
			
			/* 
		 	 * Wrapped in an OCTET STRING, so unwrap here, rather than allocating 
		 	 * a whole bunch more memory for a full ASN.1 parsing context.
		 	 */ 
			bag = gkr_pkix_asn1_element_content (bag, n_bag, &n_bag);
			if (!bag)
				goto done;	
			
			r = parse_pkcs12_bag (parser, loc, digest, bag, n_bag);

		/* Encrypted data first needs decryption */
		} else if (oid == OID_PKCS7_ENCRYPTED_DATA) {
			r = parse_pkcs12_encrypted_bag (parser, loc, digest, bag, n_bag);
		
		/* Hmmmm, not sure what this is */
		} else {
			g_warning ("unrecognized type of safe content in pkcs12: %s", g_quark_to_string (oid));
			r = GKR_PKIX_UNRECOGNIZED;
		}
		
		if (r == GKR_PKIX_FAILURE) {
			ret = r;
			goto done;
		}
	}
	
	ret = GKR_PKIX_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	if (digest)
		gkr_id_free (digest);
		
	return ret;
}

GkrPkixResult
gkr_pkix_parser_der_pkcs12 (GkrPkixParser *parser, GQuark loc, const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret;
	const guchar* content = NULL;
	gsize n_content;
	GQuark oid;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-12-PFX", data, n_data);
	if (!asn)
		goto done;

	oid = gkr_pkix_asn1_read_oid (asn, "authSafe.contentType");
	if (!oid)
		goto done;
		
	/* Outer most one must just be plain data */
	if (oid != OID_PKCS7_DATA) {
		g_message ("unsupported safe content type in pkcs12: %s", g_quark_to_string (oid));
		goto done;
	}
	
	content = gkr_pkix_asn1_read_content (asn, data, n_data, "authSafe.content", &n_content);
	if (!content)
		goto done;
		
	/* 
	 * Wrapped in an OCTET STRING, so unwrap here, rather than allocating 
	 * a whole bunch more memory for a full ASN.1 parsing context.
	 */ 
	content = gkr_pkix_asn1_element_content (content, n_content, &n_content);
	if (!content)
		goto done;
				
	ret = parse_pkcs12_safe (parser, loc, content, n_content);
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

static GkrPkixResult
parse_pkcs7_signed_data (GkrPkixParser *parser, GQuark loc, gkrid digest, 
                         const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	ASN1_TYPE casn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret;
	gchar *part;
	const guchar *certificate;
	gsize n_certificate;
	int i;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-7-SignedData", data, n_data);
	if (!asn)
		goto done;

	ret = GKR_PKIX_FAILURE;
	
	for (i = 0; TRUE; ++i) {
			
		part = g_strdup_printf ("certificates.?%u", i + 1);
		certificate = gkr_pkix_asn1_read_element (asn, data, n_data, part, &n_certificate);
		g_free (part);
		
		/* No more certificates? */
		if (!certificate)
			break;
	
		ret = gkr_pkix_der_read_certificate (certificate, n_certificate, &casn);
		if (ret == GKR_PKIX_SUCCESS)
			fire_parsed_asn1 (parser, loc, digest, GKR_PKIX_CERTIFICATE, casn);
		if (ret == GKR_PKIX_FAILURE)
			goto done;
	}
	
	/* TODO: Parse out all the CRLs */
	
	ret = GKR_PKIX_SUCCESS;
	
done:
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

static GkrPkixResult
parse_der_pkcs7 (GkrPkixParser *parser, GQuark loc, gkrid digest, 
                 const guchar *data, gsize n_data)
{
	ASN1_TYPE asn = ASN1_TYPE_EMPTY;
	GkrPkixResult ret;
	const guchar* content = NULL;
	gsize n_content;
	GQuark oid;
	
	ret = GKR_PKIX_UNRECOGNIZED;
	
	asn = gkr_pkix_asn1_decode ("PKIX1.pkcs-7-ContentInfo", data, n_data);
	if (!asn)
		goto done;

	ret = GKR_PKIX_FAILURE;

	oid = gkr_pkix_asn1_read_oid (asn, "contentType");
	if (!oid)
		goto done;

	/* Outer most one must just be plain data */
	if (oid != OID_PKCS7_SIGNED_DATA) {
		g_message ("unsupported outer content type in pkcs7: %s", g_quark_to_string (oid));
		goto done;
	}
	
	content = gkr_pkix_asn1_read_content (asn, data, n_data, "content", &n_content);
	if (!content) 
		goto done;
		
	ret = parse_pkcs7_signed_data (parser, loc, digest, content, n_content);
			
done:
	if (asn)
		asn1_delete_structure (&asn);
	return ret;
}

GkrPkixResult
gkr_pkix_parser_der_pkcs7 (GkrPkixParser *parser, GQuark loc, const guchar *data, gsize n_data)
{
	GkrPkixResult ret;
	gkrid digest;
	
	digest = gkr_id_new_digest (data, n_data);
	ret = parse_der_pkcs7 (parser, loc, digest, data, n_data);
	gkr_id_free (digest);
	
	return ret;
}

typedef struct {
	GkrPkixParser *parser;
	GQuark location;
	GkrPkixResult result;
} ParserCtx;

static GQuark
pem_to_parsed_type (gint type)
{
	if (type == PEM_RSA_PRIVATE_KEY ||
	    type == PEM_DSA_PRIVATE_KEY ||
	    type == PEM_ANY_PRIVATE_KEY ||
	    type == PEM_PRIVATE_KEY ||
	    type == PEM_ENCRYPTED_PRIVATE_KEY)
	    	return GKR_PKIX_PRIVATE_KEY;

	else if (type == PEM_CERTIFICATE)
		return GKR_PKIX_CERTIFICATE;
		
	else if (type == PEM_PKCS7 ||
	         type == PEM_PKCS12)
		return 0;

	return 0;
}

static GkrPkixResult
parse_plain_pem (GkrPkixParser *parser, GQuark location, gkrid digest, 
                 GQuark type, const guchar *data, gsize n_data)
{
	GkrPkixResult res;
	gcry_sexp_t s_key = NULL;
	ASN1_TYPE asn1 = NULL;
	GQuark parsed = 0;
	
	if (type == PEM_RSA_PRIVATE_KEY) {
		parsed = GKR_PKIX_PRIVATE_KEY;
		res = gkr_pkix_der_read_private_key_rsa (data, n_data, &s_key);

	} else if (type == PEM_DSA_PRIVATE_KEY) {
		parsed = GKR_PKIX_PRIVATE_KEY;
		res = gkr_pkix_der_read_private_key_dsa (data, n_data, &s_key);

	} else if (type == PEM_ANY_PRIVATE_KEY) {
		parsed = GKR_PKIX_PRIVATE_KEY;
		res = gkr_pkix_der_read_private_key (data, n_data, &s_key);
	
	} else if (type == PEM_PRIVATE_KEY) {
		return parse_der_pkcs8_plain (parser, location, digest, data, n_data);
		
	} else if (type == PEM_ENCRYPTED_PRIVATE_KEY) {
		return parse_der_pkcs8_encrypted (parser, location, digest, data, n_data);
		
	} else if (type == PEM_CERTIFICATE) {
		parsed = GKR_PKIX_CERTIFICATE;
		res = gkr_pkix_der_read_certificate (data, n_data, &asn1);
		
	} else if (type == PEM_PKCS7) {
		return parse_der_pkcs7 (parser, location, digest, data, n_data);
		
	} else if (type == PEM_PKCS7) {
		return gkr_pkix_parser_der_pkcs12 (parser, location, data, n_data);
		
	} else {
		res = GKR_PKIX_UNRECOGNIZED;
	}
	
	if (res == GKR_PKIX_SUCCESS) {
		g_assert (s_key || asn1);
		g_assert (parsed);
		
		if (s_key)
			fire_parsed_sexp (parser, location, digest, parsed, s_key);
		else
			fire_parsed_asn1 (parser, location, digest, parsed, asn1);
	}

	return res;
}

static GkrPkixResult
parse_encrypted_pem (GkrPkixParser *parser, GQuark location, gkrid digest, 
                     GQuark type, GHashTable *headers, const guchar *data, gsize n_data)
{
	PasswordState pstate = PASSWORD_STATE_INIT;
	GQuark parsed;
	GkrPkixResult ret;
	const gchar *val;
	const gchar *password;
	guchar *decrypted;
	gsize n_decrypted;
	gboolean res;
	gint l;
	
	g_assert (parser);
	g_assert (headers);
	g_assert (type);
	
	val = g_hash_table_lookup (headers, "DEK-Info");
	if (!val) {
		g_message ("missing encryption header");
		return GKR_PKIX_FAILURE;
	}
	
	parsed = pem_to_parsed_type (type);
	if (!parsed) 
		return GKR_PKIX_UNRECOGNIZED;
		
	while (!gkr_async_is_stopping ()) {

    	/* If no password is available, we still know what it was, so 'partial' parse */
		if (!enum_next_password (parser, location, digest, parsed, NULL, &pstate, &password)) {
        	fire_parsed_partial (parser, location, digest, parsed);
        	return GKR_PKIX_SUCCESS;
        }
		
		decrypted = NULL;
		n_decrypted = 0;
		
		/* Decrypt, this will result in garble if invalid password */	
		res = gkr_pkix_openssl_decrypt_block (val, password, data, n_data, 
		                                      &decrypted, &n_decrypted);
		if (!res)
			return GKR_PKIX_FAILURE;
			
		g_assert (decrypted);
		
		/* Unpad the DER data */
		l = gkr_pkix_asn1_element_length (decrypted, n_decrypted);
		if (l > 0)
			n_decrypted = l;
	
		/* Try to parse */
		ret = parse_plain_pem (parser, location, digest, type, decrypted, n_decrypted);
		gkr_secure_free (decrypted);

		if (ret != GKR_PKIX_UNRECOGNIZED)
			return ret;		
	}
	
	return GKR_PKIX_FAILURE;
}

static void
handle_pem_data (GQuark type, const guchar *data, gsize n_data,
                 GHashTable *headers, gpointer user_data)
{
	ParserCtx *ctx = (ParserCtx*)user_data;
	GkrPkixResult res = GKR_PKIX_FAILURE;
	gboolean encrypted = FALSE;
	gkrid digest;
	const gchar *val;
	
	digest = gkr_id_new_digest (data, n_data);

	/* See if it's encrypted PEM all openssl like*/
	if (headers) {
		val = g_hash_table_lookup (headers, "Proc-Type");
		if (val && strcmp (val, "4,ENCRYPTED") == 0) 
			encrypted = TRUE;
	}
	
	if (encrypted) {
		res = parse_encrypted_pem (ctx->parser, ctx->location, digest,
		                           type, headers, data, n_data); 
	} else {
		res = parse_plain_pem (ctx->parser, ctx->location, digest, 
		                       type, data, n_data);
	}
	
	if (res == GKR_PKIX_FAILURE) {
		ctx->result = res;
	} else if (ctx->result == GKR_PKIX_UNRECOGNIZED)
		ctx->result = res;
		
	gkr_id_free (digest);
}

GkrPkixResult
gkr_pkix_parser_pem (GkrPkixParser *parser, GQuark loc, const guchar *data, gsize n_data)
{
	ParserCtx ctx = { parser, loc, GKR_PKIX_UNRECOGNIZED };
	guint found;
	
	if (n_data == 0)
		return GKR_PKIX_UNRECOGNIZED;
	
	found = gkr_pkix_pem_parse (data, n_data, handle_pem_data, &ctx);
	
	if (found == 0)
		return GKR_PKIX_UNRECOGNIZED;
		
	return ctx.result;
}
