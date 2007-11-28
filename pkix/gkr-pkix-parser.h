/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkix-parser.h - A parser for PKIX objects

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

#ifndef __GKR_PKIX_PARSER_H__
#define __GKR_PKIX_PARSER_H__

#include <glib-object.h>

#include <gcrypt.h>
#include <libtasn1.h>

#include "common/gkr-async.h"
#include "common/gkr-unique.h"

G_BEGIN_DECLS

typedef enum _GkrParseResult {
	GKR_PARSE_FAILURE = -1,
	GKR_PARSE_UNRECOGNIZED = 0,
	GKR_PARSE_SUCCESS = 1
} GkrParseResult;

typedef enum _GkrParsedType {
	GKR_PARSED_UNKNOWN = 0,
	GKR_PARSED_PRIVATE_KEY = 1,
	GKR_PARSED_CERTIFICATE = 2
} GkrParsedType;

#define GKR_PKIX_PARSE_ERROR             (gkr_pkix_parser_get_error_domain ())

#define GKR_TYPE_PKIX_PARSER             (gkr_pkix_parser_get_type ())
#define GKR_PKIX_PARSER(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), GKR_TYPE_PKIX_PARSER, GkrPkixParser))
#define GKR_PKIX_PARSER_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), GKR_TYPE_PKIX_PARSER, GkrPkixObject))
#define GKR_IS_PKIX_PARSER(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GKR_TYPE_PKIX_PARSER))
#define GKR_IS_PKIX_PARSER_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), GKR_TYPE_PKIX_PARSER))
#define GKR_PKIX_PARSER_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), GKR_TYPE_PKIX_PARSER, GkrPkixParserClass))

typedef struct _GkrPkixParser      GkrPkixParser;
typedef struct _GkrPkixParserClass GkrPkixParserClass;

struct _GkrPkixParser {
	 GObject parent;
};

struct _GkrPkixParserClass {
	GObjectClass parent_class;

	/* When an object is not fully parsed because of restrictions */	
	gboolean (*parsed_partial) (GkrPkixParser *parser, GQuark location, 
	                            gkrconstunique unique, GkrParsedType type);

	/* When an ASN.1 type object is parsed */
	gboolean (*parsed_asn1) (GkrPkixParser *parser, GQuark location, 
	                         gkrconstunique unique, GkrParsedType type,
	                         ASN1_TYPE asn1);

	/* When a gcrypt sexp is parsed */
	gboolean (*parsed_sexp) (GkrPkixParser *parser, GQuark location, 
	                         gkrconstunique unique, GkrParsedType type,
	                         gcry_sexp_t sexp);
	
	/* A callback for each password needed */
	gchar* (*ask_password) (GkrPkixParser *parser, GQuark location, 
	                        gkrconstunique unique, GkrParsedType type,
				const gchar *orig_label, guint failed);
};

GType               gkr_pkix_parser_get_type                (void) G_GNUC_CONST;

GQuark 	            gkr_pkix_parser_get_error_domain        (void) G_GNUC_CONST;

GkrPkixParser*      gkr_pkix_parser_new                     (void);

const gchar*        gkr_pkix_parsed_type_to_string          (GkrParsedType type);

gboolean            gkr_pkix_parser_parse                   (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data, 
                                                             GError **err);

gboolean            gkr_pkix_parser_parse_location          (GkrPkixParser *parser, GQuark loc, 
                                                             GError **err);

GkrParseResult      gkr_pkix_parser_der                     (GkrPkixParser *parser, GQuark loc, 
                                                             const guchar *data, gsize n_data);
                                                             
/* Private keys ------------------------------------------------------------- */

GkrParseResult      gkr_pkix_parser_der_private_key         (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data);

GkrParseResult      gkr_pkix_parser_der_pkcs8               (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data); 

GkrParseResult      gkr_pkix_parser_der_pkcs8_plain         (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data); 

GkrParseResult      gkr_pkix_parser_der_pkcs8_encrypted     (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data); 

/* X509 --------------------------------------------------------------------- */

GkrParseResult      gkr_pkix_parser_der_certificate         (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data);

#ifdef FUTURE

GkrParseResult      gkr_pkix_parser_der_crl                 (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data,
                                                             ASN1_TYPE *crl);

GkrParseResult      gkr_pkix_parser_der_pkcs10              (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data,
                                                             ASN1_TYPE *crl);
#endif

/* Container Formats -------------------------------------------------------- */

GkrParseResult      gkr_pkix_parser_pem                     (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data);

GkrParseResult      gkr_pkix_parser_der_pkcs12              (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data);

GkrParseResult      gkr_pkix_parser_der_pkcs7               (GkrPkixParser *parser, GQuark loc,
                                                             const guchar *data, gsize n_data);

G_END_DECLS

#endif /* __GKR_PKIX_PARSER_H__ */
