/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-private.h - Private SSH agent declarations

   Copyright (C) 2007 Stefan Walter

   Gnome keyring is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.
  
   Gnome keyring is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef GKRSSHPRIVATE_H_
#define GKRSSHPRIVATE_H_

#include "common/gkr-buffer.h"

#include <gcrypt.h>

#include <glib.h>

/* -----------------------------------------------------------------------------
 * SSH OPERATIONS and CONSTANTS
 */
 
/* Requests from client to daemon */
#define GKR_SSH_OP_REQUEST_RSA_IDENTITIES		1
#define GKR_SSH_OP_RSA_CHALLENGE			3
#define GKR_SSH_OP_ADD_RSA_IDENTITY			7
#define GKR_SSH_OP_REMOVE_RSA_IDENTITY			8
#define GKR_SSH_OP_REMOVE_ALL_RSA_IDENTITIES		9
#define GKR_SSH_OP_REQUEST_IDENTITIES			11
#define GKR_SSH_OP_SIGN_REQUEST				13
#define GKR_SSH_OP_ADD_IDENTITY				17
#define GKR_SSH_OP_REMOVE_IDENTITY			18
#define GKR_SSH_OP_REMOVE_ALL_IDENTITIES		19
#define GKR_SSH_OP_ADD_SMARTCARD_KEY			20
#define GKR_SSH_OP_REMOVE_SMARTCARD_KEY			21
#define GKR_SSH_OP_LOCK					22
#define GKR_SSH_OP_UNLOCK				23
#define GKR_SSH_OP_ADD_RSA_ID_CONSTRAINED		24
#define GKR_SSH_OP_ADD_ID_CONSTRAINED			25
#define GKR_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED 	26

#define GKR_SSH_OP_MAX                                  27  

/* Responses from daemon to client */
#define GKR_SSH_RES_RSA_IDENTITIES_ANSWER		2
#define GKR_SSH_RES_RSA_RESPONSE			4
#define GKR_SSH_RES_FAILURE				5
#define GKR_SSH_RES_SUCCESS				6
#define GKR_SSH_RES_IDENTITIES_ANSWER			12
#define GKR_SSH_RES_SIGN_RESPONSE			14
#define GKR_SSH_RES_EXTENDED_FAILURE			30
#define GKR_SSH_RES_SSHCOM_FAILURE			102


#define	GKR_SSH_FLAG_CONSTRAIN_LIFETIME			1
#define	GKR_SSH_FLAG_CONSTRAIN_CONFIRM			2

#define GKR_SSH_DSA_SIGNATURE_PADDING                   20
#define	GKR_SSH_FLAG_OLD_SIGNATURE			0x01

/* -----------------------------------------------------------------------------
 * gkr-ssh-daemon-io.c
 */

typedef gboolean (*GkrSshOperation) (GkrBuffer *req, GkrBuffer *resp);
extern const GkrSshOperation gkr_ssh_operations[GKR_SSH_OP_MAX];

/* -----------------------------------------------------------------------------
 * gkr-ssh-proto.c
 */

int                   gkr_ssh_proto_keytype_to_algo           (const gchar *salgo);

const gchar*          gkr_ssh_proto_algo_to_keytype           (int algo);

gboolean              gkr_ssh_proto_read_mpi                  (GkrBuffer *req, gsize *offset, gcry_mpi_t *mpi);

gboolean              gkr_ssh_proto_write_mpi                 (GkrBuffer *resp, gcry_mpi_t mpi, int format);

gboolean              gkr_ssh_proto_read_public               (GkrBuffer *req, gsize *offset, gcry_sexp_t *key, int *algo);

gboolean              gkr_ssh_proto_read_public_rsa           (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp);

gboolean              gkr_ssh_proto_read_public_dsa           (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp);

gboolean              gkr_ssh_proto_read_private_rsa          (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp);

gboolean              gkr_ssh_proto_read_private_dsa          (GkrBuffer *req, gsize *offset, gcry_sexp_t *sexp);

gboolean              gkr_ssh_proto_write_public              (GkrBuffer *resp, int algorithm, gcry_sexp_t key);

gboolean              gkr_ssh_proto_write_public_rsa          (GkrBuffer *resp, gcry_sexp_t key);

gboolean              gkr_ssh_proto_write_public_dsa          (GkrBuffer *resp, gcry_sexp_t key);

gboolean              gkr_ssh_proto_write_signature_rsa       (GkrBuffer *resp, gcry_sexp_t ssig);

gboolean              gkr_ssh_proto_write_signature_dsa       (GkrBuffer *resp, gcry_sexp_t ssig); 


#endif /*GKRSSHPRIVATE_H_*/
