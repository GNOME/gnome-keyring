/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-ssh-agent-private.h - Private SSH agent declarations

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

#include "egg/egg-buffer.h"

#include "pkcs11/pkcs11.h"

#include <gp11/gp11.h>

#include <glib.h>

typedef struct _GckSshAgentCall {
	int sock;
	GP11Module *module;
	EggBuffer *req;
	EggBuffer *resp;
} GckSshAgentCall;

/* -----------------------------------------------------------------------------
 * SSH OPERATIONS and CONSTANTS
 */

/* Requests from client to daemon */
#define GCK_SSH_OP_REQUEST_RSA_IDENTITIES		1
#define GCK_SSH_OP_RSA_CHALLENGE			3
#define GCK_SSH_OP_ADD_RSA_IDENTITY			7
#define GCK_SSH_OP_REMOVE_RSA_IDENTITY			8
#define GCK_SSH_OP_REMOVE_ALL_RSA_IDENTITIES		9
#define GCK_SSH_OP_REQUEST_IDENTITIES			11
#define GCK_SSH_OP_SIGN_REQUEST				13
#define GCK_SSH_OP_ADD_IDENTITY				17
#define GCK_SSH_OP_REMOVE_IDENTITY			18
#define GCK_SSH_OP_REMOVE_ALL_IDENTITIES		19
#define GCK_SSH_OP_ADD_SMARTCARD_KEY			20
#define GCK_SSH_OP_REMOVE_SMARTCARD_KEY			21
#define GCK_SSH_OP_LOCK					22
#define GCK_SSH_OP_UNLOCK				23
#define GCK_SSH_OP_ADD_RSA_ID_CONSTRAINED		24
#define GCK_SSH_OP_ADD_ID_CONSTRAINED			25
#define GCK_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED 	26

#define GCK_SSH_OP_MAX                                  27  

/* Responses from daemon to client */
#define GCK_SSH_RES_RSA_IDENTITIES_ANSWER		2
#define GCK_SSH_RES_RSA_RESPONSE			4
#define GCK_SSH_RES_FAILURE				5
#define GCK_SSH_RES_SUCCESS				6
#define GCK_SSH_RES_IDENTITIES_ANSWER			12
#define GCK_SSH_RES_SIGN_RESPONSE			14
#define GCK_SSH_RES_EXTENDED_FAILURE			30
#define GCK_SSH_RES_SSHCOM_FAILURE			102


#define	GCK_SSH_FLAG_CONSTRAIN_LIFETIME			1
#define	GCK_SSH_FLAG_CONSTRAIN_CONFIRM			2

#define GCK_SSH_DSA_SIGNATURE_PADDING                   20
#define	GCK_SSH_FLAG_OLD_SIGNATURE			0x01

/* -----------------------------------------------------------------------------
 * gck-ssh-agent-ops.c
 */

typedef gboolean (*GckSshAgentOperation) (GckSshAgentCall *call);
extern const GckSshAgentOperation gck_ssh_agent_operations[GCK_SSH_OP_MAX];

/* -----------------------------------------------------------------------------
 * gck-ssh-agent.c
 */

gboolean              gck_ssh_agent_initialize_with_module          (GP11Module *module);

GP11Session*          gck_ssh_agent_checkout_main_session           (void);

void                  gck_ssh_agent_checkin_main_session            (GP11Session* session);

/* -----------------------------------------------------------------------------
 * gkr-ssh-proto.c
 */

gulong                gck_ssh_agent_proto_keytype_to_algo           (const gchar *salgo);

const gchar*          gck_ssh_agent_proto_algo_to_keytype           (gulong algo);

gboolean              gck_ssh_agent_proto_read_mpi                  (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs, 
                                                                     CK_ATTRIBUTE_TYPE type);

gboolean              gck_ssh_agent_proto_read_mpi_v1               (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs,
                                                                     CK_ATTRIBUTE_TYPE type);

const guchar*         gck_ssh_agent_proto_read_challenge_v1         (EggBuffer *req,
                                                                     gsize *offset,
                                                                     gsize *n_challenge);
                                                                     
gboolean              gck_ssh_agent_proto_write_mpi                 (EggBuffer *resp, 
                                                                     GP11Attribute *attr);

gboolean              gck_ssh_agent_proto_write_mpi_v1              (EggBuffer *resp, 
                                                                     GP11Attribute *attr);

gboolean              gck_ssh_agent_proto_read_public               (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs, 
                                                                     gulong *algo);

gboolean              gck_ssh_agent_proto_read_public_rsa           (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_read_public_dsa           (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_read_public_v1            (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_read_pair_rsa             (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *priv_attrs,
                                                                     GP11Attributes *pub_attrs);

gboolean              gck_ssh_agent_proto_read_pair_dsa             (EggBuffer *req, 
                                                                     gsize *offset, 
                                                                     GP11Attributes *priv_attrs,
                                                                     GP11Attributes *pub_attrs);

gboolean              gck_ssh_agent_proto_read_pair_v1              (EggBuffer *req,
                                                                     gsize *offset, 
                                                                     GP11Attributes *priv_attrs,
                                                                     GP11Attributes *pub_attrs);

gboolean              gck_ssh_agent_proto_write_public              (EggBuffer *resp, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_write_public_rsa          (EggBuffer *resp, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_write_public_dsa          (EggBuffer *resp, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_write_public_v1           (EggBuffer *resp, 
                                                                     GP11Attributes *attrs);

gboolean              gck_ssh_agent_proto_write_signature_rsa       (EggBuffer *resp, 
                                                                     CK_BYTE_PTR signature, 
                                                                     CK_ULONG n_signature);

gboolean              gck_ssh_agent_proto_write_signature_dsa       (EggBuffer *resp, 
                                                                     CK_BYTE_PTR signature, 
                                                                     CK_ULONG n_signature);

#endif /*GKRSSHPRIVATE_H_*/
