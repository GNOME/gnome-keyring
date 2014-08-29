/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkd-ssh-agent-private.h - Private SSH agent declarations

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

#ifndef GKDSSHPRIVATE_H_
#define GKDSSHPRIVATE_H_

#include "gkd-ssh-agent-client.h"

#include "egg/egg-buffer.h"

#include <glib.h>

typedef struct _GkdSshAgentCall {
	int sock;
	EggBuffer *req;
	EggBuffer *resp;
	GkdSshAgentClient *agent;
} GkdSshAgentCall;

/* -----------------------------------------------------------------------------
 * SSH OPERATIONS and CONSTANTS
 */

/* Requests from client to daemon */
#define GKD_SSH_OP_REQUEST_RSA_IDENTITIES               1
#define GKD_SSH_OP_RSA_CHALLENGE                        3
#define GKD_SSH_OP_ADD_RSA_IDENTITY                     7
#define GKD_SSH_OP_REMOVE_RSA_IDENTITY                  8
#define GKD_SSH_OP_REMOVE_ALL_RSA_IDENTITIES            9
#define GKD_SSH_OP_REQUEST_IDENTITIES                   11
#define GKD_SSH_OP_SIGN_REQUEST                         13
#define GKD_SSH_OP_ADD_IDENTITY                         17
#define GKD_SSH_OP_REMOVE_IDENTITY                      18
#define GKD_SSH_OP_REMOVE_ALL_IDENTITIES                19
#define GKD_SSH_OP_ADD_SMARTCARD_KEY                    20
#define GKD_SSH_OP_REMOVE_SMARTCARD_KEY                 21
#define GKD_SSH_OP_LOCK                                 22
#define GKD_SSH_OP_UNLOCK                               23
#define GKD_SSH_OP_ADD_RSA_ID_CONSTRAINED               24
#define GKD_SSH_OP_ADD_ID_CONSTRAINED                   25
#define GKD_SSH_OP_ADD_SMARTCARD_KEY_CONSTRAINED        26

#define GKD_SSH_OP_MAX                                  27

/* Responses from daemon to client */
#define GKD_SSH_RES_RSA_IDENTITIES_ANSWER               2
#define GKD_SSH_RES_RSA_RESPONSE                        4
#define GKD_SSH_RES_FAILURE                             5
#define GKD_SSH_RES_SUCCESS                             6
#define GKD_SSH_RES_IDENTITIES_ANSWER                   12
#define GKD_SSH_RES_SIGN_RESPONSE                       14
#define GKD_SSH_RES_EXTENDED_FAILURE                    30
#define GKD_SSH_RES_SSHCOM_FAILURE                      102


#define	GKD_SSH_FLAG_CONSTRAIN_LIFETIME                 1
#define	GKD_SSH_FLAG_CONSTRAIN_CONFIRM                  2

#define GKD_SSH_DSA_SIGNATURE_PADDING                   20
#define	GKD_SSH_FLAG_OLD_SIGNATURE                      0x01

/* -----------------------------------------------------------------------------
 * gkd-ssh-agent-ops.c
 */

typedef gboolean (*GkdSshAgentOperation) (GkdSshAgentCall *call);
extern const GkdSshAgentOperation gkd_ssh_agent_operations[GKD_SSH_OP_MAX];

/* -----------------------------------------------------------------------------
 * gkd-ssh-agent.c
 */

gboolean              gkd_ssh_agent_read_packet                     (gint fd,
                                                                     EggBuffer *buffer);

gboolean              gkd_ssh_agent_write_packet                    (gint fd,
                                                                     EggBuffer *buffer);

gboolean              gkd_ssh_agent_relay                           (GkdSshAgentCall *call);

#endif /*GKDSSHPRIVATE_H_*/
