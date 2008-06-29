/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pkcs11-module.c - a PKCS#11 module which communicates with gnome-keyring

   Copyright (C) 2007, Stefan Walter

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

#include "gkr-pkcs11-message.h"
#include "gkr-pkcs11-calls.h"
#include "gkr-pkcs11-mechanisms.h"
#include "pkcs11.h"

#include "common/gkr-buffer.h"
#include "common/gkr-secure-memory.h"
#include "common/gkr-unix-credentials.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* TODO: module fini should call finalize_common */

/* 
 * There are two kinds of mutex here. 
 * 
 * 1. The global_mutex. This is used to lock all global variables, and 
 *    the_sessions list.
 * 2. Each session has its own mutex. 
 */

/*
 * RULES: Growl! Bark! Woof!
 *
 *  - The mutexes must *always* be held in the above order! 
 *  - No external libraries.
 *  - All 'public' functions (ie: C_Xxxx) must check crypto_initialized 
 *    as their first order of business.
 */
 
/* -------------------------------------------------------------------
 * GLOBALS / DEFINES
 */

#define MANUFACTURER_ID         "GNOME Keyring                   "
#define LIBRARY_DESCRIPTION     "GNOME Keyring User Keys         "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1
#define SLOT_DESCRIPTION        "Keyring                                                         "
#define HARDWARE_VERSION_MAJOR  0
#define HARDWARE_VERSION_MINOR  0
#define FIRMWARE_VERSION_MAJOR  0
#define FIRMWARE_VERSION_MINOR  0
#define SLOT_TOKEN_SERIAL       "1.0             "
#define SLOT_TOKEN_MODEL        "1.0             "
#define MAX_PIN_LEN             256
#define MIN_PIN_LEN             1

/* protects all global variables, and session list */
static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t memory_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Whether we've been initialized, and on what process id it happened */
static int pkcs11_initialized = 0;
static pid_t crypto_pid = 0;
static char socket_path[1024] = { 0, };
static int slot_id = 0;

#ifndef ASSERT
#  ifdef G_DISABLE_ASSERT
#    define ASSERT(x)
#  else
#    include <assert.h>
#    define ASSERT(x) assert(x)
#  endif 
#endif

#define WARN(x) 	gkr_pkcs11_warn x
#define PREREQ(x, v) \
	if (!(x)) { gkr_pkcs11_warn ("'%s' not true at %s", #x, __func__); return v; } 

/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */

static void 
printva (const char* pref, const char* msg, va_list va)
{
	fprintf (stderr, "gnome-keyring-pkcs11 %s: ", pref);
	vfprintf (stderr, msg, va);
	fputc ('\n', stderr);
}

void 
gkr_pkcs11_warn (const char* msg, ...)
{
	va_list va;
	va_start (va, msg);
	printva ("WARNING", msg, va);
	va_end (va);
}

#ifdef _DEBUG 

static void 
gkr_pkcs11_debug (const char* msg, ...)
{
	va_list va;
	va_start (va, msg);
	printva ("DEBUG", msg, va);
	va_end (va);
}

#define DBG(x) 	gkr_pkcs11_debug x

#else /* !_DEBUG */

#define DBG(x)	

#endif /* _DEBUG */


/* -----------------------------------------------------------------------------
 * SECURE MEMORY
 *
 * These are called from gkr-secure-memory.c to provide appropriate
 * locking for memory between threads
 */ 

void
gkr_memory_lock (void)
{
	pthread_mutex_lock (&memory_mutex);
}

void 
gkr_memory_unlock (void)
{
	pthread_mutex_unlock (&memory_mutex);
}

void*
gkr_memory_fallback (void *p, unsigned long sz)
{
	return realloc (p, sz);	
}

/* -----------------------------------------------------------------------------
 * CALL SESSION
 */

enum CallState {
	CALL_INVALID,
	CALL_READY,
	CALL_PREP,
	CALL_TRANSIT,
	CALL_PARSE
};

typedef struct _CallSession {
	CK_ULONG id;                    /* Unique ID for this session */
	int call_state;                 /* Whether a call is happening or not */
	int socket;                     /* The connection we're sending on */

	GkrPkcs11Message *req;      /* The current request */
	GkrPkcs11Message *resp;     /* The current response */
	
	GkrPkcs11Message *overflow; /* The last request which overflowed */
	int overflowed;                 /* Flag used by response parsing code */

	CK_NOTIFY notify_callback;      /* Application specified callback */
	CK_VOID_PTR user_data;          /* Argument for above */

	int refs;                       /* Reference count */
	pthread_mutex_t mutex;          /* Mutex for protecting this structure */
} CallSession;

/* Allocator for call session buffers */
static void*
call_session_allocator (void* p, unsigned long sz)
{
	/* TODO: Do passwords or secrets pass through here? */
	void* res = realloc (p, (size_t)sz);
	if (!res && sz)
		WARN(("memory allocation of %lu bytes failed", sz));
	return res;	
}

/* 
 * Disconnects a call session. An active operation over this will 
 * respond by returning CKR_SESSION_CLOSED.
 */
static void
call_session_disconnect (CallSession *cs)
{
	ASSERT (cs);
	
	if (cs->socket != -1) {
		DBG (("S%d: disconnected", cs->id));
		close (cs->socket);
		cs->socket = -1;
	}
}

/* 
 * Destroy's a call session. This is done by call_session_unref_and_unlock()
 * when the reference count reaches 0.
 */
static void
call_session_destroy (CallSession* cs)
{
	ASSERT (cs);
	ASSERT (cs->refs == 0);
	
	call_session_disconnect (cs);
	ASSERT (cs->socket == -1);
	
	gkr_pkcs11_message_free (cs->req);
	gkr_pkcs11_message_free (cs->resp);
	gkr_pkcs11_message_free (cs->overflow);
	
	pthread_mutex_destroy (&cs->mutex);
	
	DBG (("S%d: destroyed", cs->id));
	free (cs);
}

/* 
 * Allocate a new call session. Called from C_OpenSession() the session is 
 * not ready for use after this call. 
 */
static CallSession*
call_session_create ()
{
	CallSession *cs = calloc (1, sizeof (CallSession));
	if (!cs)
		return NULL;
	
	if (pthread_mutex_init (&cs->mutex, NULL) != 0) {
		free (cs);
		return NULL;
	}
	
	cs->req = NULL;
	cs->resp = NULL;
	cs->overflow = NULL;
	cs->id = 0;
	cs->call_state = CALL_INVALID;
	cs->socket = -1;
	cs->overflowed = 0;
	cs->refs = 0;
	
	DBG (("S0: created"));
	return cs;
}

/* 
 * Connect a newly created call session to gnome-keyring-daemon. The socket
 * path was discovered in C_Initialize()
 */
static CK_RV
call_session_connect (CallSession *cs)
{
	struct sockaddr_un addr;
	int sock;

	ASSERT (cs);
	ASSERT (cs->socket == -1);
	ASSERT (cs->call_state == CALL_INVALID);
	ASSERT (pkcs11_initialized);
	
	/* Yup, no environment variable == no token */
	if (!socket_path[0]) {
		WARN (("S%d: no socket available to connect session to"));
		return CKR_TOKEN_NOT_PRESENT;
	}

	DBG (("S%d: connecting to: %s", cs->id, socket_path));
		
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));
	
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		WARN (("S%d: couldn't open socket: %s", 
		       cs->id, strerror (errno)));
		return CKR_DEVICE_ERROR;
	}

	/* close on exec */
	if (fcntl (sock, F_SETFD, 1) == -1) {
		close (sock);
		WARN (("S%d: couldn't secure socket: %s", 
		       cs->id, strerror (errno)));
		return CKR_DEVICE_ERROR;
	}

	if (connect (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		close (sock);
		WARN (("S%d: couldn't connect to: %s: %s", 
		       cs->id, socket_path, strerror (errno)));
		return CKR_DEVICE_ERROR;
	}

	if (gkr_unix_credentials_write (sock) < 0) {
		close (sock);
		WARN (("S%d: couldn't send socket credentials: %s", 
		       cs->id, strerror (errno)));
		return CKR_DEVICE_ERROR;
	}

	cs->socket = sock;
	cs->call_state = CALL_READY;
	DBG (("S%d: connected", cs->id));
	
	return CKR_OK;
}

/* 
 * Perform the initial setup for a new call via a session. 
 */
static CK_RV
call_session_prep_call (CallSession *cs, int call_id)
{
	CK_RV ret;
	
	ASSERT (cs);
	ASSERT (cs->call_state > CALL_INVALID);

	/* Only one call can happen at once */
	if (cs->call_state > CALL_READY) {
		WARN (("S%d: a session call is active", cs->id));
		return CKR_OPERATION_ACTIVE;
	}

	ASSERT (cs->call_state == CALL_READY);
	ASSERT (!cs->overflowed);

	/* Is the socket closed? */
	if (cs->socket == -1) {
		WARN (("S%d: session has been closed", cs->id));
		return CKR_SESSION_CLOSED;
	}
	
	/* Allocate a new request if we've lost the old one */
	if (!cs->req) {
		/* TODO: Do passwords or secrets ever pass through here? */
		cs->req = gkr_pkcs11_message_new (call_session_allocator);
		if (!cs->req) {
			WARN (("S%d: cannot allocate request buffer: out of memory", cs->id));
			return CKR_HOST_MEMORY;
		}
	}
	
	/* Put in the Call ID and signature */
	gkr_pkcs11_message_reset (cs->req);
	ret = gkr_pkcs11_message_prep (cs->req, call_id, GKR_PKCS11_REQUEST);
	if (ret != CKR_OK)
		return ret;
	
	DBG (("S%d: prepared call: %d", cs->id, call_id));

	/* Ready to fill in arguments */
	cs->call_state = CALL_PREP;
	return CKR_OK;
}

/* 
 * Write all data to session socket. During blocking write, the session is
 * unlocked, which allows it to be closed or return errors on other threads.
 */
static CK_RV
call_session_write (CallSession *cs, unsigned char* data, size_t len)
{
	int fd, r;

	ASSERT (cs);
	ASSERT (data);
	ASSERT (len > 0);

	while (len > 0) {
	
		fd = cs->socket;
		if (fd == -1) {
			WARN (("S%d: couldn't send data: session socket has been closed", cs->id));
			return CKR_SESSION_CLOSED;
		}
		
		pthread_mutex_unlock (&cs->mutex);
		
			/* TODO: Need to implement timeouts, and call notify on session */
			r = write (fd, data, len);
		
		pthread_mutex_lock (&cs->mutex);
		
		if (r == -1) {
			if (errno == EPIPE) {
				WARN (("S%d: couldn't send data: daemon closed connection", cs->id));
				call_session_disconnect (cs);
				return CKR_SESSION_CLOSED;
			} else if (errno != EAGAIN && errno != EINTR) {
				WARN (("S%d: couldn't send data: %s", cs->id, strerror (errno)));
				return CKR_DEVICE_ERROR;
			}
		} else {
			DBG (("S%d: wrote %d bytes", cs->id, r));
			data += r;
			len -= r;
		}
	}
	
	return CKR_OK;
}

/* 
 * Read a certain amount of data from session socket. During blocking read, the 
 * session is unlocked, which allows closing or return errors on other threads.
 */
static CK_RV
call_session_read (CallSession *cs, unsigned char* data, size_t len)
{
	int fd, r;

	ASSERT (cs);
	ASSERT (data);
	ASSERT (len > 0);

	while (len > 0) {
	
		fd = cs->socket;
		if (fd == -1) {
			WARN (("S%d: couldn't receive data: session socket has been closed", cs->id));
			return CKR_SESSION_CLOSED;
		}
		
		pthread_mutex_unlock (&cs->mutex);
		
			/* TODO: Need to implement timeouts, and call notify on session */
			r = read (fd, data, len);
		
		pthread_mutex_lock (&cs->mutex);
		
		if (r == 0) {
			WARN (("S%d: couldn't receive data: daemon closed connection", cs->id));
			call_session_disconnect (cs);
			return CKR_SESSION_CLOSED;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				WARN (("S%d: couldn't receive data: %s", cs->id, strerror (errno)));
				return CKR_DEVICE_ERROR;
			}
		} else {
			DBG (("S%d: read %d bytes", cs->id, r));
			data += r;
			len -= r;
		}
	}
	
	return CKR_OK;
}

/* 
 * Used by call_session_do_call() to actually send the message to the daemon.
 * Note how we unlock and relock the session during the call. 
 */
static CK_RV
call_session_send_recv (CallSession *cs)
{
	GkrPkcs11Message *req, *resp;
	unsigned char buf[4];
	uint32_t len;
	CK_RV ret;
	
	ASSERT (cs);
	ASSERT (cs->req);
	ASSERT (cs->call_state == CALL_PREP);
	
	cs->call_state = CALL_TRANSIT;
	
	/* Setup the response buffer properly */
	if (!cs->resp) {
		/* TODO: Do secrets or passwords ever flow through here? */
		cs->resp = gkr_pkcs11_message_new (call_session_allocator);
		if (!cs->resp) {
			WARN (("S%d: couldn't allocate response buffer: out of memory", cs->id));
			return CKR_HOST_MEMORY;
		}
	}
	gkr_pkcs11_message_reset (cs->resp);
	
	/* 
	 * Now as an additional check to make sure nothing nasty will
	 * happen while we are unlocked, we remove the request and 
	 * response from the session during the action.
	 */
	req = cs->req;
	resp = cs->resp;
	cs->req = cs->resp = NULL;
	ASSERT (cs->overflow == NULL);

	/* Send the number of bytes, and then the data */
	gkr_buffer_encode_uint32 (buf, req->buffer.len);
	ret = call_session_write (cs, buf, 4);
	if (ret != CKR_OK)
		goto cleanup;
	ret = call_session_write (cs, req->buffer.buf, req->buffer.len);
	if (ret != CKR_OK)
		goto cleanup;
	
	/* Now read out the number of bytes, and then the data */
	ret = call_session_read (cs, buf, 4);
	if (ret != CKR_OK) 
		goto cleanup;
	len = gkr_buffer_decode_uint32 (buf);
	if (!gkr_buffer_reserve (&resp->buffer, len + resp->buffer.len)) {
		WARN (("S%d: couldn't allocate %u byte response area: out of memory", 
		       cs->id, len));
		ret = CKR_HOST_MEMORY;
		goto cleanup;
	}
	ret = call_session_read (cs, resp->buffer.buf, len);
	if (ret != CKR_OK)
		goto cleanup;
	
	gkr_buffer_add_empty (&resp->buffer, len);
	ret = gkr_pkcs11_message_parse (resp, GKR_PKCS11_RESPONSE);
	if (ret != CKR_OK)
		goto cleanup;
	
	DBG (("S%d: received response from daemon", cs->id));
	
cleanup:
	/* Make sure nobody else used this thread while unlocked */
	ASSERT (cs->call_state == CALL_TRANSIT);
	ASSERT (cs->resp == NULL);
	cs->resp = resp;
	ASSERT (cs->req == NULL);
	cs->req = req;
	
	return ret;
}

/* 
 * At this point the request is ready. So we validate it, and we send it to 
 * the daemon for a response. 
 */
static CK_RV
call_session_do_call (CallSession *cs)
{
	CK_RV ret = CKR_OK;
	CK_ULONG ckerr;
	int reuse = 0;

	ASSERT (cs);
	ASSERT (cs->req);
	ASSERT (cs->call_state == CALL_PREP);
	ASSERT (!cs->overflowed);

	/* Did building the call fail? */
	if (gkr_pkcs11_message_buffer_error (cs->req)) {
		WARN (("S%d: couldn't allocate request area: out of memory", cs->id));
		return CKR_HOST_MEMORY;
	}

	if (cs->socket == -1) {
		WARN (("S%d: session socket has been closed", cs->id));
		return CKR_SESSION_CLOSED;
	}

	/* Make sure that the signature is valid */
	ASSERT (gkr_pkcs11_message_is_verified (cs->req));

	if (cs->overflow) {
		
		/* See if this is the same as the call that overflowed */
		if (gkr_pkcs11_message_equals (cs->req, cs->overflow)) {
			ASSERT (cs->resp);
			reuse = 1;

			/* Prepare to reparse this message */			
			ret = gkr_pkcs11_message_parse (cs->resp, GKR_PKCS11_RESPONSE);
			if (ret != CKR_OK) {
				WARN (("S%d: reparsing overflowed response failed: %d", ret));
				return ret;
			}
			
			DBG (("S%d: last message overflowed, using same response"));
		}
		
		/* We have no further use for this... */
		gkr_pkcs11_message_free (cs->overflow); 
		cs->overflow = NULL;
	}

	/* Do the dialog with daemon */
	if (!reuse)
		ret = call_session_send_recv (cs);
	
	cs->call_state = CALL_PARSE;
	
	if (ret != CKR_OK)
		return ret;

	/* If it's an error code then return it */
	if (cs->resp->call_id == PKCS11_CALL_ERROR) {

		ret = gkr_pkcs11_message_read_uint32 (cs->resp, &ckerr);
		if (ret != CKR_OK) {
			WARN (("S%d: invalid error response from gnome-keyring-daemon: too short", cs->id));
			return ret;
		}

		if (ckerr <= CKR_OK) {
			WARN (("S%d: invalid error response from gnome-keyring-daemon: bad error code", cs->id));
			return CKR_DEVICE_ERROR;
		}

		/* An error code from the daemon */
		return (CK_RV)ckerr;
	}
	
	/* Make sure daemon answered the right call */
	if (cs->req->call_id != cs->resp->call_id) {
		WARN (("S%d: invalid response from gnome-keyring-daemon: call mismatch", cs->id));
		return CKR_DEVICE_ERROR;
	}

	ASSERT (!gkr_pkcs11_message_buffer_error (cs->resp));
	ASSERT (!cs->overflowed);
	
	DBG (("S%d: parsing response values", cs->id));

	return CKR_OK;
}

static CK_RV
call_session_done_call (CallSession *cs, CK_RV ret)
{
	ASSERT (cs);
	ASSERT (cs->call_state > CALL_INVALID);

	if (cs->call_state == CALL_PARSE && cs->req && cs->resp) {

		/* Check for parsing errors that were not caught elsewhere */
		if (ret == CKR_OK) {

			if (gkr_pkcs11_message_buffer_error (cs->resp)) {
				WARN (("S%d: invalid response from gnome-keyring-daemon: bad argument data", cs->id));
				return CKR_GENERAL_ERROR;
			}

			/* Double check that the signature matched our decoding */
			ASSERT (gkr_pkcs11_message_is_verified (cs->resp));
		} 
		
		/* Caller didn't supply enough space, ... */
		if (cs->overflowed || ret == CKR_BUFFER_TOO_SMALL) {

			DBG (("S%d: not enough space to store response values", cs->id));

			/* ...Save away the request for later */
			ASSERT (!cs->overflow);
			cs->overflow = cs->req;
			cs->req = NULL;
		}
	}

	/* Some cleanup */
	cs->overflowed = 0;
	cs->call_state = CALL_READY;

	return ret;
}

/* -------------------------------------------------------------------
 * CALL SESSION LIST 
 */

typedef struct _CallSessions {
	CallSession **list;
	size_t lmax;
} CallSessions;

/* These are protected by global_mutex */
static CallSessions the_sessions = { NULL, 0 }; /* Table of sessions by ID */

static CK_RV
call_session_find_lock_ref_internal (CallSessions *css, CK_ULONG id, 
                                     int remove, CallSession **cs_ret)
{
	CallSession *cs;
	
	ASSERT (css);
	ASSERT (cs_ret);
	
	if (id >= css->lmax) {
		WARN (("invalid session id: %d", id));
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	/* A seemingly valid id */
	ASSERT (css->list);
	cs = css->list[id]; 
	
	/* 
	 * An initial check is done to make sure this session is not active. 
	 * This is done outside of the lock. The real check is done later 
	 * inside a lock. This is so we can return quickly without blocking
	 * in most cases. 
	 */
	
	if (!cs) {
		WARN (("invalid session id: %d", id));
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	ASSERT (cs->id == id);
	
	/* Closing takes precedence over active operations */
	if (!remove) {
		if (cs->call_state == CALL_INVALID) {
			WARN (("S%d: session is in an invalid state", id));
			return CKR_SESSION_HANDLE_INVALID;
		}
		if (cs->call_state != CALL_READY) {
			WARN (("S%d: an operation is already active in this session", id));
			return CKR_OPERATION_ACTIVE;
		}
	}

	/* Lock the CallSession */
	pthread_mutex_lock (&cs->mutex);
	
	/* Make sure it doesn't go away */
	ASSERT (cs->refs > 0);
	cs->refs++;

	DBG (("S%d: found and locked session", id));
	
	/* And remove it if necessary */
	if (remove) {
		css->list[id] = NULL;
		
		/* The session list reference */
		cs->refs--;
		ASSERT (cs->refs > 0);
		
		DBG (("S%d: removed session from list", id));
	}
	
	*cs_ret = cs;
	return CKR_OK;
}

static CK_RV
call_session_find_lock_and_ref (CK_ULONG id, int remove, CallSession **cs)
{
	/* This must be called without any locks held */
	
	CK_RV ret = CKR_OK;

	ASSERT (cs);
	ASSERT (pkcs11_initialized);
	
	if (id <= 0) {
		WARN (("invalid session id passed: %d", id));
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock (&global_mutex);
	
		ret = call_session_find_lock_ref_internal (&the_sessions,
		                                           id, remove, cs);

	pthread_mutex_unlock (&global_mutex);
	
	return ret;
}

static void
call_session_unref_and_unlock (CallSession *cs)
{
	/* The CallSession must be locked at this point */

	int refs;
	
	ASSERT (cs);
	
	ASSERT (cs->refs > 0);
	cs->refs--;
	
	refs = cs->refs;

	DBG (("S%d: unlocked session", cs->id));
	pthread_mutex_unlock (&cs->mutex);
	
	
	/* 
	 * At this point if no references are held, then we can safely 
	 * delete. No other thread should be involved. 
	 */
	
	if (refs == 0)
		call_session_destroy (cs);
}

static CK_RV 
call_session_register (CallSession *cs)
{
	/* This must be called without any locks held */
	
	CK_RV ret = CKR_OK;
	CK_ULONG id = 0;
	size_t i;

	ASSERT (pkcs11_initialized);

	ASSERT (cs);
	ASSERT (cs->id == 0 && cs->refs == 0);
	
	DBG (("S%d: registering new session", cs->id));

	pthread_mutex_lock (&global_mutex);

		/* Find a nice session identifier */
		while (id == 0) {

			/* 
			 * PKCS#11 GRAY AREA: We're assuming we can reuse session
			 * handles. PKCS#11 spec says they're like file handles,
			 * and file handles get reused :)
			 */
			
			/* Note we never put anything in array position '0' */
			for (i = 1; i < the_sessions.lmax; ++i) {

				/* Any empty position will do */
				if (!the_sessions.list[i]) {
					id = i;
					break;
				}
			}

			/* Couldn't find a handle, reallocate */
			if (id == 0) {
				CallSession** buf;
				size_t oldmax, newmax;

				oldmax = the_sessions.lmax;
				newmax = oldmax + 16;

				buf = realloc (the_sessions.list, newmax * sizeof (CallSession*));
				if (!buf) {
					WARN (("couldn't allocate session list, out of memory"));
					ret = CKR_HOST_MEMORY;
					break;
				}

				/* Choose the first of the new block as the id */
				id = oldmax;

				/* Clear new memory */
				the_sessions.list = buf;
				for ( ; oldmax < newmax; ++oldmax)
					buf[oldmax] = NULL;
				the_sessions.lmax = newmax;

				DBG (("allocated new session list: %d max", newmax));	
			}
		}

		if (ret == CKR_OK) {
			ASSERT (id > 0 && id < the_sessions.lmax);
			ASSERT (the_sessions.list[id] == NULL);

			/* And assign it to the session handle */
			the_sessions.list[id] = cs;
			cs->id = id;
			
			/* The session list reference */
			ASSERT (cs->refs == 0);
			cs->refs++;
			
			DBG (("S%d: registered sesson id", id));
		}

	pthread_mutex_unlock (&global_mutex);

	return ret;
}

static void 
call_session_close_all ()
{
	/* This must be called without any locks held */
	
	CallSessions sessions;
	CallSession *cs;
	CK_LONG i;
	CK_RV ret;

	/* 
	 * PKCS#11 GRAY AREA: What happens when this gets called 
	 * concurrently? We don't return an error on the second call,
	 * because by the time it returns, all sessions should be closed.
	 */

	pthread_mutex_lock (&global_mutex);

		/* Steal all the session data */
		sessions.list = the_sessions.list;
		the_sessions.list = NULL;
		sessions.lmax = the_sessions.lmax;
		the_sessions.lmax = 0;
		
		if (sessions.list || sessions.lmax) {
			DBG (("closing all sessions"));
		}

	pthread_mutex_unlock (&global_mutex);

	/* Close each session in turn */
	for (i = 1; i < sessions.lmax; ++i) {
		
		if (!sessions.list[i])
			continue;
		
		ret = call_session_find_lock_ref_internal (&sessions, i, 1, &cs);
		ASSERT (ret == CKR_OK);
		
			/* 
		 	* This closes the socket and marks session as closed. 
		 	* Session actually removed from memory when all refs are gone.
		 	*/
			call_session_disconnect (cs);
		
		
		call_session_unref_and_unlock (cs);
	}

	/* We stole the memory above, free it now */
	if (sessions.list) {
		free (sessions.list);
		DBG (("freed session list"));
	}
}

/* -----------------------------------------------------------------------------
 * MODULE SPECIFIC PROTOCOL CODE
 */

static CK_RV
proto_read_attribute_array (GkrPkcs11Message *msg, CK_ATTRIBUTE_PTR arr, 
                            CK_ULONG_PTR len, CK_ULONG max)
{
	uint32_t i, num, val;
	CK_ATTRIBUTE_PTR attr;
	const unsigned char *attrval;
	size_t attrlen;
	unsigned char validity;
	CK_RV ret;

	ASSERT (len);
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_pkcs11_message_verify_part (msg, "aA"));

	/* Get the number of items. We need this value to be correct */
	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, 
	                            &msg->parsed, &num))
		return CKR_DEVICE_ERROR; /* parse error */

	*len = num;

	if (arr && max < num)
		return CKR_BUFFER_TOO_SMALL;

	ret = CKR_OK;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {
	
		/* The attribute type */
		gkr_buffer_get_uint32 (&msg->buffer, msg->parsed,
		                       &msg->parsed, &val);

		/* Attribute validity */
		gkr_buffer_get_byte (&msg->buffer, msg->parsed,
		                     &msg->parsed, &validity);

		/* And the data itself */
		if (validity)
			gkr_buffer_get_byte_array (&msg->buffer, msg->parsed,
			                           &msg->parsed, &attrval, &attrlen);
			
		/* Don't act on this data unless no errors */
		if (gkr_buffer_has_error (&msg->buffer))
			break;

		/* Try and stuff it in the output data */
		if (arr) {
			attr = &(arr[i]);
			attr->type = val;

			if (validity) {
				/* Just requesting the attribute size */
				if (!attr->pValue) {
					attr->ulValueLen = attrlen;

				/* Wants attribute data, but too small */
				} else if (attr->ulValueLen < attrlen) {
					attr->ulValueLen = attrlen;
					ret = CKR_BUFFER_TOO_SMALL;

				/* Wants attribute data, value is null */
				} else if (attrval == NULL) {
					attr->ulValueLen = 0;

				/* Wants attribute data, enough space */
				} else {
					attr->ulValueLen = attrlen;
					memcpy (attr->pValue, attrval, attrlen);
				}

			/* Not a valid attribute */
			} else {
				attr->ulValueLen = ((CK_ULONG)-1);
			}
		}
	}

	return gkr_buffer_has_error (&msg->buffer) ? CKR_DEVICE_ERROR : ret;	
}

static CK_RV
proto_read_byte_array (GkrPkcs11Message *msg, CK_BYTE_PTR arr,
                       CK_ULONG_PTR len, CK_ULONG max)
{
	const unsigned char *val;
	size_t vlen;

	ASSERT (len);
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_pkcs11_message_verify_part (msg, "ay"));


	if (!gkr_buffer_get_byte_array (&msg->buffer, msg->parsed,
	                                &(msg->parsed), &val, &vlen))
		return CKR_DEVICE_ERROR; /* parse error */

	*len = vlen;

	/* Just asking us for size */
	if (!arr) 
		return CKR_OK;

	if (max < vlen)
		return CKR_BUFFER_TOO_SMALL;

	/* Enough space, yay */
	memcpy (arr, val, vlen);
	return CKR_OK;
}


static CK_RV
proto_read_uint32_array (GkrPkcs11Message *msg, CK_ULONG_PTR arr,
                         CK_ULONG_PTR len, CK_ULONG max)
{
	uint32_t i, num, val;

	ASSERT (len);
	ASSERT (msg);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_pkcs11_message_verify_part (msg, "au"));

	/* Get the number of items. We need this value to be correct */
	if (!gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, 
	                            &msg->parsed, &num))
		return CKR_DEVICE_ERROR; /* parse error */

	*len = num;

	if (arr && max < num)
		return CKR_BUFFER_TOO_SMALL;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {
		gkr_buffer_get_uint32 (&msg->buffer, msg->parsed,
		                       &msg->parsed, &val);
		if (arr)
			arr[i] = val;
	}

	return gkr_buffer_has_error (&msg->buffer) ? CKR_DEVICE_ERROR : CKR_OK;
}

static CK_RV
proto_write_mechanism (GkrPkcs11Message *msg, CK_MECHANISM_PTR mech)
{
	int use_parameter = 0;
	
	ASSERT (msg);
	ASSERT (mech);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_pkcs11_message_verify_part (msg, "M"));
	
	/* The mechanism type */
	gkr_buffer_add_uint32 (&msg->buffer, mech->mechanism);
	
	/*
	 * Some callers of PKCS11 expect us not to access the parameter
	 * if it's not required for the mechanims, and leave it 
	 * uninitialized and full of strange values which we could 
	 * crash trying to access. Yuck.
	 * 
	 * This list is incomplete. As we add mechanims which have parameters
	 * to gnome-keyring, we should add those here. 
	 */
	switch (mech->mechanism) {
	case CKM_RSA_PKCS_OAEP:
	case CKM_RSA_PKCS_PSS:
		use_parameter = 1;
		break;
	};
	
	/* The parameter value */
	if (use_parameter)
		gkr_buffer_add_byte_array (&msg->buffer, mech->pParameter, 
		                           mech->ulParameterLen);
	else
		gkr_buffer_add_byte_array (&msg->buffer, NULL, 0);

	return gkr_buffer_has_error (&msg->buffer) ? CKR_HOST_MEMORY : CKR_OK;
}

static CK_RV
proto_read_sesssion_info (GkrPkcs11Message *msg, CK_SESSION_INFO_PTR info)
{
	uint32_t val;

	ASSERT (msg);
	ASSERT (info);

	/* Make sure this is in the right order */
	ASSERT (!msg->signature || gkr_pkcs11_message_verify_part (msg, "I"));
	
	/* The slot id (we ignore) */
	gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &val);
	info->slotID = 0;

	/* The state */
	gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &val);
	info->state = val;

	/* The flags */
	gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &val);
	info->flags = val;

	/* The device error code */
	gkr_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &val);
	info->ulDeviceError = val;

	return gkr_buffer_has_error (&msg->buffer) ? CKR_DEVICE_ERROR : CKR_OK;
}


/* -------------------------------------------------------------------
 * INITIALIZATION and 'GLOBAL' CALLS
 */

static CK_RV
gkr_C_Initialize (CK_VOID_PTR init_args)
{
	CK_C_INITIALIZE_ARGS_PTR args;
	CK_RV ret = CKR_OK;
	pid_t initialize_pid;
	char *path;
	int l;
	
	DBG (("C_Initialize: enter"));

	/* 
	 * We check this first to make sure that using our own mutex 
	 * initialization is ok.
	 */
	
#ifdef _DEBUG 
	GKR_PKCS11_CHECK_CALLS();
#endif

	if (init_args != NULL) {
		int supplied_ok;

		/* pReserved must be NULL */
		args = init_args;
		PREREQ (!args->pReserved, CKR_ARGUMENTS_BAD);

		/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
		supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
		               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
		              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		               args->LockMutex != NULL && args->UnlockMutex != NULL);
		PREREQ (supplied_ok, CKR_ARGUMENTS_BAD);

		/*
		 * When the CKF_OS_LOCKING_OK flag isn't set and mutex function pointers are supplied
		 * by an application, return an error.  DBus must be able to use its own locks.
		 */
		if (!(args->flags & CKF_OS_LOCKING_OK) && (args->CreateMutex != NULL)) {
			PREREQ (FALSE, CKR_CANT_LOCK);
		}
	}

	/* Main initialization */
	pthread_mutex_lock (&global_mutex);

		initialize_pid = getpid ();
		if (pkcs11_initialized) {

			/* This process has called C_Initialize already */
			if (initialize_pid == crypto_pid) {
				WARN (("C_Initialize called twice for same process"));
				ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
			}
		}
		
		if (ret == CKR_OK) {

			/* slot_id is a random number to avoid the temptation of refering to 
			   the slot by slot id. */
			slot_id = rand ();

			pkcs11_initialized = 1;
			crypto_pid = initialize_pid;
			
			/* Lookup the socket path, append '.pkcs11' */
			socket_path[0] = 0;
			path = getenv ("GNOME_KEYRING_SOCKET");
			if (path && path[0]) {
				l = sizeof (socket_path) - 1;
				strncpy (socket_path, path, l);
				strncat (socket_path, ".pkcs11", l);
				socket_path[l] = 0;
				
				DBG (("gnome-keyring pkcs11 socket is: %s", socket_path));
			}
		}

	pthread_mutex_unlock (&global_mutex);
	
	/* 
	 * Remove all the sessions. This happens when we reinitialize 
	 * due to a fork, see above.
	 */
	call_session_close_all ();

	DBG (("C_Initialize: %d", ret));
	return ret;
}

static CK_RV
gkr_C_Finalize (CK_VOID_PTR reserved)
{
	DBG (("C_Finalize: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (!reserved, CKR_ARGUMENTS_BAD);

	pthread_mutex_lock (&global_mutex);
	
		/* This should stop all other calls in */
		pkcs11_initialized = 0;
	
		slot_id = -1;
		crypto_pid = 0;
		socket_path[0] = 0;
	
	pthread_mutex_unlock (&global_mutex);

	call_session_close_all ();
	
	DBG (("C_Finalize: %d", CKR_OK));
	return CKR_OK;
}

static CK_RV
gkr_C_GetInfo (CK_INFO_PTR info)
{
	DBG (("C_GetInfo: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (info, CKR_ARGUMENTS_BAD);

	ASSERT (strlen (MANUFACTURER_ID) == 32);
	ASSERT (strlen (LIBRARY_DESCRIPTION) == 32);

	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy ((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);

	DBG (("C_GetInfo: %d", CKR_OK));
	return CKR_OK;
}

static CK_RV
gkr_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	/* This would be a strange call to receive */
	return C_GetFunctionList (list);
}

static CK_RV
gkr_C_GetSlotList (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count)
{
	CK_RV ret = CKR_OK;
	int have;

	DBG (("C_GetSlotList: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (count, CKR_ARGUMENTS_BAD);
	
	/* The environment variable is our token */
	have = socket_path[0] || !tokenPresent;

	/* Application only wants to know the number of slots. */
	if (slot_list == NULL) {
		*count = have ? 1 : 0;
		goto cleanup;
	}

	if (have) {
		if ((*count < 1) && (slot_list != NULL)) {
			*count = 1;
			ret = CKR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		
		*count = 1;
		slot_list[0] = slot_id;
	} else {
		*count = 0;
	}
	
cleanup:
	DBG (("C_GetSlotList: %d", ret));
	return ret;
}

static CK_RV
gkr_C_GetSlotInfo (CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	
	DBG (("C_GetSlotInfo: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (info, CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if (id != slot_id) {
		ret = CKR_SLOT_ID_INVALID;
		goto cleanup;
	}

	ASSERT (strlen (SLOT_DESCRIPTION) == 64);
	ASSERT (strlen (MANUFACTURER_ID) == 32);

	/* Provide information about the slot in the provided buffer */
	strncpy ((char*)info->slotDescription, SLOT_DESCRIPTION, 64);
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	info->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	info->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	info->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	info->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;

	/* Token is the enviornment var */
	info->flags = 0;  
	if (socket_path[0])
		info->flags |= CKF_TOKEN_PRESENT;

cleanup:
	DBG (("C_GetSlotInfo: %d", ret));
	return ret;
}

static CK_RV
gkr_C_GetTokenInfo (CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	
	DBG (("C_GetTokenInfo: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (info, CKR_ARGUMENTS_BAD);

	/* Make sure the slot ID is valid */
	if (id != slot_id) {
		ret = CKR_SLOT_ID_INVALID;
		goto cleanup;
	}
	
	if (!socket_path[0]) {
		ret =  CKR_TOKEN_NOT_PRESENT;
		goto cleanup;
	}

	ASSERT (strlen (SLOT_DESCRIPTION) == 64);
	ASSERT (strlen (MANUFACTURER_ID) == 32);
	ASSERT (strlen (SLOT_TOKEN_MODEL) == 16);
	ASSERT (strlen (SLOT_TOKEN_SERIAL) == 16);

	/* Provide information about a token in the provided buffer */
	strncpy ((char*)info->label, SLOT_DESCRIPTION, 32);
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy ((char*)info->model, SLOT_TOKEN_MODEL, 16);
	strncpy ((char*)info->serialNumber, SLOT_TOKEN_SERIAL, 16);

	info->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
	info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxPinLen = MAX_PIN_LEN;
	info->ulMinPinLen = MIN_PIN_LEN;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->hardwareVersion.major = HARDWARE_VERSION_MAJOR;
	info->hardwareVersion.minor = HARDWARE_VERSION_MINOR;
	info->firmwareVersion.major = FIRMWARE_VERSION_MAJOR;
	info->firmwareVersion.minor = FIRMWARE_VERSION_MINOR;
	memset (info->utcTime, ' ', 16);

cleanup:
	DBG (("C_GetTokenInfo: %d", ret));
	return ret;
}

static CK_RV
gkr_C_GetMechanismList (CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list,
                        CK_ULONG_PTR count)
{
	int i, mechnum;
	CK_RV ret = CKR_OK;

	DBG (("C_GetMechanismList: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (count, CKR_ARGUMENTS_BAD);

	if (id != slot_id) {
		ret = CKR_SLOT_ID_INVALID;
		goto cleanup;
	}
	if (!socket_path[0]) {
		ret = CKR_TOKEN_NOT_PRESENT;
		goto cleanup;
	}

	mechnum = sizeof (gkr_pkcs11_mechanisms) / sizeof (CK_MECHANISM_TYPE);

	if (mechanism_list == NULL) {
		*count = mechnum;
		goto cleanup;
	}

	if (*count < mechnum) {
		*count = mechnum;
		ret = CKR_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	for (i = 0; i < mechnum; i++)
		mechanism_list[i] = gkr_pkcs11_mechanisms[i];
	*count = mechnum;

cleanup:
	DBG (("C_GetMechanismList: %d", ret));
	return ret;
}

static CK_RV
gkr_C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type, 
                        CK_MECHANISM_INFO_PTR info)
{
	int i, mechnum;
	CK_RV ret = CKR_OK;

	DBG (("C_GetMechanismInfo: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (info, CKR_ARGUMENTS_BAD);

	if (id != slot_id) {
		ret = CKR_SLOT_ID_INVALID;
		goto cleanup;
	}
	if (!socket_path[0]) {
		ret = CKR_TOKEN_NOT_PRESENT;
		goto cleanup;
	}

	mechnum = sizeof (gkr_pkcs11_mechanisms) / sizeof (CK_MECHANISM_TYPE);
	for (i = 0; i < mechnum; i++) {
		if (gkr_pkcs11_mechanisms[i] == type)
			break;
	}

	/* unsupported mechanism */
	if (i == mechnum) {
		ret = CKR_MECHANISM_INVALID;
		goto cleanup;
	}

	info->ulMinKeySize = gkr_pkcs11_mechanism_info[i].ulMinKeySize;
	info->ulMaxKeySize = gkr_pkcs11_mechanism_info[i].ulMaxKeySize;
	info->flags = gkr_pkcs11_mechanism_info[i].flags;

cleanup:
	DBG (("C_GetMechanismInfo: %d", ret));
	return ret;
}

static CK_RV
gkr_C_InitToken (CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen, 
                 CK_UTF8CHAR_PTR label)
{
	DBG (("C_InitToken: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	DBG (("C_InitToken: %d", CKR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
gkr_C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
	DBG (("C_WaitForSlotEvent: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	
	/* 
	 * PKCS#11 GRAY AREA: What happens when we know we'll *never* 
	 * have any slot events, and someone calls us without CKR_DONT_BLOCK?
	 * In case there's a thread dedicated to calling this function in a 
	 * loop, we wait 5 seconds when called without CKR_DONT_BLOCK.
	 */
	
	if (!(flags & CKF_DONT_BLOCK))
		sleep (5);
	
	DBG (("C_WaitForSlotEvent: %d", CKR_NO_EVENT));
	return CKR_NO_EVENT;
}

/* -------------------------------------------------------------------
 * SESSION MANAGEMENT CALLS
 */

static CK_RV
gkr_C_OpenSession (CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data,
                   CK_NOTIFY callback, CK_SESSION_HANDLE_PTR session)
{
	CallSession *cs;
	CK_RV ret = CKR_OK;

	DBG (("C_OpenSession: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	PREREQ (session, CKR_ARGUMENTS_BAD);
	PREREQ (flags & CKF_SERIAL_SESSION, CKR_FUNCTION_NOT_PARALLEL);

	if (id != slot_id) 
		return CKR_SLOT_ID_INVALID;
	if (!socket_path[0])
		return CKR_TOKEN_NOT_PRESENT;

	/* Create the session */
	cs = call_session_create (&cs);
	if (cs == NULL) {
		ret = CKR_HOST_MEMORY;
		goto cleanup;
	}

	cs->notify_callback = callback;
	cs->user_data = user_data;
	
	/* Connect the session */
	ret = call_session_connect (cs);
	if (ret != CKR_OK)
		goto cleanup;

	/* 
	 * This lock isn't strictly necessary, but all the send/receive call
	 * stuff requires and expects locking so... 
	 */
	pthread_mutex_lock (&cs->mutex);
	
		ret = call_session_prep_call (cs, PKCS11_CALL_C_OpenSession);
		if (ret == CKR_OK)
			ret = gkr_pkcs11_message_write_byte_array (cs->req, 
			                            (unsigned char*)GKR_PKCS11_HANDSHAKE, 
		                                    GKR_PKCS11_HANDSHAKE_LEN);
		if (ret == CKR_OK)
			ret = gkr_pkcs11_message_write_uint32 (cs->req, crypto_pid);
		if (ret == CKR_OK) /* We don't use the slot id yet */
			ret = gkr_pkcs11_message_write_uint32 (cs->req, 0); 
		if (ret == CKR_OK)
			ret = gkr_pkcs11_message_write_uint32 (cs->req, flags);
		if (ret == CKR_OK)
			ret = call_session_do_call (cs);
		ret = call_session_done_call (cs, ret);
	
	pthread_mutex_unlock (&cs->mutex);
	
	if (ret != CKR_OK)
		goto cleanup;
	
	/* Register it in the big mix */
	ret = call_session_register (cs);
	if (ret != CKR_OK) 
		goto cleanup;
	
cleanup:
	if (ret == CKR_OK) {
		/* ID should have been assigned when registering it */
		ASSERT (cs->id > 0);
		*session = cs->id;
	} else {
		call_session_destroy (cs);
	}

	DBG (("C_OpenSession: %d", ret));
	return ret;
}

static CK_RV
gkr_C_CloseSession (CK_SESSION_HANDLE session)
{
	CallSession *cs;
	CK_RV ret = CKR_OK;
	
	DBG (("C_OpenSession: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	/* The 'remove' flag removes it from the main session list */
	ret = call_session_find_lock_and_ref (session, 1, &cs);
	if (ret == CKR_OK) {
		/* 
		 * PKCS#11 GRAY AREA: Is this supposed to return CKR_OPERATION_ACTIVE
		 * if some other session call is in progress? We err on the side of 
		 * closing the session anyway, which will most likely cause the 
		 * operation in progress to return CKR_SESSION_CLOSED.
		 */
		
		if (cs->socket < 0) {
			ret = CKR_SESSION_CLOSED;
		} else {

			/* 
			 * This closes the socket and marks session as closed. 
			 * Session actually removed from memory when all refs are gone.
			 */
			call_session_disconnect (cs);
		}

		/* This will unref and possibly destroy the session */
		call_session_unref_and_unlock (cs);
	}

	DBG (("C_CloseSession: %d", ret));
	return ret;
}

static CK_RV
gkr_C_CloseAllSessions (CK_SLOT_ID id)
{
	CK_RV ret = CKR_OK;
	
	DBG (("C_CloseAllSessions: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);

	if (id == slot_id) 
		call_session_close_all ();
	else 
		ret = CKR_SLOT_ID_INVALID;
	
	DBG (("C_CloseAllSessions: %d", ret));
	return CKR_OK;
}

static CK_RV
gkr_C_GetFunctionStatus (CK_SESSION_HANDLE hSession)
{
	DBG (("C_GetFunctionStatus: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	DBG (("C_CancelFunction: %d", CKR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV
gkr_C_CancelFunction (CK_SESSION_HANDLE hSession)
{
	DBG (("C_CancelFunction: enter"));
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	DBG (("C_CancelFunction: %d", CKR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;
}
/* -------------------------------------------------------------------
 * SESSION DBUS CALLS 
 */

#define BEGIN_CALL(session, call_id) \
	DBG ((#call_id ": enter")); \
	PREREQ (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED); \
	{  \
		CallSession *_cs; \
		CK_RV _ret = CKR_OK; \
		_ret = call_session_find_lock_and_ref (session, 0, &_cs); \
		if (_ret != CKR_OK) return _ret; \
		_ret = call_session_prep_call (_cs, PKCS11_CALL_##call_id); \
		if (_ret != CKR_OK) goto _cleanup;

#define PROCESS_CALL \
		_ret = call_session_do_call (_cs); \
		if (_ret != CKR_OK) goto _cleanup;
	
#define END_CALL \
	_cleanup: \
		_ret = call_session_done_call (_cs, _ret); \
		call_session_unref_and_unlock (_cs); \
		DBG (("ret: %d", _ret)); \
		return _ret; \
	} 

#define IN_ATTRIBUTE_ARRAY(arr, num) \
	_ret = gkr_pkcs11_message_write_attribute_array (_cs->req, (arr), (num)); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_ARRAY(arr, len) \
	_ret = gkr_pkcs11_message_write_byte_array (_cs->req, arr, len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_HANDLE(val) \
	_ret = gkr_pkcs11_message_write_uint32 (_cs->req, val); \
	if (_ret != CKR_OK) goto _cleanup;
	
#define IN_MECHANISM(val) \
	_ret = proto_write_mechanism (_cs->req, val); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ULONG(val) \
	_ret = gkr_pkcs11_message_write_uint32 (_cs->req, val);  \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_ATTRIBUTE_ARRAY(arr, num, max) \
	if (!arr) _cs->overflowed = 1; \
	_ret = proto_read_attribute_array (_cs->resp, (arr), (num), (max)); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_BYTE_ARRAY(arr, len, max)  \
	if (!arr) _cs->overflowed = 1; \
	_ret = proto_read_byte_array (_cs->resp, (arr), (len), (max)); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_HANDLE(val) \
	_ret = gkr_pkcs11_message_read_uint32 (_cs->resp, val); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_HANDLE_ARRAY(a, n, mx) \
	if (!a) _cs->overflowed = 1; \
	_ret = proto_read_uint32_array (_cs->resp, (a), (n), (mx)); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_RETURN_CODE() { \
	CK_RV r; \
	_ret = gkr_pkcs11_message_read_uint32 (_cs->resp, (_ret == CKR_OK) ? &r : NULL); \
	if (_ret == CKR_OK) _ret = r; \
	if (_ret != CKR_OK) goto _cleanup; \
	}

#define OUT_SESSION_INFO(info) \
	_ret = proto_read_sesssion_info (_cs->resp, info); \
	if (_ret != CKR_OK) goto _cleanup;
	
#define OUT_ULONG(val) \
	_ret = gkr_pkcs11_message_read_uint32 (_cs->resp, val); \
	if (_ret != CKR_OK) goto _cleanup;


static CK_RV
gkr_C_GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info)
{
	PREREQ (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL (session, C_GetSessionInfo);
	PROCESS_CALL;
		OUT_SESSION_INFO (info);
	END_CALL;
}

static CK_RV
gkr_C_InitPIN (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, 
               CK_ULONG pin_len)
{
	BEGIN_CALL (session, C_InitPIN);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_SetPIN (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin,
              CK_ULONG old_pin_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len)
{
	BEGIN_CALL (session, C_SetPIN);
		IN_BYTE_ARRAY (old_pin, old_pin_len);
		IN_BYTE_ARRAY (new_pin, old_pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_GetOperationState (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state,
                         CK_ULONG_PTR operation_state_len)
{
	BEGIN_CALL (session, C_GetOperationState);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (operation_state, operation_state_len, *operation_state_len);
	END_CALL;
}

static CK_RV
gkr_C_SetOperationState (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state,
                         CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                         CK_OBJECT_HANDLE authentication_key)
{
	BEGIN_CALL (session, C_SetOperationState);
		IN_BYTE_ARRAY (operation_state, operation_state_len);
		IN_HANDLE (encryption_key);
		IN_HANDLE (authentication_key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Login (CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
             CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	BEGIN_CALL (session, C_Login);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Logout (CK_SESSION_HANDLE session)
{
	BEGIN_CALL (session, C_Logout);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_CreateObject (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
                    CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	BEGIN_CALL (session, C_CreateObject);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_HANDLE (new_object);
	END_CALL;
}

static CK_RV
gkr_C_CopyObject (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                  CK_ATTRIBUTE_PTR template, CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR new_object)
{
	BEGIN_CALL (session, C_CopyObject);
		IN_HANDLE (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_HANDLE (new_object);
	END_CALL;
}


static CK_RV
gkr_C_DestroyObject (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	BEGIN_CALL (session, C_DestroyObject);
		IN_HANDLE (object);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_GetObjectSize (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                     CK_ULONG_PTR size)
{
	BEGIN_CALL (session, C_GetObjectSize);
		IN_HANDLE (object);
	PROCESS_CALL;
		OUT_ULONG (size);
	END_CALL;
}

static CK_RV
gkr_C_GetAttributeValue (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	BEGIN_CALL (session, C_GetAttributeValue);
		IN_HANDLE (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ATTRIBUTE_ARRAY (template, &count, count);
		OUT_RETURN_CODE ();
	END_CALL;
}

static CK_RV
gkr_C_SetAttributeValue (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	BEGIN_CALL (session, C_SetAttributeValue);
		IN_HANDLE (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_FindObjectsInit (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
                       CK_ULONG count)
{
	BEGIN_CALL (session, C_FindObjectsInit);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_FindObjects (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects,
                   CK_ULONG max_count, CK_ULONG_PTR count)
{
	BEGIN_CALL (session, C_FindObjects);
		IN_ULONG (max_count);
	PROCESS_CALL;
		OUT_HANDLE_ARRAY (objects, count, max_count);
	END_CALL;
}

static CK_RV
gkr_C_FindObjectsFinal (CK_SESSION_HANDLE session)
{
	BEGIN_CALL (session, C_FindObjectsFinal);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_EncryptInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_EncryptInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Encrypt (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
               CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	BEGIN_CALL (session, C_Encrypt);
		IN_BYTE_ARRAY (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_data, encrypted_data_len, *encrypted_data_len);
	END_CALL;
}

static CK_RV
gkr_C_EncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                     CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                     CK_ULONG_PTR encrypted_part_len)
{
	BEGIN_CALL (session, C_EncryptUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len, *encrypted_part_len);
	END_CALL;
}

static CK_RV
gkr_C_EncryptFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	BEGIN_CALL (session, C_EncryptFinal);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len, *last_part_len);
	END_CALL;
}

static CK_RV
gkr_C_DecryptInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_DecryptInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Decrypt (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_data,
               CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	BEGIN_CALL (session, C_Decrypt);
		IN_BYTE_ARRAY (enc_data, enc_data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len, *data_len);
	END_CALL;
}

static CK_RV
gkr_C_DecryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part,
                     CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	BEGIN_CALL (session, C_DecryptUpdate);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len, *part_len);
	END_CALL;
}

static CK_RV
gkr_C_DecryptFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	BEGIN_CALL (session, C_DecryptFinal);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len, *last_part_len);
	END_CALL;
}

static CK_RV
gkr_C_DigestInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism)
{
	BEGIN_CALL (session, C_DigestInit);
		IN_MECHANISM (mechanism);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Digest (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
              CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	BEGIN_CALL (session, C_Digest);
		IN_BYTE_ARRAY (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len, *digest_len);
	END_CALL;
}

static CK_RV
gkr_C_DigestUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	BEGIN_CALL (session, C_DigestUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_DigestKey (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_DigestKey);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_DigestFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR digest,
                   CK_ULONG_PTR digest_len)
{
	BEGIN_CALL (session, C_DigestFinal);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len, *digest_len);
	END_CALL;
}

static CK_RV
gkr_C_SignInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_SignInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Sign (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
            CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	BEGIN_CALL (session, C_Sign);
		IN_BYTE_ARRAY (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len, *signature_len);
	END_CALL;
}

static CK_RV
gkr_C_SignUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	BEGIN_CALL (session, C_SignUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_SignFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
                 CK_ULONG_PTR signature_len)
{
	BEGIN_CALL (session, C_SignFinal);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len, *signature_len);
	END_CALL;
}

static CK_RV
gkr_C_SignRecoverInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_SignRecoverInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_SignRecover (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, 
                   CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	BEGIN_CALL (session, C_SignRecover);
		IN_BYTE_ARRAY (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len, *signature_len);
	END_CALL;
}

static CK_RV
gkr_C_VerifyInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_VerifyInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_Verify (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len,
              CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	BEGIN_CALL (session, C_Verify);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_VerifyUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len)
{
	BEGIN_CALL (session, C_VerifyUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_VerifyFinal (CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
                   CK_ULONG signature_len)
{
	BEGIN_CALL (session, C_VerifyFinal);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_VerifyRecoverInit (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (session, C_VerifyRecoverInit);
		IN_MECHANISM (mechanism);
		IN_HANDLE (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_VerifyRecover (CK_SESSION_HANDLE session, CK_BYTE_PTR signature,
                     CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	BEGIN_CALL (session, C_VerifyRecover);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len, *data_len);
	END_CALL;
}

static CK_RV
gkr_C_DigestEncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                           CK_ULONG part_len, CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	BEGIN_CALL (session, C_DigestEncryptUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len, *enc_part_len);
	END_CALL;
}

static CK_RV
gkr_C_DecryptDigestUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                           CK_ULONG_PTR part_len)
{
	BEGIN_CALL (session, C_DecryptDigestUpdate);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len, *part_len);
	END_CALL;
}

static CK_RV
gkr_C_SignEncryptUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR part,
                         CK_ULONG part_len, CK_BYTE_PTR enc_part,
                         CK_ULONG_PTR enc_part_len)
{
	BEGIN_CALL (session, C_SignEncryptUpdate);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len, *enc_part_len);
	END_CALL;
}

static CK_RV
gkr_C_DecryptVerifyUpdate (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len, CK_BYTE_PTR part, 
                           CK_ULONG_PTR part_len)
{
	BEGIN_CALL (session, C_DecryptVerifyUpdate);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len, *part_len);
	END_CALL;
}

static CK_RV
gkr_C_GenerateKey (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                   CK_ATTRIBUTE_PTR template, CK_ULONG count, 
                   CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL (session, C_GenerateKey);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_HANDLE (key);
	END_CALL;
}

static CK_RV
gkr_C_GenerateKeyPair (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                       CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                       CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                       CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	BEGIN_CALL (session, C_GenerateKeyPair);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (pub_template, pub_count);
		IN_ATTRIBUTE_ARRAY (priv_template, priv_count);
	PROCESS_CALL;
		OUT_HANDLE (pub_key);
		OUT_HANDLE (priv_key);
	END_CALL;
}

static CK_RV
gkr_C_WrapKey (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
               CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
               CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	BEGIN_CALL (session, C_WrapKey);
		IN_MECHANISM (mechanism);
		IN_HANDLE (wrapping_key);
		IN_HANDLE (key);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (wrapped_key, wrapped_key_len, *wrapped_key_len);
	END_CALL;
}

static CK_RV
gkr_C_UnwrapKey (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                 CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                 CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL (session, C_UnwrapKey);
		IN_MECHANISM (mechanism);
		IN_HANDLE (unwrapping_key);
		IN_BYTE_ARRAY (wrapped_key, wrapped_key_len);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_HANDLE (key);
	END_CALL;
}

static CK_RV
gkr_C_DeriveKey (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                 CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL (session, C_DeriveKey);
		IN_MECHANISM (mechanism);
		IN_HANDLE (base_key);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_HANDLE (key);
	END_CALL;
}

static CK_RV
gkr_C_SeedRandom (CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	BEGIN_CALL (session, C_SeedRandom);
		IN_BYTE_ARRAY (seed, seed_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
gkr_C_GenerateRandom (CK_SESSION_HANDLE session, CK_BYTE_PTR random_data,
                      CK_ULONG random_len)
{
	BEGIN_CALL (session, C_GenerateRandom);
		IN_ULONG (random_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (random_data, &random_len, random_len);
	END_CALL;
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

/* 
 * PKCS#11 is broken here. It states that Unix compilers automatically byte 
 * pack structures. This is wrong. GCC on Linux aligns to 4 by default. 
 * 
 * This results in incompatibilities. Where this structure's first version
 * members take up too much or too little space depending on how this module
 * is compiled.
 */

static CK_FUNCTION_LIST functionList = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	gkr_C_Initialize,
	gkr_C_Finalize,
	gkr_C_GetInfo,
	gkr_C_GetFunctionList,
	gkr_C_GetSlotList,
	gkr_C_GetSlotInfo,
	gkr_C_GetTokenInfo,
	gkr_C_GetMechanismList,
	gkr_C_GetMechanismInfo,
	gkr_C_InitToken,
	gkr_C_InitPIN,
	gkr_C_SetPIN,
	gkr_C_OpenSession,
	gkr_C_CloseSession,
	gkr_C_CloseAllSessions,
	gkr_C_GetSessionInfo,
	gkr_C_GetOperationState,
	gkr_C_SetOperationState,
	gkr_C_Login,
	gkr_C_Logout,
	gkr_C_CreateObject,
	gkr_C_CopyObject,
	gkr_C_DestroyObject,
	gkr_C_GetObjectSize,
	gkr_C_GetAttributeValue,
	gkr_C_SetAttributeValue,
	gkr_C_FindObjectsInit,
	gkr_C_FindObjects,
	gkr_C_FindObjectsFinal,
	gkr_C_EncryptInit,
	gkr_C_Encrypt,
	gkr_C_EncryptUpdate,
	gkr_C_EncryptFinal,
	gkr_C_DecryptInit,
	gkr_C_Decrypt,
	gkr_C_DecryptUpdate,
	gkr_C_DecryptFinal,
	gkr_C_DigestInit,
	gkr_C_Digest,
	gkr_C_DigestUpdate,
	gkr_C_DigestKey,
	gkr_C_DigestFinal,
	gkr_C_SignInit,
	gkr_C_Sign,
	gkr_C_SignUpdate,
	gkr_C_SignFinal,
	gkr_C_SignRecoverInit,
	gkr_C_SignRecover,
	gkr_C_VerifyInit,
	gkr_C_Verify,
	gkr_C_VerifyUpdate,
	gkr_C_VerifyFinal,
	gkr_C_VerifyRecoverInit,
	gkr_C_VerifyRecover,
	gkr_C_DigestEncryptUpdate,
	gkr_C_DecryptDigestUpdate,
	gkr_C_SignEncryptUpdate,
	gkr_C_DecryptVerifyUpdate,
	gkr_C_GenerateKey,
	gkr_C_GenerateKeyPair,
	gkr_C_WrapKey,
	gkr_C_UnwrapKey,
	gkr_C_DeriveKey,
	gkr_C_SeedRandom,
	gkr_C_GenerateRandom,
	gkr_C_GetFunctionStatus,
	gkr_C_CancelFunction,
	gkr_C_WaitForSlotEvent
};

CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	PREREQ (list, CKR_ARGUMENTS_BAD);

	*list = &functionList;
	return CKR_OK;
}
