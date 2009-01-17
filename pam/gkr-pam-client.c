/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pam-client.h - Simple code for communicating with daemon

   Copyright (C) 2007 Stef Walter

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

#include "gkr-pam.h"

#include "egg/egg-buffer.h"
#include "egg/egg-unix-credentials.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#if defined(HAVE_GETPEERUCRED)
#include <ucred.h>
#endif

#if defined(LOCAL_PEERCRED)
#include <sys/param.h>
#include <sys/ucred.h>
#endif

#define PAM_APP_NAME      "Auto Login (PAM)"
#define PAM_APP_NAME_LEN  (sizeof (PAM_APP_NAME) - 1)

static int
check_peer_same_uid (int sock)
{
	uid_t uid = -1;
	
	/* 
	 * Certain OS require a message to be sent over the unix socket for the 
	 * otherside to get the process credentials. Most uncool.
	 * 
	 * The normal gnome-keyring protocol accomodates this and the client
	 * sends a message/byte before sending anything else. This only works
	 * for the daemon verifying the client. 
	 * 
	 * This code here is used by a client to verify the daemon is running
	 * as the right user. Since we cannot modify the protocol, this only
	 * works on OSs that can do this credentials lookup transparently.
	 */

/* Linux */
#if defined(SO_PEERCRED)
	struct ucred cr;   
	socklen_t cr_len = sizeof (cr);
		
	if (getsockopt (sock, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) == 0 &&
	    cr_len == sizeof (cr)) {
	    	uid = cr.uid;
	} else {
		syslog (GKR_LOG_ERR, "could not get gnome-keyring-daemon socket credentials, "
		        "(returned len %d/%d)\n", cr_len, (int) sizeof (cr));
		return -1;
	}


/* The BSDs */
#elif defined(LOCAL_PEERCRED)
	uid_t gid;
        struct xucred xuc;
        socklen_t xuc_len = sizeof (xuc);

	if (getsockopt (sock, SOL_SOCKET, LOCAL_PEERCRED, &xuc, &xuc_len) == 0 && 
	    xuc_len == sizeof (xuc)) {
	    	uid = xuc.cr_uid;
	} else {
		syslog (GKR_LOG_ERR, "could not get gnome-keyring-daemon socket credentials, "
		        "(returned len %d/%d)\n", xuc_len, (int)sizeof (xuc));
		return -1;   
	}
	
	
/* NOTE: Add more here */
#else
	syslog (GKR_LOG_WARN, "Cannot verify that the process to which we are passing the login"
	        " password is genuinely running as the same user login: not supported on this OS.");
	uid = geteuid ();
	
	
#endif

	if (uid != geteuid ()) {
		syslog (GKR_LOG_ERR, "The gnome keyring socket is not running with the same "
		        "credentials as the user login. Disconnecting.");
		return 0;
	}
	
	return 1;
}

static int
write_credentials_byte (int sock)
{
	for (;;) {
		if (egg_unix_credentials_write (sock) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			syslog (GKR_LOG_ERR, "couldn't send credentials to daemon: %s", 
			        strerror (errno));
			return -1;
		}
		
		break;
	}
	
	return 0;
}

static int
connect_to_daemon (const char *path)
{
	struct sockaddr_un addr;
	struct stat st;
	int sock;
	
	/* First a bunch of checks to make sure nothing funny is going on */
	
	if (lstat (path, &st) < 0) {
		syslog (GKR_LOG_ERR, "Couldn't access gnome keyring socket: %s: %s", 
		        path, strerror (errno));
		return -1;
	}
	
	if (st.st_uid != geteuid ()) {
		syslog (GKR_LOG_ERR, "The gnome keyring socket is not owned with the same "
		        "credentials as the user login: %s", path);
		return -1;
	}
	
	if (S_ISLNK(st.st_mode) || !S_ISSOCK(st.st_mode)) {
		syslog (GKR_LOG_ERR, "The gnome keyring socket is not a valid simple "
		        "non-linked socket");
		return -1;
	}	
	
	/* Now we connect */

	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, path, sizeof (addr.sun_path));
	
	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog (GKR_LOG_ERR, "couldn't create socket: %s", strerror (errno));
		return -1;
	}

	/* close on exec */
	fcntl (sock, F_SETFD, 1);

	if (connect (sock, (struct sockaddr*) &addr, sizeof (addr)) < 0) {
		syslog (GKR_LOG_ERR, "couldn't connect to daemon at: %s: %s", 
		        path, strerror (errno));
		close (sock);
		return -1;
	}
	
	/* Verify the server is running as the right user */
	
	if (check_peer_same_uid (sock) <= 0) {
		close (sock);
		return -1;
	}
	
	/* This lets the server verify us */
	
	if (write_credentials_byte (sock) < 0) {
		close (sock);
		return -1;
	}
	
	return sock;
}

static void
write_part (int fd, const unsigned char *data, int len, GnomeKeyringResult *res)
{
	assert (res);
	
	/* Already an error present */
	if (*res != GNOME_KEYRING_RESULT_OK)
		return;
	
	assert (data);
	
	while (len > 0) {
		int r = write (fd, data, len);
		if (r < 0) {
			if (errno == EAGAIN) 
				continue;
			syslog (GKR_LOG_ERR, "couldn't send data to gnome-keyring-daemon: %s", 
			        strerror (errno));
			*res = GNOME_KEYRING_RESULT_IO_ERROR;
			return;
		}
		data += r;
		len -= r;
	}
}

static int 
read_part (int fd, unsigned char *data, int len) 
{
	int r, all;
	
	all = len;
	while (len > 0) {
		r = read (fd, data, len);
		if (r < 0) {
			if (errno == EAGAIN)
				continue;
			syslog (GKR_LOG_ERR, "couldn't read data from gnome-keyring-daemon: %s",
			        strerror (errno));
			return -1;
		} 
		if (r == 0) { 
			syslog (GKR_LOG_ERR, "couldn't read data from gnome-keyring-daemon: %s",
			        "unexpected end of data");
			return -1;
		}
		
		data += r;
		len -= r;
	}

	return all;
}

static GnomeKeyringResult 
keyring_daemon_op (const char *socket, GnomeKeyringOpCode op, int argc, 
                   const char* argv[])
{
	GnomeKeyringResult ret = GNOME_KEYRING_RESULT_OK;
	unsigned char buf[4];
	int i, sock = -1;
	uint oplen, l;
	
	assert (socket);
	
	/* 
	 * We only support operations with zero or more strings
	 * and an empty (only result code) return. 
	 */
	 
	assert (op == GNOME_KEYRING_OP_UNLOCK_KEYRING || 
	        op == GNOME_KEYRING_OP_CREATE_KEYRING || 
	        op == GNOME_KEYRING_OP_CHANGE_KEYRING_PASSWORD);

	sock = connect_to_daemon (socket);
	if (sock < 0) {
		ret = -1;
		goto done;
	}
	
	/* Send the application packet / name */
	egg_buffer_encode_uint32 (buf, PAM_APP_NAME_LEN + 8);
	write_part (sock, buf, 4, &ret);
	egg_buffer_encode_uint32 (buf, PAM_APP_NAME_LEN);
	write_part (sock, buf, 4, &ret);
	write_part (sock, (unsigned char*)PAM_APP_NAME, PAM_APP_NAME_LEN, &ret);
	    
	/* Calculate the packet length */
	oplen = 8; /* The packet size, and op code */
	for (i = 0; i < argc; ++i)  
		oplen += 4 + strlen (argv[i]);

	/* Write out the length, and op */
	egg_buffer_encode_uint32 (buf, oplen);
	write_part (sock, buf, 4, &ret);
	egg_buffer_encode_uint32 (buf, op);
	write_part (sock, buf, 4, &ret);
	
	/* And now the arguments */
	for (i = 0; i < argc; ++i) {
		if (argv[i] == NULL)
			l = 0x7FFFFFFF;
		else 
			l = strlen (argv[i]);
		egg_buffer_encode_uint32 (buf, l);
		write_part (sock, buf, 4, &ret);
		if (argv[i] != NULL)
			write_part (sock, (unsigned char*)argv[i], l, &ret);
	}
	
	if (ret != GNOME_KEYRING_RESULT_OK)
		goto done;
	    	
	/* Read the response length */
	if (read_part (sock, buf, 4) != 4) {
		ret = GNOME_KEYRING_RESULT_IO_ERROR;
		goto done;
	}

	/* We only support simple responses */	
	l = egg_buffer_decode_uint32 (buf);
	if (l != 8) {
		syslog (GKR_LOG_ERR, "invalid length response from gnome-keyring-daemon: %d", l);
		ret = GNOME_KEYRING_RESULT_IO_ERROR;
		goto done;
	}

	if (read_part (sock, buf, 4) != 4) {
		ret = GNOME_KEYRING_RESULT_IO_ERROR;
		goto done;
	}
	ret = egg_buffer_decode_uint32 (buf);
	
done:
	if (sock >= 0)
		close (sock);
	
	return ret;
}

GnomeKeyringResult
gkr_pam_client_run_operation (struct passwd *pwd, const char *socket, 
                              GnomeKeyringOpCode op, int argc, const char* argv[])
{
	struct sigaction ignpipe, oldpipe, defchld, oldchld;
	GnomeKeyringResult res;
	pid_t pid;
	int status;
	
	/* Make dumb signals go away */
	memset (&ignpipe, 0, sizeof (ignpipe));
	memset (&oldpipe, 0, sizeof (oldpipe));
	ignpipe.sa_handler = SIG_IGN;
	sigaction (SIGPIPE, &ignpipe, &oldpipe);
	
	memset (&defchld, 0, sizeof (defchld));
	memset (&oldchld, 0, sizeof (oldchld));
	defchld.sa_handler = SIG_DFL;
	sigaction (SIGCHLD, &defchld, &oldchld);

	if (pwd->pw_uid == getuid () && pwd->pw_gid == getgid () && 
	    pwd->pw_uid == geteuid () && pwd->pw_gid == getegid ()) {

		/* Already running as the right user, simple */
		res = keyring_daemon_op (socket, op, argc, argv);
		
	} else {
		
		/* Otherwise run a child process to do the dirty work */
		switch (pid = fork ()) {
		case -1:
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't fork: %s", 
			        strerror (errno));
			res = GNOME_KEYRING_RESULT_IO_ERROR;
			break;
			
		case 0:
			/* Setup process credentials */
			if (setgid (pwd->pw_gid) < 0 || setuid (pwd->pw_uid) < 0 ||
			    setegid (pwd->pw_gid) < 0 || seteuid (pwd->pw_uid) < 0) {
				syslog (GKR_LOG_ERR, "gkr-pam: couldn't switch to user: %s: %s", 
				        pwd->pw_name, strerror (errno));
				exit (GNOME_KEYRING_RESULT_IO_ERROR);
			}
	
			res = keyring_daemon_op (socket, op, argc, argv);
			exit (res);
			return 0; /* Never reached */
			
		default:
			/* wait for child process */
			if (wait (&status) != pid) {
				syslog (GKR_LOG_ERR, "gkr-pam: couldn't wait on child process: %s", 
				        strerror (errno));
				res = GNOME_KEYRING_RESULT_IO_ERROR;
			}
			
			res = WEXITSTATUS (status);
			break;
		};
	}
	
	sigaction (SIGCHLD, &oldchld, NULL);
	sigaction (SIGPIPE, &oldpipe, NULL);
	
	return res;
}
