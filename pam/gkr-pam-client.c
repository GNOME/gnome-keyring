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

#include "common/gkr-buffer.h"

#include <sys/types.h>
#include <sys/socket.h>
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

#define PAM_APP_NAME      "Auto Login (PAM)"
#define PAM_APP_NAME_LEN  (sizeof (PAM_APP_NAME) - 1)

static int
connect_to_daemon (const char *path)
{
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
	union {
		struct cmsghdr hdr;
		char cred[CMSG_SPACE (sizeof (struct cmsgcred))];
	} cmsg;
	struct iovec iov;
	struct msghdr msg;
#endif

	struct sockaddr_un addr;
	int sock, bytes_written;
  	char buf;

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
	
	/* Write the credentials byte */
	buf = 0;
#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
	iov.iov_base = &buf;
	iov.iov_len = 1;

	memset (&msg, 0, sizeof (msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t) &cmsg;
	msg.msg_controllen = CMSG_SPACE (sizeof (struct cmsgcred));
	memset (&cmsg, 0, sizeof (cmsg));
	cmsg.hdr.cmsg_len = CMSG_LEN (sizeof (struct cmsgcred));
	cmsg.hdr.cmsg_level = SOL_SOCKET;
	cmsg.hdr.cmsg_type = SCM_CREDS;
#endif

again:

#if defined(HAVE_CMSGCRED) && (!defined(LOCAL_CREDS) || defined(__FreeBSD__))
	bytes_written = sendmsg (sock, &msg, 0);
#else
	bytes_written = write (sock, &buf, 1);
#endif

	if (bytes_written < 0) {
		if (errno == EINTR || errno == EAGAIN)
			goto again;
		syslog (GKR_LOG_ERR, "couldn't send credentials to: %s: %s", 
		        path, strerror (errno));
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
	gkr_buffer_encode_uint32 (buf, PAM_APP_NAME_LEN + 8);
	write_part (sock, buf, 4, &ret);
	gkr_buffer_encode_uint32 (buf, PAM_APP_NAME_LEN);
	write_part (sock, buf, 4, &ret);
	write_part (sock, (unsigned char*)PAM_APP_NAME, PAM_APP_NAME_LEN, &ret);
	    
	/* Calculate the packet length */
	oplen = 8; /* The packet size, and op code */
	for (i = 0; i < argc; ++i)  
		oplen += 4 + strlen (argv[i]);

	/* Write out the length, and op */
	gkr_buffer_encode_uint32 (buf, oplen);
	write_part (sock, buf, 4, &ret);
	gkr_buffer_encode_uint32 (buf, op);
	write_part (sock, buf, 4, &ret);
	
	/* And now the arguments */
	for (i = 0; i < argc; ++i) {
		if (argv[i] == NULL)
			l = 0x7FFFFFFF;
		else 
			l = strlen (argv[i]);
		gkr_buffer_encode_uint32 (buf, l);
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
	l = gkr_buffer_decode_uint32 (buf);
	if (l != 8) {
		syslog (GKR_LOG_ERR, "invalid length response from gnome-keyring-daemon: %d", l);
		ret = GNOME_KEYRING_RESULT_IO_ERROR;
		goto done;
	}

	if (read_part (sock, buf, 4) != 4) {
		ret = GNOME_KEYRING_RESULT_IO_ERROR;
		goto done;
	}
	ret = gkr_buffer_decode_uint32 (buf);
	
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
