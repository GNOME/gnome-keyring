/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gkr-pam-module.h - A PAM module for unlocking the keyring

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

/* 
 * Inspired by pam_keyring:
 *   W. Michael Petullo <mike@flyn.org>
 *   Jonathan Nettleton <jon.nettleton@gmail.com>
 */

#include "config.h"

#include <security/pam_modules.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define USE_PID_FILE 0

#if USE_PID_FILE
/* Although this starts with a slash, it is relative to the home dir */
#define HOME_PID_LOCATION	"/.gnome2/keyrings/run/pam-gnome-keyring.pid"
#endif

enum {
	FLAG_DEBUG =     0x0100,
	FLAG_TRY_FIRST = 0x0100,
	FLAG_USE_FIRST = 0x0200
};

#define GKR_LOG_ERR   (LOG_ERR | LOG_AUTHPRIV)
#define GKR_LOG_WARN  (LOG_WARNING | LOG_AUTHPRIV)

#define ENV_SOCKET 		"GNOME_KEYRING_SOCKET"
#define ENV_PID    		"GNOME_KEYRING_PID"

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

#ifndef PAM_AUTHTOK_RECOVERY_ERR
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif

/* -----------------------------------------------------------------------------
 * HELPERS 
 */
 

static void
close_safe (int fd)
{
	if (fd != -1)
		close (fd);
}

static void
free_safe (void *data)
{
	if (data)
		free (data);
}

static void
free_password (char *password)
{
        volatile char *vp = (volatile char*)password;
        while (password && *vp) 
        	*(vp++) = 0xAA;
	free_safe (password);
}

static char* 
strbtrim (char* data)
{
	assert (data);
	while (*data && isspace (*data))
		++data;
	return (char*)data;
}

typedef int (*line_cb) (char *line, void *arg);

static int
foreach_line (char *lines, line_cb cb, void *arg)
{
	char *line;
	int ret;
	
	assert (lines);
	
	while ((line = strsep (&lines, "\n")) != NULL) {
		 ret = (cb) (line, arg);
		 if (ret != PAM_SUCCESS)
		 	return ret;
	}
	
	return PAM_SUCCESS;
}

#if USE_PID_FILE

static int
mkdir_parents (const char *file)
{
	struct stat st;
	const char *pos;
	char *path;
	int ret = -1;
	
	assert (file);
	
	path = malloc (strlen (file) + 1);
	if (!path) {
		errno = ENOMEM;
		return -1;
	}
	
	path[0] = 0;
	for (;;) {
	
		pos = strchr (file, '/');
		if (!pos) {
			ret = 0;
			break;
		}
	
		strncat (path, file, pos - file);
		if (path[0] && stat (path, &st) < 0) {
			if (errno != ENOENT && errno != ENOTDIR)
				break;
			if (mkdir (path, 0700) < 0)
				break;
		}
			
		file = pos + 1;
		strcat (path, "/");
	}
	
	free (path);
	return ret;
}

#endif /* USE_PID_FILE */

static char*
read_all (int fd)
{
	char buf[256];
	char *ret = NULL;
	int r, len = 0;
	
	for (;;) {
		r = read (fd, buf, sizeof (buf));
		if (r < 0) {
			if (errno == EAGAIN)
				continue;
			free_safe (ret);
			return NULL;
			
		} else  { 
			char *n = realloc (ret, len + r + 1);
			if (!n) {
				free_safe (ret);
				errno = ENOMEM;
				return NULL;
			}
			memset(n + len, 0, r + 1); 
			ret = n;
			len = len + r;
			
			strncat (ret, buf, r);
		}
		
		if (r == 0)
			break;
	}
	
	return ret;
}

static int
write_all (int fd, const char *data)
{
	struct sigaction ignoresact, oldsact;
	int len, all, r;
	
	assert (data);
	
	memset (&ignoresact, 0, sizeof (ignoresact));
	memset (&oldsact, 0, sizeof (oldsact));
	ignoresact.sa_handler = SIG_IGN;
	
	all = len = strlen (data);

	/* Don't let SIGPIPE occur */
	if (sigaction (SIGPIPE, &ignoresact, &oldsact) < 0)
		return -1;

	while (len > 0) {
		r = write (fd, data, len);
		if (r < 0) {
			if (errno == EAGAIN) 
				continue;
			return -1;
		}
		data += r;
		len -= r;
	}
			
	/* Restore old handler */
	sigaction (SIGPIPE, &oldsact, NULL);
	
	return all;
}

/* -----------------------------------------------------------------------------
 * DAEMON MANAGEMENT 
 */

static int
setup_pam_env (pam_handle_t *ph, const char *name, const char *val)
{
	int ret;
	char *var;
	
	assert (name);
	assert (val);
	
	var = malloc (strlen (name) + strlen (val) + 2);
	if (!var) {
		syslog (GKR_LOG_ERR, "gkr-pam: out of memory");
		return PAM_SYSTEM_ERR;
	} 
	
	sprintf (var, "%s=%s", name, val);
	ret = pam_putenv (ph, var);
	free (var);
	
	return ret;
}

static void
cleanup_free (pam_handle_t *ph, void *data, int pam_end_status)
{
	free_safe (data);
}

#if USE_PID_FILE
static void
write_create_pid (struct passwd *pwd, const char *spid)
{
	char *path;
	int fd, r;
	
	assert (pwd);
	assert (pwd->pw_dir);
	assert (spid);
	
	/* All strings strcat'd below must fit in 1024 */
	path = malloc (strlen (HOME_PID_LOCATION) + strlen (pwd->pw_dir) + 1);
	if (!path) {
		syslog (GKR_LOG_ERR, "gkr-pam: out of memory");
		return;
	}
	
	strcpy (path, pwd->pw_dir);
	strcat (path, HOME_PID_LOCATION);
	
	if (mkdir_parents (path) < 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't create directory");
		free (path);
		return;
	}

	fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't open pid file: %s: %s", 
		        path, strerror (errno));

	} else {
		r = write_all (fd, spid);
		close (fd);
	
		if (r < 0) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't write to pid file: %s: %s",
		        	path, strerror (errno));
		}
	}
	
	free (path);
}

static char*
read_delete_pid (struct passwd *pwd)
{
	char *spid = NULL;
	char *path;
	int fd;
	
	assert (pwd);
	assert (pwd->pw_dir);
	
	path = malloc (strlen (HOME_PID_LOCATION) + strlen (pwd->pw_dir) + 1);
	if (!path) {
		syslog (GKR_LOG_ERR, "gkr-pam: out of memory");
		return NULL;
	}
	
	strcpy (path, pwd->pw_dir);
	strcat (path, HOME_PID_LOCATION);
	
	fd = open (path, O_RDONLY);
	if (fd == -1) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't open pid file: %s: %s",
		        path, strerror (errno));
	
	} else {
		
		spid = read_all (fd);
		if (!spid) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't read pid file: %s: %s",
			        path, strerror (errno));
		}
		
		close (fd);
		
		/* Delete the file now that we no longer need it */
		unlink (path);
	}
	
	free (path);
	return spid;
}

#endif /* USE_PID_FILE */

static void
setup_child (int inp[2], int outp[2], int errp[2], struct passwd *pwd)
{
	char *args[] = { GNOME_KEYRING_DAEMON, "-d",  
	                 "--unsupported-version-specific-magic", NULL};
	
	assert (pwd);
	assert (pwd->pw_dir);
	
	/* Fix up our end of the pipes */
	if (dup2 (inp[READ_END], STDIN) < 0 || 
	    dup2 (outp[WRITE_END], STDOUT) < 0 || 
	    dup2 (errp[WRITE_END], STDERR) < 0) {
	    	syslog (GKR_LOG_ERR, "gkr-pam: couldn't setup pipes: %s",
		        strerror (errno));
		exit (EXIT_FAILURE);
	}
	    
	/* Close unnecessary file descriptors */
	close (inp[READ_END]);
	close (inp[WRITE_END]);
	close (outp[READ_END]);
	close (outp[WRITE_END]);
	close (errp[READ_END]);
	close (errp[WRITE_END]);
	
	/* We may be running effective as another user, revert that */
	seteuid (getuid ());
	setegid (getgid ());
	
	/* Setup process credentials */
	if (setgid (pwd->pw_gid) < 0 || setuid (pwd->pw_uid) < 0 ||
	    setegid (pwd->pw_gid) < 0 || seteuid (pwd->pw_uid) < 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't setup credentials: %s", 
		        strerror (errno));
		exit (EXIT_FAILURE);
	}
	
	/* Setup environment variables */
	if (setenv ("HOME", pwd->pw_dir, 1) < 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't setup environment: %s", 
		        strerror (errno));
		exit (EXIT_FAILURE);
	}

	/* Now actually execute the process */
	execv (args[0], args);
	syslog (GKR_LOG_ERR, "gkr-pam: couldn't run gnome-keyring-daemon: %s", 
	        strerror (errno));
	exit (EXIT_FAILURE);
}


static int 
log_problem (char *line, void *arg)
{
	int *failed;
	
	assert (line);
	assert (arg);
	
	failed = (int*)arg;
	syslog (*failed ? GKR_LOG_ERR : GKR_LOG_WARN, "%s", line);
	return PAM_SUCCESS;
}

static int
setup_environment (char *line, void *arg)
{
	pam_handle_t *ph = (pam_handle_t*)arg;
	char *x;
	int ret;
	
	assert (line);
	assert (arg);
	
	if (!strchr (line, '='))
		return PAM_SUCCESS;
			
	/* Trim the start and end of the line */
	line = strbtrim (line);
	
	ret = pam_putenv (ph, line);
	
	/* If it's the PID line then we're interested in it */
	if (strncmp (line, ENV_PID, strlen (ENV_PID)) == 0) { 
		x = line + strlen (ENV_PID);
		if (x[0] == '=')
			pam_set_data (ph, "gkr-pam-pid", strdup (x + 1), cleanup_free);
	}
	
	return ret;
}

static int
start_unlock_daemon (pam_handle_t *ph, struct passwd *pwd, void *arg)
{
	struct sigaction defsact, oldsact;
	const char *password = (const char*)arg;
	int inp[2] = { -1, -1 };
	int outp[2] = { -1, -1 };
	int errp[2] = { -1, -1 };
	int ret = PAM_SERVICE_ERR;
	pid_t pid;
	char *output = NULL;
	char *outerr = NULL;
	int failed, status;
	
	assert (pwd);
	assert (password);

	/* Make sure that SIGCHLD occurs */
	memset (&defsact, 0, sizeof (defsact));
	memset (&oldsact, 0, sizeof (oldsact));
	defsact.sa_handler = SIG_DFL;
	sigaction (SIGCHLD, &defsact, &oldsact);
	
	/* Create the necessary pipes */
	if (pipe (inp) < 0 || pipe (outp) < 0 || pipe (errp) < 0) {
	    	syslog (GKR_LOG_ERR, "gkr-pam: couldn't create pipes: %s", 
	    	        strerror (errno));
	    	goto done;
	}


	switch (pid = fork ()) {
	case -1:
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't fork: %s", 
		        strerror (errno));
		goto done;
		
	/* This is the child */
	case 0:
		setup_child (inp, outp, errp, pwd);
		/* Should never be reached */
		break;
		
	/* This is the parent */
	default:
		break;
	};
	
	/* Close our unneeded ends of the pipes */
	close (inp[READ_END]);
	close (outp[WRITE_END]);
	close (errp[WRITE_END]);
	inp[READ_END] = outp[WRITE_END] = errp[WRITE_END] = -1; 
	
	/* 
	 * Note that we're not using select or any such. We know how the daemon
	 * expects and processes data.
	 */
	 
	/* Send the password */
	if (write_all (inp[WRITE_END], password) < 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't write password to gnome-keyring-daemon: %s", 
		        strerror (errno));
		goto done;
	}
	
	/* Tell daemon that's the end of the password */
	close (inp[WRITE_END]);
	inp[WRITE_END] = -1;
	
	/* Read any stdout data */
	output = read_all (outp[READ_END]);
	if (!output) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't read environment variables from gnome-keyring-daemon: %s", 
		        strerror (errno));
		goto done;
	}

	/* Read any stderr data */
	outerr = read_all (errp[READ_END]);
	if (!outerr) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't read environment variables from gnome-keyring-daemon: %s", 
		        strerror (errno));
		goto done;
	}
	
	/* Wait for the initial process to exit */
	if (waitpid (pid, &status, 0) < 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't wait on gnome-keyring-daemon process: %s",
		        strerror (errno));
		goto done;
	}
	
	failed = !WIFEXITED (status) || WEXITSTATUS (status) != 0;
	if (outerr && outerr[0])
		foreach_line (outerr, log_problem, &failed);
	
	/* Failure from process */
	if (failed) {
		syslog (GKR_LOG_ERR, "gkr-pam: gnome-keyring-daemon didn't start properly properly");
		goto done;
	}
		
	/* Yay, all done */
	ret = foreach_line (output, setup_environment, ph);

#if USE_PID_FILE
	{
		const char *spid;
		/* Store this away in in the user's home directory if possible */
		if (pam_get_data (ph, "gkr-pam-pid", (const void**)&spid) == PAM_SUCCESS && spid)
			write_create_pid (pwd, spid);
	}
#endif

done:
	/* Restore old handler */
	sigaction (SIGCHLD, &oldsact, NULL);
	
	close_safe (inp[0]);
	close_safe (inp[1]);
	close_safe (outp[0]);
	close_safe (outp[1]);
	close_safe (errp[0]);
	close_safe (errp[1]);
	
	free_safe (output);
	free_safe (outerr);

	return ret;
}

static int
stop_daemon (pam_handle_t *ph, struct passwd *pwd, void *unused)
{
	const char *spid;
	char *apid = NULL;
	pid_t pid;
	
	assert (pwd);

	/* Try and read it from the pam handle */
	spid = NULL;
	pam_get_data (ph, "gkr-pam-pid", (const void**)&spid);
	
#if USE_PID_FILE
	/* Read and delete the pid file */
	apid = read_delete_pid (pwd);
	if (!spid)
		spid = apid;
#endif

	/* 
	 * No pid, no worries, maybe we didn't start gnome-keyring-daemon
	 * Or this the calling (PAM using) application is hopeless and 
	 * wants to call different PAM callbacks from different functions.
	 * 
	 * In any case we live and let live.
	 */
	if (!spid)
		goto done;
	
	/* Make sure it parses out nicely */
	pid = (pid_t)atoi (spid);
	if (pid <= 0) {
		syslog (GKR_LOG_ERR, "gkr-pam: invalid gnome-keyring-daemon process id: %s", spid);
		goto done;
	}
	
    	if (kill (pid, SIGTERM) < 0 && errno != ESRCH) {
    		syslog (GKR_LOG_ERR, "gkr-pam: couldn't kill gnome-keyring-daemon process %d: %s", 
    		        (int)pid, strerror (errno));
    		goto done;
    	}    		
	
done:
	free_safe (apid);
	
	/* Don't bother user when daemon can't be stopped */
	return PAM_SUCCESS;
}
 
/* -----------------------------------------------------------------------------
 * PAM STUFF
 */

static int
prompt_password (pam_handle_t *ph)
{
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp;
	const struct pam_message *msgs[1];
	const void *item;
	char *password;
	int ret;

	/* Get the conversation function */
	ret = pam_get_item (ph, PAM_CONV, &item);
	if (ret != PAM_SUCCESS)
		return ret;

	/* Setup a message */
	memset (&msg, 0, sizeof (msg));
	memset (&resp, 0, sizeof (resp));
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = "Password: ";
	msgs[0] = &msg;
	
	/* Call away */
	conv = (const struct pam_conv*)item;
	ret = (conv->conv) (1, msgs, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS)
		return ret;
	
	/* Yay the password */	
	password = resp[0].resp;
	free (resp);
	
	if (password == NULL) 
		return PAM_CONV_ERR;
		
	/* Store it away */
	ret = pam_set_item (ph, PAM_AUTHTOK, password);
	free_password (password);

	if (ret == PAM_SUCCESS)
		ret = pam_get_item (ph, PAM_AUTHTOK, &item); 

	return ret;
}

typedef int (*action_func) (pam_handle_t *ph, struct passwd *pwd, void *arg);

static int
run_as_user (pam_handle_t *ph, struct passwd *pwd, action_func func, void *arg)
{
	uid_t egid, euid;
	int ret;
	
	assert (pwd);
	assert (func);
	
	egid = getegid ();
	euid = geteuid ();
	
	if (setegid (pwd->pw_gid) < 0 || seteuid (pwd->pw_uid) < 0) {
	    	syslog (GKR_LOG_ERR, "couldn't change to user credentials: %s: %s",
	    	        pwd->pw_name, strerror (errno));
	    	        
		/* Try our best to switch back */
		seteuid (euid);
		setegid (egid);
		return PAM_SYSTEM_ERR;
	}
		
	/* Run the action */
	ret = (func) (ph, pwd, arg);
	
	/* Switch back */
	if (seteuid (euid) < 0 || setegid (egid) < 0) {
		syslog (GKR_LOG_ERR, "couldn't revert from user credentials: %s: %s", 
		        pwd->pw_name, strerror (errno));
		return PAM_SYSTEM_ERR;
	}

	return ret;
} 
	
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *ph, int unused, int argc, const char **argv)
{
	uint args = 0;
	struct passwd *pwd;
	const char *user, *password, *env;
	int ret;
		
	/* Parse the arguments */
	for (; argc-- > 0; ++argv) {
		if (strcasecmp (argv[0], "debug") == 0)
			args |= FLAG_DEBUG;
		else if (strcasecmp (argv[0], "use_first_pass") == 0)
			args |= FLAG_USE_FIRST;
		else if (strcasecmp (argv[0], "try_first_pass") == 0)
			args |= FLAG_TRY_FIRST;
		else
			syslog (GKR_LOG_WARN, "gkr-pam: invalid option: %s", argv[0]);
	}
	
	/* Figure out and/or prompt for the user name */
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the user name: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}
	
	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information for: %s", user);
		return PAM_SERVICE_ERR;
	}
		
	/* Prompt for a password if necessary */
	if (!(args & FLAG_TRY_FIRST) && !(args & FLAG_USE_FIRST)) {
		ret = prompt_password (ph);
		if (ret != PAM_SUCCESS) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s",
			        pam_strerror (ph, ret));
			return PAM_AUTH_ERR;
		}
	}
	
	/* Now look up the password */
	ret = pam_get_item (ph, PAM_AUTHTOK, (const void**)&password);
	if (ret != PAM_SUCCESS || password == NULL) {
		if (!(args & FLAG_TRY_FIRST)) {
			ret = prompt_password (ph);
			if (ret != PAM_SUCCESS) {
				syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
				        pam_strerror (ph, ret));
				return PAM_AUTH_ERR;
			}
			ret = pam_get_item (ph, PAM_AUTHTOK, (const void**)&password);
		} 
		if (ret != PAM_SUCCESS || password == NULL) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
			        ret == PAM_SUCCESS ? "password was null" : pam_strerror (ph, ret));
			return PAM_AUTHTOK_RECOVERY_ERR;
		}
	}
	
	/* See if it's already running, and transfer env variables */
	env = getenv (ENV_SOCKET);
	if (env && env[0]) {
		ret = setup_pam_env (ph, ENV_SOCKET, env);
		if (ret == PAM_SUCCESS) {
			env = getenv (ENV_PID);
			if (env && env[0])
				ret = setup_pam_env (ph, ENV_PID, env);
		}
		
		if (ret != PAM_SUCCESS) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't set environment variables: %s",
			        pam_strerror (ph, ret));
			return ret;
		}
			 
		syslog (GKR_LOG_WARN, "gkr-pam: gnome-keyring-daemon already running");
		return PAM_SUCCESS;
	}
	
	/* Change effective user id for process */
	ret = run_as_user (ph, pwd, start_unlock_daemon, (void*)password);
	if (ret != PAM_SUCCESS)
		return ret;
	 
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	struct passwd *pwd;
	const char *user;
	int ret;
	
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get user from pam: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}
	
	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information for: %s", user);
		return PAM_SERVICE_ERR;
	}

	run_as_user (ph, pwd, stop_daemon, NULL);
	
	/* Don't bother user when daemon can't be stopped */
	return PAM_SUCCESS; 
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * ph, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;	
}

#if 0

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	/* TODO: Implement properly */
	return PAM_SUCCESS;
}

#endif
