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
   <http://www.gnu.org/licenses/>.

   Author: Stef Walter <stef@memberwebs.com>
*/

/* 
 * Inspired by pam_keyring:
 *   W. Michael Petullo <mike@flyn.org>
 *   Jonathan Nettleton <jon.nettleton@gmail.com>
 */

#include "config.h"

#include "gkr-pam.h"

#include "daemon/control/gkd-control-codes.h"

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#if defined(ENABLE_NLS) && defined(__linux__)
#include <libintl.h>
#define gkr_pam_gettext(msgid) dgettext ("Linux-PAM", msgid)
#else
#define gkr_pam_gettext(msgid) (msgid)
#endif /* ENABLE_NLS */

enum {
	ARG_AUTO_START          = 1 << 0,
	ARG_IGNORE_SERVICE      = 1 << 1,
	ARG_USE_AUTHTOK	        = 1 << 2
};

#define ENV_CONTROL             "GNOME_KEYRING_CONTROL"

#define MAX_CONTROL_SIZE	(sizeof(((struct sockaddr_un *)0)->sun_path))

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

/* Linux/BSD compatibility */
#ifndef PAM_AUTHTOK_RECOVER_ERR
#define PAM_AUTHTOK_RECOVER_ERR PAM_AUTHTOK_RECOVERY_ERR
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
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
	volatile char *vp;
	size_t len;
	
	if (!password)
		return;

	/* Defeats some optimizations */		
	len = strlen (password);
	memset (password, 0xAA, len);
	memset (password, 0xBB, len);

	/* Defeats others */
        vp = (volatile char*)password;
        while (*vp) 
        	*(vp++) = 0xAA;

	free (password);
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
	char *line, *ctx;
	int ret;
	
	assert (lines);
	
	/* Call cb for each line in the text block */
	for (line = strtok_r (lines, "\n", &ctx); line != NULL; 
	     line = strtok_r (NULL, "\n", &ctx)) {
		 ret = (cb) (line, arg);
		 if (ret != PAM_SUCCESS)
		 	return ret;
	}
	
	return PAM_SUCCESS;
}

static char*
read_string (int fd)
{
	/* We only accept a max of 8K from the daemon */
	#define MAX_LENGTH 8192
	
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
		
		if (r == 0 || len > MAX_LENGTH)
			break;
	}
	
	return ret;
}

static int
write_string (int fd, const char* buf)
{
	size_t bytes = 0;
	int res, len = strlen (buf);

	while (bytes < len) {
		res = write (fd, buf + bytes, len - bytes);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN)
				return -1;
		} else {
			bytes += res;
		}
	}
	
	return 0;
}

/* check for list match. */
static int
evaluate_inlist (const char *needle, const char *haystack)
{
	const char *item;
	const char *remaining;

	if (!needle)
		return 0;

	remaining = haystack;

	for (;;) {
		item = strstr (remaining, needle);
		if (item == NULL)
			break;

		/* is it really the start of an item in the list? */
		if (item == haystack || *(item - 1) == ',') {
			item += strlen (needle);
			/* is item really needle? */
			if (*item == '\0' || *item == ',')
                                return 1;
		}

                remaining = strchr (item, ',');
                if (remaining == NULL)
                        break;

		/* skip ',' */
		++remaining;
        }

        return 0;
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

static const char*
get_any_env (pam_handle_t *ph, const char *name)
{
	const char *env;
	
	assert (name);
	
	/* We only return non-empty variables */
	
	/* 
	 * Some PAMs decide to strdup the return value, not sure 
	 * how we can detect this.
	 */
	env = pam_getenv (ph, name);
	if (env && env[0]) 
		return env;
		
	env = getenv (name);
	if (env && env[0])
		return env;
		
	return NULL;
}

static void
cleanup_free_password (pam_handle_t *ph, void *data, int pam_end_status)
{
	free_password (data);
}

#ifdef WITH_SELINUX
#include  <selinux/selinux.h>
/* Attempt to set SELinux Context. We are ignoring failure and just going
   with default behaviour
*/
static void setup_selinux_context(const char *command) {
	security_context_t fcon = NULL, newcon = NULL, execcon = NULL;

	if (is_selinux_enabled() != 1) return;

	int ret = getexeccon(&execcon);
	if ((ret < 0) || (! execcon)) goto err;

	ret = getfilecon(command, &fcon);
	if (ret < 0) goto err;

	ret = security_compute_create(execcon, fcon, string_to_security_class ("process"), &newcon);
	if (ret < 0) goto err;

	setexeccon(newcon);

err:
	freecon(newcon);
	freecon(fcon);
	freecon(execcon);
	return;
}
#endif

static void
setup_child (int inp[2],
             int outp[2],
             int errp[2],
             pam_handle_t *ph,
             struct passwd *pwd,
             const char *argument)
{
	const char* display;
	const char *runtime;
	int i, ret;

	char *args[] = {
		GNOME_KEYRING_DAEMON,
		"--daemonize",
		(char *)argument,
		NULL
	};

#ifdef WITH_SELINUX
	setup_selinux_context(GNOME_KEYRING_DAEMON);
#endif

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

	/* Try valiantly to close unnecessary file descriptors */
	for (i = STDERR; i < 64; ++i)
		close (i);
	    
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
	ret = setup_pam_env (ph, "HOME", pwd->pw_dir);
	if (ret == PAM_SUCCESS && !pam_getenv (ph, "DISPLAY")) {
		display = getenv ("DISPLAY");
		if (display)
			ret = setup_pam_env (ph, "DISPLAY", display);
	}
	if (ret == PAM_SUCCESS && !pam_getenv (ph, "XDG_RUNTIME_DIR")) {
		runtime = getenv ("XDG_RUNTIME_DIR");
		if (runtime)
			ret = setup_pam_env (ph, "XDG_RUNTIME_DIR", runtime);
	}

	/* Make sure that worked */
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't setup environment: %s", 
 		        pam_strerror (ph, ret));
 		exit (EXIT_FAILURE);
	}
	
	/* Now actually execute the process */
	execve (args[0], args, pam_getenvlist (ph));
	syslog (GKR_LOG_ERR, "gkr-pam: couldn't run gnome-keyring-daemon: %s", 
	        strerror (errno));
	exit (EXIT_FAILURE);
}


static int 
log_problem (char *line, void *arg)
{
	int *failed;

	/* 
	 * Called for each stderr output line from the daemon.
	 * Send it all to the log. 
	 */
		
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
	int ret;
	
	/* 
	 * Called for each stdout output line from the daemon
	 * presumably environment variables.
	 */
	
	assert (line);
	assert (arg);
	
	/* Make sure it is in fact an environment variable */
	if (!strchr (line, '='))
		return PAM_SUCCESS;
			
	line = strbtrim (line);
	ret = pam_putenv (ph, line);

	return ret;
}

static int
start_daemon (pam_handle_t *ph,
              struct passwd *pwd,
              bool is_user_login,
              const char *password)
{
	struct sigaction defsact, oldsact, ignpipe, oldpipe;
	int inp[2] = { -1, -1 };
	int outp[2] = { -1, -1 };
	int errp[2] = { -1, -1 };
	int ret = PAM_SERVICE_ERR;
	pid_t pid;
	char *output = NULL;
	char *outerr = NULL;
	int failed, status;
	
	assert (pwd);

	/* 
	 * Make sure that SIGCHLD occurs. Otherwise our waitpid below
	 * doesn't work properly. We need to wait on the process to 
	 * get the daemon exit status.
	 */
	memset (&defsact, 0, sizeof (defsact));
	memset (&oldsact, 0, sizeof (oldsact));
	defsact.sa_handler = SIG_DFL;
	sigaction (SIGCHLD, &defsact, &oldsact);
	
	/*
	 * Make sure we don't exit with a SIGPIPE while doing this, that 
	 * would be very annoying to a user trying to log in.
	 */	
	memset (&ignpipe, 0, sizeof (ignpipe));
	memset (&oldpipe, 0, sizeof (oldpipe));
	ignpipe.sa_handler = SIG_IGN;
	sigaction (SIGPIPE, &ignpipe, &oldpipe);
	
	/* Create the necessary pipes */
	if (pipe (inp) < 0 || pipe (outp) < 0 || pipe (errp) < 0) {
	    	syslog (GKR_LOG_ERR, "gkr-pam: couldn't create pipes: %s", 
	    	        strerror (errno));
	    	goto done;
	}

	/* Start up daemon child process */
	switch (pid = fork ()) {
	case -1:
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't fork: %s", 
		        strerror (errno));
		goto done;
		
	/* This is the child */
	case 0:
		setup_child (inp, outp, errp, ph, pwd,
		             is_user_login ? "--login" : NULL);
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
	 * We always pass in a --login argument, even when we have a NULL password
	 * since this controls the startup behavior. When using --login daemon waits
	 * for a password. Closing input signifies password is done.
	 */

	if (password)
		write_string (inp[WRITE_END], password);
	close (inp[WRITE_END]);

	/* 
	 * Note that we're not using select() or any such. We know how the 
	 * daemon sends its data.
	 */

	/* Read any stdout and stderr data */
	output = read_string (outp[READ_END]);
	outerr = read_string (errp[READ_END]);
	if (!output || !outerr) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't read data from gnome-keyring-daemon: %s", 
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
		syslog (GKR_LOG_ERR, "gkr-pam: gnome-keyring-daemon didn't start properly");
		goto done;
	}
		
	ret = foreach_line (output, setup_environment, ph);
	if (password)
		syslog (GKR_LOG_INFO, "gkr-pam: gnome-keyring-daemon started properly and unlocked keyring");
	else
		syslog (GKR_LOG_INFO, "gkr-pam: gnome-keyring-daemon started properly");

done:
	/* Restore old handler */
	sigaction (SIGCHLD, &oldsact, NULL);
	sigaction (SIGPIPE, &oldpipe, NULL);
	
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

/* control must be at least MAX_CONTROL_SIZE */
static int
get_control_file (pam_handle_t *ph, char *control)
{
	const char *control_root;
	const char *suffix;

	control_root = get_any_env (ph, ENV_CONTROL);
	if (control_root == NULL) {
		control_root = get_any_env (ph, "XDG_RUNTIME_DIR");
		if (control_root == NULL)
			return GKD_CONTROL_RESULT_NO_DAEMON;
		suffix = "/keyring/control";
	} else {
		suffix = "/control";
	}

	if (strlen (control_root) + strlen (suffix) + 1 > MAX_CONTROL_SIZE) {
		syslog (GKR_LOG_ERR, "gkr-pam: address is too long for unix socket path: %s/%s",
			control, suffix);
		return GKD_CONTROL_RESULT_FAILED;
	}

	strcpy (control, control_root);
	strcat (control, suffix);

	return GKD_CONTROL_RESULT_OK;
}

static int
stop_daemon (pam_handle_t *ph,
             struct passwd *pwd)
{
	char control[MAX_CONTROL_SIZE];
	int res;

	assert (pwd);

	res = get_control_file(ph, control);
	if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: unable to locate daemon control file");
		return PAM_SERVICE_ERR;
	}

	res = gkr_pam_client_run_operation (pwd, control, GKD_CONTROL_OP_QUIT, 0, NULL);

	/* Daemon had already gone away */
	if (res == GKD_CONTROL_RESULT_NO_DAEMON) {
		return PAM_SUCCESS;

	} else if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't stop the daemon");
		return PAM_SERVICE_ERR;
	}

	syslog (GKR_LOG_NOTICE, "gkr-pam: stopped the daemon");
	return PAM_SUCCESS;
}

static int
unlock_keyring (pam_handle_t *ph,
                struct passwd *pwd,
                const char *password,
                int *need_daemon)
{
	char control[MAX_CONTROL_SIZE];
	int res;
	const char *argv[2];
	
	assert (pwd);

	res = get_control_file(ph, control);
	if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: unable to locate daemon control file");
		if (res == GKD_CONTROL_RESULT_NO_DAEMON && need_daemon)
			*need_daemon = 1;
		return PAM_SERVICE_ERR;
	}

	argv[0] = password;

	res = gkr_pam_client_run_operation (pwd, control, GKD_CONTROL_OP_UNLOCK,
					    (argv[0] == NULL) ? 0 : 1, argv);
	/* An error unlocking */
	if (res == GKD_CONTROL_RESULT_NO_DAEMON) {
		if (need_daemon)
			*need_daemon = 1;
		return PAM_SERVICE_ERR;
	} else if (res == GKD_CONTROL_RESULT_DENIED) {
		syslog (GKR_LOG_ERR, "gkr-pam: the password for the login keyring was invalid.");
		return PAM_SERVICE_ERR;
	} else if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't unlock the login keyring.");
		return PAM_SERVICE_ERR;
	}

	syslog (GKR_LOG_INFO, "gkr-pam: unlocked login keyring");
	return PAM_SUCCESS;
}

static int
change_keyring_password (pam_handle_t *ph,
                         struct passwd *pwd,
                         const char *password,
                         const char *original,
                         int *need_daemon)
{
	char control[MAX_CONTROL_SIZE];
	const char *argv[3];
	int res;

	assert (pwd);
	assert (password);
	assert (original);

	res = get_control_file(ph, control);
	if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: unable to locate daemon control file");
		return PAM_SERVICE_ERR;
	}

	argv[0] = original;
	argv[1] = password;
	
	res = gkr_pam_client_run_operation (pwd, control, GKD_CONTROL_OP_CHANGE, 2, argv);

	if (res == GKD_CONTROL_RESULT_NO_DAEMON) {
		if (need_daemon)
			*need_daemon = 1;
		return PAM_SERVICE_ERR;
	/* No keyring, not an error. Will be created at initial authenticate. */
	} else if (res == GKD_CONTROL_RESULT_DENIED) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't change password for the login keyring: the passwords didn't match.");
		return PAM_SERVICE_ERR;
	} else if (res != GKD_CONTROL_RESULT_OK) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't change password for the login keyring.");
		return PAM_SERVICE_ERR;
	}

	syslog (GKR_LOG_NOTICE, "gkr-pam: changed password for login keyring");
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
	msg.msg = gkr_pam_gettext ("Password: ");
	msgs[0] = &msg;
	
	/* Call away */
	conv = (const struct pam_conv*)item;
	ret = (conv->conv) (1, msgs, &resp, conv->appdata_ptr);
	if (ret != PAM_SUCCESS)
		return ret;
	
	password = resp[0].resp;
	free (resp);
	
	if (password == NULL) 
		return PAM_CONV_ERR;
		
	/* Store it away for later use */
	ret = pam_set_item (ph, PAM_AUTHTOK, password);
	free_password (password);

	if (ret == PAM_SUCCESS)
		ret = pam_get_item (ph, PAM_AUTHTOK, &item); 

	return ret;
}

static uint 
parse_args (pam_handle_t *ph, int argc, const char **argv)
{
	uint args = 0;
	const void *svc;
	int only_if_len;
	int i;

	svc = NULL;
	if (pam_get_item (ph, PAM_SERVICE, &svc) != PAM_SUCCESS)
		svc = NULL;

	only_if_len = strlen ("only_if=");

	/* Parse the arguments */
	for (i = 0; i < argc; i++) {
		if (strcmp (argv[i], "auto_start") == 0) {
			args |= ARG_AUTO_START;

		} else if (strncmp (argv[i], "only_if=", only_if_len) == 0) {
			const char *value = argv[i] + only_if_len;
			if (!evaluate_inlist (svc, value))
				args |= ARG_IGNORE_SERVICE;

		} else if (strcmp (argv[i], "use_authtok") == 0) {
			args |= ARG_USE_AUTHTOK;

		} else {
			syslog (GKR_LOG_WARN, "gkr-pam: invalid option: %s",
				argv[i]);
		}
	}
	
	return args;
}

static int
stash_password_for_session (pam_handle_t *ph,
                            const char *password)
{
	if (pam_set_data (ph, "gkr_system_authtok", strdup (password),
	                  cleanup_free_password) != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: error stashing password for session");
		return PAM_AUTHTOK_RECOVER_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *ph, int unused, int argc, const char **argv)
{
	struct passwd *pwd;
	const char *user, *password;
	int need_daemon = 0;
	uint args;
	int ret;
	
	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;
		
	/* Figure out and/or prompt for the user name */
	ret = pam_get_user (ph, &user, NULL);
	if (ret != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the user name: %s", 
		        pam_strerror (ph, ret));
		return PAM_SERVICE_ERR;
	}
	
	pwd = getpwnam (user);
	if (!pwd) {
		syslog (GKR_LOG_ERR, "gkr-pam: error looking up user information");
		return PAM_SERVICE_ERR;
	}
		
	/* Look up the password */
	ret = pam_get_item (ph, PAM_AUTHTOK, (const void**)&password);
	if (ret != PAM_SUCCESS || password == NULL) {
		if (ret == PAM_SUCCESS)
			syslog (GKR_LOG_WARN, "gkr-pam: no password is available for user");
		else
			syslog (GKR_LOG_WARN, "gkr-pam: no password is available for user: %s", 
			        pam_strerror (ph, ret));
		return PAM_SUCCESS;
	}

	ret = unlock_keyring (ph, pwd, password, &need_daemon);
	if (ret != PAM_SUCCESS && need_daemon) {
		if (args & ARG_AUTO_START) {
			/* We pass password to the daemon when starting, thus it will immediately unlock keyring */
			ret = start_daemon (ph, pwd, true, password);
		} else {
			ret = stash_password_for_session (ph, password);
			syslog (GKR_LOG_INFO, "gkr-pam: stashed password to try later in open session");
		}
	}

	return ret;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *user = NULL, *password = NULL;
	struct passwd *pwd;
	int ret;
	uint args;
	int need_daemon = 0;

	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;

	/* Figure out the user name */
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

	/* Get the stored authtok here */
	if (pam_get_data (ph, "gkr_system_authtok", (const void**)&password) != PAM_SUCCESS) {
		/* 
		 * No password, no worries, maybe this (PAM using) application 
		 * didn't do authentication, or is hopeless and wants to call 
		 * different PAM callbacks from different processes.
		 * 
		 * No use complaining
		 */
		password = NULL;
	}
	
	if (args & ARG_AUTO_START || password) {
		ret = unlock_keyring (ph, pwd, password, &need_daemon);
		if (ret != PAM_SUCCESS && need_daemon && (args & ARG_AUTO_START))
			ret = start_daemon (ph, pwd, true, password);
	}

	/* Destroy the stored authtok once it has been used */
	if (password && pam_set_data (ph, "gkr_system_authtok", NULL, NULL) != PAM_SUCCESS) {
		syslog (GKR_LOG_ERR, "gkr-pam: error destroying the password");
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * ph, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;	
}

static int
pam_chauthtok_preliminary (pam_handle_t *ph, struct passwd *pwd)
{
	/* 
	 * If a super-user is changing a user's password then pam_unix.so
	 * doesn't prompt for the user's current password, which means we 
	 * won't have access to that password to change the keyring password.
	 * 
	 * So we could prompt for the current user's password except that 
	 * most software is broken in this regard, and doesn't use the 
	 * prompts properly. 
	 * 
	 * In addition how would we verify the user's password? We could 
	 * verify it against the Gnome Keyring, but if it is mismatched
	 * from teh UNIX password then that would be super confusing.
	 * 
	 * So we opt, just to send NULL along with the change password 
	 * request and have the user type in their current GNOME Keyring
	 * password at an explanatory prompt.
	 */

	return PAM_IGNORE;
}

static int
pam_chauthtok_update (pam_handle_t *ph, struct passwd *pwd, uint args)
{
	const char *password, *original;
	int need_daemon = 0;
	int ret;

	ret = pam_get_item (ph, PAM_AUTHTOK, (const void**)&password);
	if (ret != PAM_SUCCESS)
		password = NULL;

	ret = pam_get_item (ph, PAM_OLDAUTHTOK, (const void**)&original);
	if (ret != PAM_SUCCESS || original == NULL) {
		syslog (GKR_LOG_WARN, "gkr-pam: couldn't update the login keyring password: %s",
		        "no old password was entered");
		if (password)
			stash_password_for_session (ph, password);
		return PAM_IGNORE;
	}
		
	if (password == NULL) {
		/* No password was set, and we can't prompt for it */
		if (args & ARG_USE_AUTHTOK) {
			syslog (GKR_LOG_ERR, "gkr-pam: no password set, and use_authtok was specified");
			return PAM_AUTHTOK_RECOVER_ERR;
		}

		/* No password was entered, prompt for it */
		ret = prompt_password (ph);
		if (ret != PAM_SUCCESS) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
			        pam_strerror (ph, ret));
			return PAM_AUTH_ERR;
		}
		ret = pam_get_item (ph, PAM_AUTHTOK, (const void**)&password);
		if (ret != PAM_SUCCESS || password == NULL) {
			syslog (GKR_LOG_ERR, "gkr-pam: couldn't get the password from user: %s", 
			        ret == PAM_SUCCESS ? "password was null" : pam_strerror (ph, ret));
			return PAM_AUTHTOK_RECOVER_ERR;
		}
	}

	ret = change_keyring_password (ph, pwd, password, original, &need_daemon);
	if (ret != PAM_SUCCESS && need_daemon) {

		/*
		 * We always start the daemon here, and don't respect the auto_start
		 * argument. Because if the password is being changed, then making
		 * the 'login' keyring match it is a priority.
		 *
		 * Note that we don't pass in an unlock password, that happens below.
		 */
		ret = start_daemon (ph, pwd, false, NULL);
		if (ret == PAM_SUCCESS) {
			ret = change_keyring_password (ph, pwd, password, original, NULL);

			/* if not auto_start, kill the daemon if we started it: we don't want
			 * it to stay */
			if (!(args & ARG_AUTO_START))
				stop_daemon (ph, pwd);
		}
	}

	/*
	 * Likely the daemon is being started later in the session if we weren't
	 * allowed to autostart it here. Store the password for our session handler
	 */
	if (!(args & ARG_AUTO_START))
		stash_password_for_session (ph, password);

	return ret;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	/* Nothing to do, but we have to have this function exported */
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *user;
	struct passwd *pwd;
	uint args;
	int ret;
	
	args = parse_args (ph, argc, argv);

	if (args & ARG_IGNORE_SERVICE)
		return PAM_SUCCESS;

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

	if (flags & PAM_PRELIM_CHECK) 
		return pam_chauthtok_preliminary (ph, pwd);
	else if (flags & PAM_UPDATE_AUTHTOK)
		return pam_chauthtok_update (ph, pwd, args);
	else 
		return PAM_IGNORE;
}
