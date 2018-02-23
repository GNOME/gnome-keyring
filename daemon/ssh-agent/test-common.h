/*
 * gnome-keyring
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daiki Ueno
 */

#include <glib.h>
#include "egg/egg-buffer.h"

void prepare_request_identities (EggBuffer *req);
void prepare_add_identity (EggBuffer *req);
void prepare_remove_identity (EggBuffer *req);
void prepare_remove_all_identities (EggBuffer *req);
void prepare_sign_request (EggBuffer *req);

void check_identities_answer (EggBuffer *resp, gsize count);
void check_sign_response (EggBuffer *resp);
void check_response (EggBuffer *resp, unsigned char expected);
void check_success (EggBuffer *resp);
void check_failure (EggBuffer *resp);

GBytes *public_key_from_file (const gchar *path, gchar **comment);

#define DEFINE_CALL_FUNCS(Test, Call)			\
static inline void					\
call_request_identities (Test *test, gsize count)	\
{							\
	egg_buffer_reset (&test->req);			\
	egg_buffer_reset (&test->resp);			\
							\
	prepare_request_identities (&test->req);	\
	Call (test);					\
	check_identities_answer (&test->resp, count);	\
}							\
							\
static inline void					\
call_add_identity (Test *test)				\
{							\
	egg_buffer_reset (&test->req);			\
	egg_buffer_reset (&test->resp);			\
							\
	prepare_add_identity (&test->req);		\
	Call (test);					\
	check_success (&test->resp);			\
}							\
							\
static inline void					\
call_remove_identity (Test *test)			\
{							\
	egg_buffer_reset (&test->req);			\
	egg_buffer_reset (&test->resp);			\
							\
	prepare_remove_identity (&test->req);		\
	Call (test);					\
	check_success (&test->resp);			\
}							\
							\
static inline void					\
call_remove_all_identities (Test *test)			\
{							\
	egg_buffer_reset (&test->req);			\
	egg_buffer_reset (&test->resp);			\
							\
	prepare_remove_all_identities (&test->req);	\
	Call (test);					\
	check_success (&test->resp);			\
}							\
							\
static inline void					\
call_sign (Test *test)					\
{							\
	egg_buffer_reset (&test->req);			\
	egg_buffer_reset (&test->resp);			\
							\
	prepare_sign_request (&test->req);		\
	Call (test);					\
	check_sign_response (&test->resp);		\
}
