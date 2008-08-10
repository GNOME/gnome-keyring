#ifndef GKRTOOL_H_
#define GKRTOOL_H_

#include <glib.h>

/* -------------------------------------------------------------------------------
 * GENERAL HELPERS
 */

extern gboolean gkr_tool_mode_quiet;

#define GKR_TOOL_BASIC_OPTIONS \
	{ "quiet", 'q', 0, G_OPTION_ARG_NONE, &gkr_tool_mode_quiet, "Don't print unnecessary output", NULL }, 

void gkr_tool_handle_error (GError **error, const gchar *message, ...);

int gkr_tool_parse_options (int *argc, char** argv[], GOptionEntry *options);

/* -------------------------------------------------------------------------------
 * VARIOUS COMMAND HANDLERS 
 */
int gkr_tool_import (int argc, char *argv[]);

#endif /* GKRTOOL_H_ */
