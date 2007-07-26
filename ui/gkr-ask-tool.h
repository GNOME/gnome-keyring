#ifndef GKRASKTOOL_H_
#define GKRASKTOOL_H_

#include <gtk/gtk.h>

GtkWidget*      gkr_ask_tool_create_location   (GKeyFile *input_data);

const gchar*    gkr_ask_tool_get_location      (GtkWidget *widget);

#endif /*GKRASKTOOL_H_*/
