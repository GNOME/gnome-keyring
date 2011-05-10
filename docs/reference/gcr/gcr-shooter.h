
#include <gtk/gtk.h>

typedef enum {
	GCR_SHOOTER_SMALL,
	GCR_SHOOTER_MEDIUM,
	GCR_SHOOTER_LARGE,
	GCR_SHOOTER_ASIS
} GcrShooterSize;

typedef struct GcrShooterInfo {
	GtkWidget *window;
	gchar *name;
	gboolean no_focus;
	gboolean include_decorations;
	GcrShooterSize size;
} GcrShooterInfo;

GcrShooterInfo*   gcr_widgets_create        (const gchar *name);

GcrShooterInfo*   gcr_shooter_info_new      (const gchar *name,
                                             GtkWidget *widget,
                                             GcrShooterSize size);
