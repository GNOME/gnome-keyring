
#include "config.h"

#include "gkr-ask-daemon.h"
#include "gkr-ask-request.h"

#include <glib.h>

static GkrAskRequest* current_ask = NULL;
static GList *outstanding_asks = NULL;

static gchar *the_display = NULL;

static void prompt_next (void);

void
gkr_ask_daemon_init (void)
{
	const gchar* display;
	
	display = g_getenv ("DISPLAY");
	if (display && display[0])
		gkr_ask_daemon_set_display (display);
}

void 
gkr_ask_daemon_cleanup (void)
{
	GkrAskRequest *ask;
	if (current_ask)
		gkr_ask_daemon_cancel (current_ask);
	
	while (outstanding_asks) {
		ask = GKR_ASK_REQUEST (outstanding_asks->data);
		gkr_ask_daemon_cancel (ask);
	}
	
	g_free (the_display);
	the_display = NULL;
}

static void 
completed_ask (GkrAskRequest *ask, gpointer unused)
{
	/* current_ask will be null if cancelled */
	g_assert (current_ask == NULL || ask == current_ask);
	
	current_ask = NULL;
	g_object_unref (ask);
	
	prompt_next ();
}

static void 
prompt_next (void)
{
	while (outstanding_asks) {
		
		g_assert (!current_ask);
		current_ask = GKR_ASK_REQUEST (outstanding_asks->data);
		
		outstanding_asks = g_list_remove (outstanding_asks, current_ask);
		g_signal_connect (current_ask, "completed", G_CALLBACK (completed_ask), NULL);
		
		/* This can immediately call the completed handler */
		if (!gkr_ask_request_check (current_ask)) {
			
			/* Needs to be prompted for */
			g_assert (current_ask);
			gkr_ask_request_prompt (current_ask);
			return;
		}
	}
}

void
gkr_ask_daemon_queue (GkrAskRequest* ask)
{
	g_assert (GKR_IS_ASK_REQUEST (ask));
	g_assert (!gkr_ask_request_is_complete (ask));
	
	/* See if it'll complete without a prompt */
	if (gkr_ask_request_check (ask))
		return;
	
	/* Put it in the queue and prompt */
	outstanding_asks = g_list_append (outstanding_asks, ask);
	g_object_ref (ask);
	
	if (!current_ask)
		prompt_next ();
}

void
gkr_ask_daemon_cancel (GkrAskRequest* ask)
{
	if (gkr_ask_request_is_complete (ask))
		return;
	
	/* Keep a reference during this function */
	g_object_ref (ask);
	
	if (ask == current_ask) {
		g_object_unref (ask);
		current_ask = NULL;
	}
	
	if (g_list_find (outstanding_asks, ask)) {
		g_object_unref (ask);
		outstanding_asks = g_list_remove (outstanding_asks, ask);
	}
	
	gkr_ask_request_cancel (ask);
	
	/* Function reference */
	g_object_unref (ask);
}

void 
gkr_ask_daemon_set_display (const gchar* display)
{
	g_free (the_display);
	the_display = g_strdup (display);
}

const gchar*
gkr_ask_daemon_get_display (void)
{
	return the_display;
}
