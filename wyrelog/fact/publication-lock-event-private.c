/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/publication-lock-event-private.h"

#if defined(WYL_TEST_HANDLE_SEAMS)
static WylFactPublicationLockEventFunc event_hook;
static gpointer event_hook_data;
static volatile gint event_sequence;

void
wyl_fact_publication_lock_event_set_hook
  (WylFactPublicationLockEventFunc hook, gpointer user_data)
{
  event_hook = hook;
  event_hook_data = user_data;
}

void
wyl_fact_publication_lock_event_emit
  (WylFactPublicationLockDomain domain, WylFactPublicationLockPhase phase,
    gpointer subject)
{
  if (event_hook == NULL)
    return;
  WylFactPublicationLockEvent event = {
    .sequence = (guint64) (g_atomic_int_add (&event_sequence, 1) + 1),
    .domain = domain,
    .phase = phase,
    .subject = subject,
    .thread = g_thread_self (),
  };
  event_hook (&event, event_hook_data);
}
#endif
