/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
  WYL_FACT_PUBLICATION_LOCK_HANDLE_COORDINATOR = 0,
  WYL_FACT_PUBLICATION_LOCK_ARTIFACT_LEASE,
  WYL_FACT_PUBLICATION_LOCK_RUNTIME_WRITER,
  WYL_FACT_PUBLICATION_LOCK_RUNTIME_STATE,
  WYL_FACT_PUBLICATION_LOCK_POLICY_FENCE,
} WylFactPublicationLockDomain;

typedef enum
{
  WYL_FACT_PUBLICATION_LOCK_ACQUIRED = 0,
  WYL_FACT_PUBLICATION_LOCK_RELEASE_BEGIN,
  WYL_FACT_PUBLICATION_LOCK_RELEASED,
} WylFactPublicationLockPhase;

#if defined(WYL_TEST_HANDLE_SEAMS)
typedef struct
{
  guint64 sequence;
  WylFactPublicationLockDomain domain;
  WylFactPublicationLockPhase phase;
  gpointer subject;
  GThread *thread;
} WylFactPublicationLockEvent;

typedef void (*WylFactPublicationLockEventFunc)
  (const WylFactPublicationLockEvent *event, gpointer user_data);

void wyl_fact_publication_lock_event_set_hook
  (WylFactPublicationLockEventFunc hook, gpointer user_data);
void wyl_fact_publication_lock_event_emit
  (WylFactPublicationLockDomain domain, WylFactPublicationLockPhase phase,
    gpointer subject);
#else
static inline void
wyl_fact_publication_lock_event_emit
  (WylFactPublicationLockDomain domain, WylFactPublicationLockPhase phase,
    gpointer subject)
{
  (void) domain;
  (void) phase;
  (void) subject;
}
#endif

G_END_DECLS
