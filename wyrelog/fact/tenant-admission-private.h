/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <gio/gio.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct _WylFactTenantAdmissionManager WylFactTenantAdmissionManager;
typedef struct _WylFactTenantAdmissionLease WylFactTenantAdmissionLease;

typedef enum
{
  WYL_FACT_TENANT_ADMISSION_OPEN = 0,
  WYL_FACT_TENANT_ADMISSION_CLOSING,
  WYL_FACT_TENANT_ADMISSION_CLOSED,
} WylFactTenantAdmissionState;

wyrelog_error_t wyl_fact_tenant_admission_manager_new
  (WylFactTenantAdmissionManager **out_manager);
WylFactTenantAdmissionManager *wyl_fact_tenant_admission_manager_ref
  (WylFactTenantAdmissionManager *manager);
void wyl_fact_tenant_admission_manager_unref
  (WylFactTenantAdmissionManager *manager);
wyrelog_error_t wyl_fact_tenant_admission_manager_shutdown
  (WylFactTenantAdmissionManager *manager);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactTenantAdmissionManager,
    wyl_fact_tenant_admission_manager_unref)

wyrelog_error_t wyl_fact_tenant_admission_acquire_read
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    GCancellable *cancellable, WylFactTenantAdmissionLease **out_lease);
wyrelog_error_t wyl_fact_tenant_admission_acquire_write
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    GCancellable *cancellable, WylFactTenantAdmissionLease **out_lease);
wyrelog_error_t wyl_fact_tenant_admission_lease_validate
  (WylFactTenantAdmissionLease *lease, const gchar *tenant_id);
wyrelog_error_t wyl_fact_tenant_admission_lease_release
  (WylFactTenantAdmissionLease *lease);
static inline void
wyl_fact_tenant_admission_lease_cleanup (WylFactTenantAdmissionLease *lease)
{
  (void) wyl_fact_tenant_admission_lease_release (lease);
}

wyrelog_error_t wyl_fact_tenant_admission_close
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id);
wyrelog_error_t wyl_fact_tenant_admission_open
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id);
wyrelog_error_t wyl_fact_tenant_admission_get_state
  (WylFactTenantAdmissionManager *manager, const gchar *tenant_id,
    WylFactTenantAdmissionState *out_state, guint *out_readers,
    guint *out_waiters);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactTenantAdmissionLease,
    wyl_fact_tenant_admission_lease_cleanup)

G_END_DECLS;
