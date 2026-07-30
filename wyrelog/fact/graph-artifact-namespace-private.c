/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#endif
#include "fact/graph-artifact-namespace-private.h"
#include "wyl-id-private.h"
#include <string.h>

#ifdef G_OS_WIN32
struct WylFactArtifactNamespace
{
  gint unused;
};
struct WylFactArtifactMutationLease
{
  gint unused;
};
struct WylFactArtifactSidecarBinding
{
  gint unused;
};
struct WylFactArtifactMainBinding
{
  gint unused;
};
struct WylFactArtifactReaderMainBinding
{
  gint unused;
};
struct WylFactArtifactReaderWalBinding
{
  gint unused;
};
struct WylFactDuckdbTempChildBinding
{
  gint unused;
};
static wyrelog_error_t
closed (void)
{
  return WYRELOG_E_POLICY;
}

void wyl_fact_artifact_namespace_set_test_fault
    (WylFactArtifactNamespaceTestFault fault)
{
  (void) fault;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open (const WylFactGraphDirectory *d,
    const WylFactGraphRegularFile *main_file, WylFactArtifactNamespace **o)
{
  (void) d;
  (void) main_file;
  if (o)
    *o = NULL;
  return closed ();
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *n)
{
  (void) n;
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_reader_guard (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **o)
{
  (void) n;
  if (o)
    *o = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_mutation_lease (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **o)
{
  (void) n;
  if (o)
    *o = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_revalidate (WylFactArtifactMutationLease *l)
{
  (void) l;
  return closed ();
}

void
wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *l)
{
  (void) l;
}

wyrelog_error_t
wyl_fact_artifact_reader_guard_open_main_binding (WylFactArtifactMutationLease
    *l, WylFactArtifactReaderMainBinding **b, gint *fd)
{
  (void) l;
  if (b)
    *b = NULL;
  if (fd)
    *fd = -1;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_reader_main_binding_revalidate
    (WylFactArtifactReaderMainBinding * b) {
  (void) b;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_reader_main_binding_revalidate_fd
    (WylFactArtifactReaderMainBinding * b, gint fd) {
  (void) b;
  (void) fd;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_reader_main_binding_close (WylFactArtifactReaderMainBinding
    *b, gint *fd)
{
  (void) b;
  (void) fd;
  return closed ();
}

void
wyl_fact_artifact_reader_main_binding_free (WylFactArtifactReaderMainBinding *b)
{
  (void) b;
}

wyrelog_error_t
    wyl_fact_artifact_reader_guard_open_existing_wal_binding
    (WylFactArtifactMutationLease * l, WylFactArtifactReaderWalBinding ** b,
    gint * fd) {
  (void) l;
  if (b)
    *b = NULL;
  if (fd)
    *fd = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_reader_wal_binding_revalidate (WylFactArtifactReaderWalBinding
    *b)
{
  (void) b;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_reader_wal_binding_revalidate_fd
    (WylFactArtifactReaderWalBinding * b, gint fd) {
  (void) b;
  (void) fd;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_reader_wal_binding_close (WylFactArtifactReaderWalBinding *b,
    gint *fd)
{
  (void) b;
  (void) fd;
  return closed ();
}

void
wyl_fact_artifact_reader_wal_binding_free (WylFactArtifactReaderWalBinding *b)
{
  (void) b;
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_main_binding
    (WylFactArtifactMutationLease * l, WylFactArtifactMainBinding ** b,
    gint * fd) {
  (void) l;
  if (b)
    *b = NULL;
  if (fd)
    *fd = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_main_binding_revalidate (WylFactArtifactMainBinding *b)
{
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_main_binding_revalidate_fd (WylFactArtifactMainBinding *b,
    gint fd)
{
  (void) fd;
  if (!b)
    return closed ();
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_main_binding_close (WylFactArtifactMainBinding *b, gint *fd)
{
  (void) b;
  (void) fd;
  return closed ();
}

void
wyl_fact_artifact_main_binding_free (WylFactArtifactMainBinding *b)
{
  (void) b;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_file (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, gboolean c, gboolean w, gint *o)
{
  (void) l;
  (void) a;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp (WylFactArtifactMutationLease *l,
    const gchar *t, gboolean c, gboolean w, gint *o)
{
  (void) l;
  (void) t;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_sidecar_binding
    (WylFactArtifactMutationLease * l, WylFactArtifactName a, gboolean c,
    gboolean w, WylFactArtifactSidecarBinding ** b, gint * o) {
  (void) l;
  (void) a;
  (void) c;
  (void) w;
  if (b)
    *b = NULL;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
    (WylFactArtifactMutationLease * l, WylFactArtifactName a, gboolean w,
    WylFactArtifactSidecarBinding ** b, gint * o) {
  (void) l;
  (void) a;
  (void) w;
  if (b)
    *b = NULL;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_revalidate (WylFactArtifactSidecarBinding *b)
{
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_revalidate_fd (WylFactArtifactSidecarBinding
    *b, gint fd)
{
  (void) b;
  (void) fd;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_close (WylFactArtifactSidecarBinding *b,
    gint *fd)
{
  (void) b;
  (void) fd;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_sidecar_binding_publish_no_replace
    (WylFactArtifactSidecarBinding * b, WylFactArtifactName a) {
  (void) b;
  (void) a;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_sidecar_binding_replace_existing_wal
    (WylFactArtifactSidecarBinding * source,
    WylFactArtifactSidecarBinding * destination,
    WylFactArtifactSidecarReplaceResult * out_result) {
  (void) source;
  (void) destination;
  if (out_result)
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_retire (WylFactArtifactSidecarBinding *b,
    WylFactArtifactSidecarRetireResult *out_result)
{
  (void) b;
  if (out_result)
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  return closed ();
}

void
wyl_fact_artifact_sidecar_binding_free (WylFactArtifactSidecarBinding *b)
{
  (void) b;
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_replace_sidecar (WylFactArtifactTempBinding *t,
    WylFactArtifactSidecarBinding *b)
{
  (void) t;
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp_binding (WylFactArtifactMutationLease
    *l, const gchar *t, gboolean c, gboolean w, WylFactArtifactTempBinding **b,
    gint *o)
{
  (void) l;
  (void) t;
  (void) c;
  (void) w;
  if (b)
    *b = NULL;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_open (WylFactArtifactTempBinding *b,
    gboolean w, gint *o)
{
  (void) b;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_unlink (WylFactArtifactTempBinding *b)
{
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_rename (WylFactArtifactTempBinding *b,
    const gchar *t)
{
  (void) b;
  (void) t;
  return closed ();
}

wyrelog_error_t
    wyl_fact_artifact_temp_binding_export_recovery_evidence
    (WylFactArtifactTempBinding * b, WylFactArtifactTempRecoveryEvidence ** e) {
  (void) b;
  if (e)
    *e = NULL;
  return closed ();
}

void wyl_fact_artifact_temp_recovery_evidence_free
    (WylFactArtifactTempRecoveryEvidence * e)
{
  (void) e;
}

wyrelog_error_t
wyl_fact_artifact_temp_recovery_evidence_encode (const
    WylFactArtifactTempRecoveryEvidence *e, GBytes **b)
{
  (void) e;
  if (b)
    *b = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_temp_recovery_evidence_decode (GBytes *b,
    WylFactArtifactTempRecoveryEvidence **e)
{
  (void) b;
  if (e)
    *e = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_recover_temp (WylFactArtifactMutationLease *l,
    const WylFactArtifactTempRecoveryEvidence *e)
{
  (void) l;
  (void) e;
  return closed ();
}

void
wyl_fact_artifact_temp_binding_free (WylFactArtifactTempBinding *b)
{
  (void) b;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_unlink (WylFactArtifactMutationLease *l,
    WylFactArtifactName a)
{
  (void) l;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_rename (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, WylFactArtifactName b)
{
  (void) l;
  (void) a;
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean c, gboolean w, gint *o)
{
  (void) n;
  (void) a;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_unlink (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  (void) a;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_lock (WylFactArtifactNamespace *n, gboolean e,
    gint *o)
{
  (void) n;
  (void) e;
  if (o)
    *o = -1;
  return !n || !o ? WYRELOG_E_INVALID : closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_temp (WylFactArtifactNamespace *n,
    const gchar *t, gboolean c, gboolean w, gint *o)
{
  (void) n;
  (void) t;
  (void) c;
  (void) w;
  if (o)
    *o = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_rename (WylFactArtifactNamespace *n,
    WylFactArtifactName a, WylFactArtifactName b)
{
  (void) n;
  (void) a;
  (void) b;
  return closed ();
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync_directory (WylFactArtifactNamespace *n)
{
  (void) n;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create (WylFactArtifactMutationLease *l,
    WylFactDuckdbTempRoot **out_root)
{
  (void) l;
  if (out_root)
    *out_root = NULL;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyl_fact_duckdb_temp_root_create_with_orphan_evidence
    (WylFactArtifactMutationLease * l, WylFactDuckdbTempRoot ** out_root,
    WylFactDuckdbTempOrphanEvidence ** out_evidence) {
  (void) l;
  if (out_root)
    *out_root = NULL;
  if (out_evidence)
    *out_evidence = NULL;
  if (!out_root || !out_evidence)
    return WYRELOG_E_INVALID;
  return closed ();
}

void
wyl_fact_duckdb_temp_orphan_evidence_free (WylFactDuckdbTempOrphanEvidence *e)
{
  (void) e;
}

gchar *wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name
    (const WylFactDuckdbTempOrphanEvidence * e)
{
  (void) e;
  return NULL;
}

void
wyl_fact_duckdb_temp_root_free (WylFactDuckdbTempRoot *root)
{
  (void) root;
}

gchar *
wyl_fact_duckdb_temp_root_dup_logical_name (WylFactDuckdbTempRoot *root)
{
  (void) root;
  return NULL;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_child_exists (WylFactDuckdbTempRoot *root,
    const gchar *name, gboolean *out_exists)
{
  (void) root;
  (void) name;
  if (out_exists)
    *out_exists = FALSE;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_foreach_child (WylFactDuckdbTempRoot *root,
    WylFactDuckdbTempChildVisitor visitor, gpointer data)
{
  (void) root;
  (void) visitor;
  (void) data;
  return closed ();
}

gchar *
wyl_fact_duckdb_temp_child_dup_logical_name (WylFactDuckdbTempChild *child)
{
  (void) child;
  return NULL;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create_child (WylFactDuckdbTempRoot *root,
    const gchar *name, WylFactDuckdbTempChild **out_child, gint *out_fd)
{
  (void) root;
  (void) name;
  if (out_child)
    *out_child = NULL;
  if (out_fd)
    *out_fd = -1;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
    (WylFactDuckdbTempRoot * root, const gchar * name,
    WylFactDuckdbTempChild ** out_child, gint * out_fd,
    WylFactDuckdbTempOrphanEvidence ** out_evidence)
{
  (void) root;
  (void) name;
  if (out_child)
    *out_child = NULL;
  if (out_fd)
    *out_fd = -1;
  if (out_evidence)
    *out_evidence = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_open (WylFactDuckdbTempChild *child,
    gboolean writable, gint *out_fd)
{
  (void) child;
  (void) writable;
  if (out_fd)
    *out_fd = -1;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create_child_binding (WylFactDuckdbTempRoot *root,
    const gchar *name, WylFactDuckdbTempChild **child,
    WylFactDuckdbTempChildBinding **binding, gint *fd,
    WylFactDuckdbTempOrphanEvidence **evidence)
{
  (void) root;
  (void) name;
  if (child)
    *child = NULL;
  if (binding)
    *binding = NULL;
  if (fd)
    *fd = -1;
  if (evidence)
    *evidence = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_open_binding (WylFactDuckdbTempChild *child,
    gboolean writable, WylFactDuckdbTempChildBinding **binding, gint *fd)
{
  (void) child;
  (void) writable;
  if (binding)
    *binding = NULL;
  if (fd)
    *fd = -1;
  return closed ();
}

wyrelog_error_t wyl_fact_duckdb_temp_child_binding_revalidate
    (WylFactDuckdbTempChildBinding * binding)
{
  (void) binding;
  return closed ();
}

wyrelog_error_t wyl_fact_duckdb_temp_child_binding_revalidate_fd
    (WylFactDuckdbTempChildBinding * binding, gint fd)
{
  (void) binding;
  (void) fd;
  return closed ();
}

wyrelog_error_t wyl_fact_duckdb_temp_child_binding_close
    (WylFactDuckdbTempChildBinding * binding, gint * fd)
{
  (void) binding;
  if (fd)
    *fd = -1;
  return closed ();
}

void
wyl_fact_duckdb_temp_child_binding_free (WylFactDuckdbTempChildBinding *b)
{
  (void) b;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_list_children (WylFactDuckdbTempRoot *root,
    GPtrArray **out_children)
{
  (void) root;
  if (out_children)
    *out_children = NULL;
  return closed ();
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_retire (WylFactDuckdbTempChild *child,
    WylFactDuckdbTempRetireResult *out_result)
{
  (void) child;
  if (out_result)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  return closed ();
}

void
wyl_fact_duckdb_temp_child_free (WylFactDuckdbTempChild *child)
{
  (void) child;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_retire (WylFactDuckdbTempRoot *root,
    WylFactDuckdbTempRetireResult *out_result)
{
  (void) root;
  if (out_result)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  return closed ();
}
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#ifdef __linux__
#include <sys/syscall.h>
extern long syscall (long, ...);
#endif
typedef struct WylFactArtifactLockDomain WylFactArtifactLockDomain;
struct WylFactArtifactNamespace
{
  gint references;
  gint fd;
  guint64 device, inode, owner;
  gint main_fd;
  guint64 main_device, main_inode;
  gint lock_pin_fd;
  guint64 lock_device, lock_inode;
  WylFactArtifactLockDomain *lock_domain;
};
struct WylFactArtifactLockDomain
{
  guint64 directory_device, directory_inode;
  gint pin_fd;
  guint64 lock_device, lock_inode;
  guint references;
};
struct WylFactArtifactMutationLease
{
  gint references;
  WylFactArtifactNamespace *namespace_;
  GMutex mutex;
  gint lock_fd;
  guint64 directory_device, directory_inode;
  guint64 lock_device, lock_inode;
  gboolean exclusive;
};
struct WylFactArtifactTempBinding
{
  WylFactArtifactMutationLease *lease;
  gchar *token;
  gint pin_fd;
  guint64 device, inode;
  gboolean creator;
  gboolean active;
};
struct WylFactArtifactSidecarBinding
{
  WylFactArtifactMutationLease *lease;
  WylFactArtifactName sidecar;
  gint pin_fd;
  guint64 device, inode;
  gboolean creator;
  gboolean active;
  gint working_fd;
  gboolean io_open;
};
struct WylFactArtifactMainBinding
{
  WylFactArtifactMutationLease *lease;
  gint pin_fd;
  guint64 device, inode;
  gboolean active;
};
struct WylFactArtifactReaderMainBinding
{
  WylFactArtifactMutationLease *lease;
  gint pin_fd;
  guint64 device, inode;
  gboolean active;
};
struct WylFactArtifactReaderWalBinding
{
  WylFactArtifactMutationLease *lease;
  gint pin_fd;
  guint64 device, inode;
  gboolean active;
};
struct WylFactArtifactTempRecoveryEvidence
{
  gchar *token;
  guint64 directory_device, directory_inode;
  guint64 lock_device, lock_inode;
  guint64 artifact_device, artifact_inode;
};
struct WylFactDuckdbTempRoot
{
  gint references;
  WylFactArtifactMutationLease *lease;
  gint fd;
  gchar *name;
  gchar *logical_name;
  guint64 device, inode;
  gboolean active;
  GPtrArray *children;          /* non-owning live child bindings */
};
struct WylFactDuckdbTempChild
{
  gint references;
  WylFactDuckdbTempRoot *root;
  gint pin_fd;
  gchar *name;
  guint64 device, inode;
  gboolean active;
  gboolean io_revoked;
  gboolean unowned_io_terminal;
  GPtrArray *bindings;          /* non-owning live I/O bindings */
};
struct WylFactDuckdbTempChildBinding
{
  WylFactDuckdbTempChild *child;
  gint working_fd;
  gboolean active;
  gboolean io_open;
};
struct WylFactDuckdbTempOrphanEvidence
{
  gchar *logical_name;
};
static const gchar *names[] =
    { "facts.duckdb", "facts.duckdb.wal", "facts.duckdb.wal.checkpoint",
  "facts.duckdb.wal.recovery", "facts.duckdb.lock", NULL
};

static GMutex lock_domains_mutex;
static GPtrArray *lock_domains;
static gint namespace_test_fault;
static WylFactDuckdbTempChild *duckdb_temp_child_ref (WylFactDuckdbTempChild *);
static wyrelog_error_t duckdb_temp_child_matches_unlocked
    (WylFactDuckdbTempChild *);
static void duckdb_temp_child_binding_revoke_unlocked
    (WylFactDuckdbTempChildBinding *);
static wyrelog_error_t duckdb_temp_child_binding_revalidate_unlocked
    (WylFactDuckdbTempChildBinding *);
static wyrelog_error_t duckdb_temp_child_binding_revalidate_fd_unlocked
    (WylFactDuckdbTempChildBinding *, gint);
static wyrelog_error_t duckdb_temp_set_orphan_evidence (const gchar *,
    WylFactDuckdbTempOrphanEvidence **);
static void release_lock_domain (WylFactArtifactNamespace *);
static wyrelog_error_t namespace_test_substitute_regular
    (WylFactArtifactNamespace *, const gchar *, gboolean);
static wyrelog_error_t namespace_test_substitute_fifo
    (WylFactArtifactNamespace *, const gchar *);

static gboolean
namespace_fault_take (WylFactArtifactNamespaceTestFault fault)
{
  return g_atomic_int_compare_and_exchange (&namespace_test_fault, fault,
      WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_NONE);
}

void wyl_fact_artifact_namespace_set_test_fault
    (WylFactArtifactNamespaceTestFault fault)
{
  if (fault >= WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_NONE
      && fault
      <= WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_POST_VALIDATION)
    g_atomic_int_set (&namespace_test_fault, fault);
}

static const gchar *
name_for (WylFactArtifactName n)
{
  return n <= WYL_FACT_ARTIFACT_LOCK ? names[n] : NULL;
}

static gboolean
valid (WylFactArtifactName n)
{
  return n >= WYL_FACT_ARTIFACT_MAIN && n <= WYL_FACT_ARTIFACT_LOCK;
}

static gboolean
sidecar_name (WylFactArtifactName n)
{
  return n == WYL_FACT_ARTIFACT_WAL || n == WYL_FACT_ARTIFACT_CHECKPOINT
      || n == WYL_FACT_ARTIFACT_RECOVERY;
}

static wyrelog_error_t
check_directory (WylFactArtifactNamespace *n)
{
  struct stat s;
  if (!n || n->fd < 0 || fstat (n->fd, &s) || !S_ISDIR (s.st_mode)
      || (s.st_mode & 07777) != 0700 || (guint64) s.st_uid != n->owner
      || s.st_uid != geteuid ()
      || (guint64) s.st_dev != n->device || (guint64) s.st_ino != n->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
check (WylFactArtifactNamespace *n)
{
  struct stat held, named;
  if (check_directory (n) != WYRELOG_E_OK || n->main_fd < 0
      || fstat (n->main_fd, &held) != 0 || !S_ISREG (held.st_mode)
      || held.st_nlink != 1 || (held.st_mode & 07777) != 0600
      || (guint64) held.st_uid != n->owner
      || (guint64) held.st_dev != n->main_device
      || (guint64) held.st_ino != n->main_inode
      || fstatat (n->fd, name_for (WYL_FACT_ARTIFACT_MAIN), &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named.st_mode)
      || named.st_nlink != 1 || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != n->owner
      || (guint64) named.st_dev != n->main_device
      || (guint64) named.st_ino != n->main_inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static gint
duplicate_cloexec (gint fd)
{
#ifdef F_DUPFD_CLOEXEC
  return fcntl (fd, F_DUPFD_CLOEXEC, 3);
#else
  gint duplicate = dup (fd);
  if (duplicate >= 0 && fcntl (duplicate, F_SETFD, FD_CLOEXEC) != 0) {
    close (duplicate);
    duplicate = -1;
  }
  return duplicate;
#endif
}

static WylFactArtifactNamespace *
namespace_ref (WylFactArtifactNamespace *n)
{
  if (n)
    g_atomic_int_inc (&n->references);
  return n;
}

static void
namespace_unref (WylFactArtifactNamespace *n)
{
  if (!n || !g_atomic_int_dec_and_test (&n->references))
    return;
  if (n->fd >= 0)
    close (n->fd);
  if (n->main_fd >= 0)
    close (n->main_fd);
  if (n->lock_pin_fd >= 0)
    close (n->lock_pin_fd);
  release_lock_domain (n);
  g_free (n);
}

static wyrelog_error_t
lock_stat_matches (WylFactArtifactNamespace *n, gint fd,
    guint64 device, guint64 inode)
{
  struct stat held, named;
  if (check (n) != WYRELOG_E_OK || fd < 0 || fstat (fd, &held) != 0
      || !S_ISREG (held.st_mode) || held.st_nlink != 1
      || (held.st_mode & 07777) != 0600
      || (guint64) held.st_uid != n->owner
      || (guint64) held.st_dev != device || (guint64) held.st_ino != inode)
    return WYRELOG_E_POLICY;
  if (fstatat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK), &named,
          AT_SYMLINK_NOFOLLOW) != 0)
    return WYRELOG_E_POLICY;
  return S_ISREG (named.st_mode) && named.st_nlink == 1
      && (named.st_mode & 07777) == 0600
      && (guint64) named.st_uid == n->owner
      && (guint64) named.st_dev == device && (guint64) named.st_ino == inode
      ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
lock_open_error (gint error)
{
  return error == ELOOP || error == EISDIR || error == ENOTDIR
      ? WYRELOG_E_POLICY :
      (error == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO);
}

/* The retained pin is never used for flock.  Every guard gets a separately
 * opened file description so the kernel sees real independent lock holders. */
static wyrelog_error_t
open_checked_lock (WylFactArtifactNamespace *n, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!n || !out_fd)
    return WYRELOG_E_INVALID;
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  if (n->lock_pin_fd < 0) {
    gint pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
        O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
        0600);
    gboolean created = pin >= 0;
    if (pin < 0 && errno == EEXIST)
      pin = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
          O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (pin < 0)
      return lock_open_error (errno);
    if (created && fchmod (pin, 0600) != 0) {
      close (pin);
      return WYRELOG_E_IO;
    }
    struct stat s;
    if (fstat (pin, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    if (lock_stat_matches (n, pin, s.st_dev, s.st_ino) != WYRELOG_E_OK) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    /* An EEXIST opener may race the creator before its durability barrier.
     * Fsyncing in both paths makes publication wait for one directory barrier. */
    if (namespace_fault_take
        (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_DIRECTORY_FSYNC)
        || fsync (n->fd) != 0) {
      close (pin);
      return WYRELOG_E_IO;
    }
    if (namespace_fault_take
        (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_POST_FSYNC_IDENTITY))
    {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    if (lock_stat_matches (n, pin, s.st_dev, s.st_ino) != WYRELOG_E_OK) {
      close (pin);
      return WYRELOG_E_POLICY;
    }
    n->lock_pin_fd = pin;
    n->lock_device = s.st_dev;
    n->lock_inode = s.st_ino;
  }

  if (lock_stat_matches (n, n->lock_pin_fd, n->lock_device,
          n->lock_inode) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  gint fd = openat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK),
      O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return lock_open_error (errno);
  if (lock_stat_matches (n, fd, n->lock_device, n->lock_inode)
      != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

static WylFactArtifactLockDomain *
find_lock_domain (guint64 device, guint64 inode)
{
  if (!lock_domains)
    return NULL;
  for (guint i = 0; i < lock_domains->len; i++) {
    WylFactArtifactLockDomain *domain = g_ptr_array_index (lock_domains, i);
    if (domain->directory_device == device && domain->directory_inode == inode)
      return domain;
  }
  return NULL;
}

/* A process-wide domain makes every live namespace for the same held
 * directory reject a replaced lock entry instead of silently splitting into
 * two flock domains.  The namespace-local duplicate keeps lease lifetime
 * independent from other namespace objects. */
static wyrelog_error_t
pin_lock_domain (WylFactArtifactNamespace *n)
{
  g_mutex_lock (&lock_domains_mutex);
  WylFactArtifactLockDomain *domain = find_lock_domain (n->device, n->inode);
  if (domain) {
    gint pin = dup (domain->pin_fd);
    if (pin < 0) {
      g_mutex_unlock (&lock_domains_mutex);
      return WYRELOG_E_IO;
    }
    n->lock_pin_fd = pin;
    n->lock_device = domain->lock_device;
    n->lock_inode = domain->lock_inode;
    n->lock_domain = domain;
    domain->references++;
    wyrelog_error_t r = lock_stat_matches (n, pin, n->lock_device,
        n->lock_inode);
    if (r != WYRELOG_E_OK) {
      domain->references--;
      n->lock_domain = NULL;
      n->lock_pin_fd = -1;
      close (pin);
    }
    g_mutex_unlock (&lock_domains_mutex);
    return r;
  }

  gint fd = -1;
  wyrelog_error_t r = open_checked_lock (n, &fd);
  if (r != WYRELOG_E_OK) {
    g_mutex_unlock (&lock_domains_mutex);
    return r;
  }
  close (fd);
  domain = g_new0 (WylFactArtifactLockDomain, 1);
  domain->directory_device = n->device;
  domain->directory_inode = n->inode;
  domain->pin_fd = dup (n->lock_pin_fd);
  if (domain->pin_fd < 0) {
    g_free (domain);
    close (n->lock_pin_fd);
    n->lock_pin_fd = -1;
    g_mutex_unlock (&lock_domains_mutex);
    return WYRELOG_E_IO;
  }
  domain->lock_device = n->lock_device;
  domain->lock_inode = n->lock_inode;
  domain->references = 1;
  if (!lock_domains)
    lock_domains = g_ptr_array_new ();
  g_ptr_array_add (lock_domains, domain);
  n->lock_domain = domain;
  g_mutex_unlock (&lock_domains_mutex);
  return WYRELOG_E_OK;
}

static void
release_lock_domain (WylFactArtifactNamespace *n)
{
  if (!n->lock_domain)
    return;
  g_mutex_lock (&lock_domains_mutex);
  WylFactArtifactLockDomain *domain = n->lock_domain;
  g_assert_cmpuint (domain->references, >, 0);
  if (--domain->references == 0) {
    for (guint i = 0; i < lock_domains->len; i++)
      if (g_ptr_array_index (lock_domains, i) == domain) {
        g_ptr_array_remove_index_fast (lock_domains, i);
        break;
      }
    close (domain->pin_fd);
    g_free (domain);
  }
  n->lock_domain = NULL;
  g_mutex_unlock (&lock_domains_mutex);
}

static wyrelog_error_t open_file_unchecked (WylFactArtifactNamespace *,
    WylFactArtifactName, gboolean, gboolean, gint *);
static wyrelog_error_t open_temp_unchecked (WylFactArtifactNamespace *,
    const gchar *, gboolean, gboolean, gint *);

wyrelog_error_t
wyl_fact_artifact_namespace_open (const WylFactGraphDirectory *d,
    const WylFactGraphRegularFile *main_file, WylFactArtifactNamespace **o)
{
  if (o)
    *o = NULL;
  if (!d || !main_file || !o || d->graph_fd < 0 || main_file->fd < 0)
    return WYRELOG_E_INVALID;
  gint fd = duplicate_cloexec (d->graph_fd);
  gint main_fd = duplicate_cloexec (main_file->fd);
  if (fd < 0 || main_fd < 0) {
    if (fd >= 0)
      close (fd);
    if (main_fd >= 0)
      close (main_fd);
    return WYRELOG_E_IO;
  }
  struct stat s, main_stat, named_main;
  if (fstat (fd, &s) || !S_ISDIR (s.st_mode)
      || (s.st_mode & 07777) != 0700 || s.st_uid != geteuid ()
      || (guint64) s.st_dev != d->graph_device
      || (guint64) s.st_ino != d->graph_inode
      || fstat (main_fd, &main_stat) || !S_ISREG (main_stat.st_mode)
      || main_stat.st_nlink != 1 || (main_stat.st_mode & 07777) != 0600
      || main_stat.st_uid != geteuid ()
      || (guint64) main_stat.st_dev != main_file->device
      || (guint64) main_stat.st_ino != main_file->inode
      || fstatat (fd, name_for (WYL_FACT_ARTIFACT_MAIN), &named_main,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named_main.st_mode)
      || named_main.st_nlink != 1 || (named_main.st_mode & 07777) != 0600
      || named_main.st_uid != geteuid ()
      || (guint64) named_main.st_dev != main_file->device
      || (guint64) named_main.st_ino != main_file->inode) {
    close (fd);
    close (main_fd);
    return WYRELOG_E_POLICY;
  }
  WylFactArtifactNamespace *n = g_new0 (WylFactArtifactNamespace, 1);
  n->references = 1;
  n->fd = fd;
  n->main_fd = main_fd;
  n->lock_pin_fd = -1;
  n->device = s.st_dev;
  n->inode = s.st_ino;
  n->owner = s.st_uid;
  n->main_device = main_stat.st_dev;
  n->main_inode = main_stat.st_ino;
  /* Pin and register before publishing n: no concurrent namespace can choose
   * a different inode for this held graph directory. */
  wyrelog_error_t lock_result = pin_lock_domain (n);
  if (lock_result != WYRELOG_E_OK) {
    close (n->fd);
    close (n->main_fd);
    g_free (n);
    return lock_result;
  }
  if (check (n) != WYRELOG_E_OK) {
    namespace_unref (n);
    return WYRELOG_E_POLICY;
  }
  *o = n;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_namespace_free (WylFactArtifactNamespace *n)
{
  namespace_unref (n);
}

wyrelog_error_t
wyl_fact_artifact_namespace_revalidate (WylFactArtifactNamespace *n)
{
  return check (n);
}

static wyrelog_error_t
acquire_lease (WylFactArtifactNamespace *n, gboolean exclusive,
    WylFactArtifactMutationLease **out_lease)
{
  if (out_lease)
    *out_lease = NULL;
  if (!n || !out_lease)
    return WYRELOG_E_INVALID;
  gint fd = -1;
  wyrelog_error_t r = open_checked_lock (n, &fd);
  if (r != WYRELOG_E_OK)
    return r;
  if (flock (fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
    close (fd);
    return errno == EWOULDBLOCK || errno == EAGAIN ? WYRELOG_E_BUSY :
        WYRELOG_E_IO;
  }
  WylFactArtifactMutationLease *lease =
      g_new0 (WylFactArtifactMutationLease, 1);
  lease->references = 1;
  lease->namespace_ = namespace_ref (n);
  g_mutex_init (&lease->mutex);
  lease->lock_fd = fd;
  lease->directory_device = n->device;
  lease->directory_inode = n->inode;
  lease->lock_device = n->lock_device;
  lease->lock_inode = n->lock_inode;
  lease->exclusive = exclusive;
  r = wyl_fact_artifact_mutation_lease_revalidate (lease);
  if (r != WYRELOG_E_OK) {
    wyl_fact_artifact_mutation_lease_free (lease);
    return r;
  }
  *out_lease = lease;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_reader_guard (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **out_lease)
{
  return acquire_lease (n, FALSE, out_lease);
}

wyrelog_error_t
wyl_fact_artifact_namespace_acquire_mutation_lease (WylFactArtifactNamespace *n,
    WylFactArtifactMutationLease **out_lease)
{
  return acquire_lease (n, TRUE, out_lease);
}

static wyrelog_error_t
lease_revalidate_unlocked (WylFactArtifactMutationLease *l)
{
  if (!l || !l->namespace_ || l->lock_fd < 0
      || l->directory_device != l->namespace_->device
      || l->directory_inode != l->namespace_->inode
      || l->lock_device != l->namespace_->lock_device
      || l->lock_inode != l->namespace_->lock_inode)
    return WYRELOG_E_POLICY;
  return lock_stat_matches (l->namespace_, l->lock_fd, l->lock_device,
      l->lock_inode);
}

/* Main binding reports a genuinely absent fixed name as NOT_FOUND, while
 * retaining every other held-authority check before observing that absence. */
static wyrelog_error_t
lease_revalidate_without_named_main_unlocked (WylFactArtifactMutationLease *l)
{
  WylFactArtifactNamespace *n;
  struct stat held_main, held_lock, named_lock;
  if (!l || !(n = l->namespace_) || l->lock_fd < 0 || !l->exclusive
      || l->directory_device != n->device || l->directory_inode != n->inode
      || l->lock_device != n->lock_device || l->lock_inode != n->lock_inode
      || check_directory (n) != WYRELOG_E_OK || n->main_fd < 0
      || fstat (n->main_fd, &held_main) != 0 || !S_ISREG (held_main.st_mode)
      || held_main.st_nlink != 1 || (held_main.st_mode & 07777) != 0600
      || (guint64) held_main.st_uid != n->owner
      || (guint64) held_main.st_dev != n->main_device
      || (guint64) held_main.st_ino != n->main_inode
      || fstat (l->lock_fd, &held_lock) != 0 || !S_ISREG (held_lock.st_mode)
      || held_lock.st_nlink != 1 || (held_lock.st_mode & 07777) != 0600
      || (guint64) held_lock.st_uid != n->owner
      || (guint64) held_lock.st_dev != l->lock_device
      || (guint64) held_lock.st_ino != l->lock_inode
      || fstatat (n->fd, name_for (WYL_FACT_ARTIFACT_LOCK), &named_lock,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named_lock.st_mode)
      || named_lock.st_nlink != 1 || (named_lock.st_mode & 07777) != 0600
      || (guint64) named_lock.st_uid != n->owner
      || (guint64) named_lock.st_dev != l->lock_device
      || (guint64) named_lock.st_ino != l->lock_inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_revalidate (WylFactArtifactMutationLease *l)
{
  if (!l)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&l->mutex);
  wyrelog_error_t r = lease_revalidate_unlocked (l);
  g_mutex_unlock (&l->mutex);
  return r;
}

void
wyl_fact_artifact_mutation_lease_free (WylFactArtifactMutationLease *l)
{
  if (!l)
    return;
  if (!g_atomic_int_dec_and_test (&l->references))
    return;
  g_mutex_clear (&l->mutex);
  if (l->lock_fd >= 0)
    close (l->lock_fd);
  namespace_unref (l->namespace_);
  g_free (l);
}

/* Deterministic test-only ABA seam.  The canonical name returns to the
 * imported inode, but the namespace must still fail the operation rather than
 * hand out a descriptor across an observed replacement window. */
static wyrelog_error_t
namespace_test_main_open_aba (WylFactArtifactNamespace *n)
{
  static const gchar temporary[] = ".facts.duckdb-main-open-aba";
  const gchar *main_name = name_for (WYL_FACT_ARTIFACT_MAIN);
  if (renameat (n->fd, main_name, n->fd, temporary) != 0)
    return WYRELOG_E_IO;
  gint foreign = openat (n->fd, main_name,
      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (foreign < 0) {
    (void) renameat (n->fd, temporary, n->fd, main_name);
    return WYRELOG_E_IO;
  }
  close (foreign);
  if (unlinkat (n->fd, main_name, 0) != 0
      || renameat (n->fd, temporary, n->fd, main_name) != 0)
    return WYRELOG_E_IO;
  return WYRELOG_E_POLICY;
}

/* facts.duckdb is imported at namespace construction.  No later API may
 * re-open its pathname: callers receive only a CLOEXEC duplicate of the held
 * open-file description after the complete directory/main revalidation. */
static wyrelog_error_t
duplicate_imported_main (WylFactArtifactNamespace *n, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!n || !out_fd || check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA))
    return namespace_test_main_open_aba (n);
  gint fd = duplicate_cloexec (n->main_fd);
  if (fd < 0 || check (n) != WYRELOG_E_OK) {
    if (fd >= 0)
      close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

static WylFactArtifactMutationLease *
mutation_lease_ref (WylFactArtifactMutationLease *l)
{
  g_atomic_int_inc (&l->references);
  return l;
}

static wyrelog_error_t
main_binding_matches_unlocked (WylFactArtifactMainBinding *binding)
{
  WylFactArtifactMutationLease *lease = binding->lease;
  WylFactArtifactNamespace *namespace_ = lease->namespace_;
  struct stat pinned, named;
  if (!binding->active || fstat (binding->pin_fd, &pinned) != 0
      || !S_ISREG (pinned.st_mode) || pinned.st_nlink != 1
      || (pinned.st_mode & 07777) != 0600
      || (guint64) pinned.st_uid != namespace_->owner
      || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || binding->device != namespace_->main_device
      || binding->inode != namespace_->main_inode
      || fstatat (namespace_->fd, name_for (WYL_FACT_ARTIFACT_MAIN), &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named.st_mode)
      || named.st_nlink != 1 || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != namespace_->owner
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
main_binding_revalidate_unlocked (WylFactArtifactMainBinding *binding)
{
  if (!binding || !binding->lease || !binding->lease->exclusive)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = lease_revalidate_unlocked (binding->lease);
  if (result == WYRELOG_E_OK)
    result = main_binding_matches_unlocked (binding);
  /* A main binding is an I/O capability, not recovery evidence.  Once it has
   * observed an invalid held authority it can never become usable again. */
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

static wyrelog_error_t
duckdb_temp_child_binding_new (WylFactDuckdbTempChild *child, gint fd,
    WylFactDuckdbTempChildBinding **out_binding)
{
  if (!child || !out_binding || fd < 0)
    return WYRELOG_E_INVALID;
  *out_binding = NULL;
  WylFactArtifactMutationLease *lease = child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_matches_unlocked (child);
  struct stat st;
  if (result == WYRELOG_E_OK && (fstat (fd, &st) != 0
          || !S_ISREG (st.st_mode) || st.st_nlink != 1
          || (st.st_mode & 07777) != 0600
          || (guint64) st.st_uid != lease->namespace_->owner
          || (guint64) st.st_dev != child->device
          || (guint64) st.st_ino != child->inode))
    result = WYRELOG_E_POLICY;
  WylFactDuckdbTempChildBinding *binding = result == WYRELOG_E_OK
      ? g_new0 (WylFactDuckdbTempChildBinding, 1) : NULL;
  if (result == WYRELOG_E_OK && !binding)
    result = WYRELOG_E_NOMEM;
  if (result == WYRELOG_E_OK) {
    binding->child = duckdb_temp_child_ref (child);
    binding->working_fd = fd;
    binding->active = TRUE;
    binding->io_open = TRUE;
    child->io_revoked = FALSE;
    g_ptr_array_add (child->bindings, binding);
    gboolean fault = namespace_fault_take
        (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_BINDING_POST_OPEN_IDENTITY);
    if (fault || duckdb_temp_child_binding_revalidate_fd_unlocked (binding,
            fd) != WYRELOG_E_OK) {
      if (fault)
        duckdb_temp_child_binding_revoke_unlocked (binding);
      g_ptr_array_remove_fast (child->bindings, binding);
      wyl_fact_duckdb_temp_child_free (binding->child);
      g_free (binding);
      binding = NULL;
      result = WYRELOG_E_POLICY;
    }
  }
  if (result == WYRELOG_E_OK)
    *out_binding = binding;
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create_child_binding (WylFactDuckdbTempRoot *root,
    const gchar *name, WylFactDuckdbTempChild **out_child,
    WylFactDuckdbTempChildBinding **out_binding, gint *out_fd,
    WylFactDuckdbTempOrphanEvidence **out_evidence)
{
  if (out_child)
    *out_child = NULL;
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (out_evidence)
    *out_evidence = NULL;
  if (!root || !out_child || !out_binding || !out_fd || !out_evidence)
    return WYRELOG_E_INVALID;
  WylFactDuckdbTempChild *child = NULL;
  gint fd = -1;
  wyrelog_error_t result =
      wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence (root, name,
      &child, &fd, out_evidence);
  if (result != WYRELOG_E_OK)
    return result;
  WylFactDuckdbTempChildBinding *binding = NULL;
  result = duckdb_temp_child_binding_new (child, fd, &binding);
  if (result != WYRELOG_E_OK) {
    /* fd still names the newly created child here; it is ours to close. */
    close (fd);
    WylFactDuckdbTempRetireResult retired;
    (void) wyl_fact_duckdb_temp_child_retire (child, &retired);
    /* Binding construction can fail after durable child creation.  If its
     * terminal revoke barrier prevents exact cleanup, preserve the only safe
     * recovery telemetry instead of losing the otherwise unnameable orphan. */
    if (retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED) {
      g_autofree gchar *logical_name = g_strdup_printf ("%s/%s",
          root->logical_name, name);
      if (!logical_name || duckdb_temp_set_orphan_evidence (logical_name,
              out_evidence) != WYRELOG_E_OK)
        result = WYRELOG_E_NOMEM;
    }
    wyl_fact_duckdb_temp_child_free (child);
    return result;
  }
  *out_child = child;
  *out_binding = binding;
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_open_binding (WylFactDuckdbTempChild *child,
    gboolean writable, WylFactDuckdbTempChildBinding **out_binding,
    gint *out_fd)
{
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!child || !out_binding || !out_fd)
    return WYRELOG_E_INVALID;
  gint fd = -1;
  wyrelog_error_t result = wyl_fact_duckdb_temp_child_open (child, writable,
      &fd);
  if (result != WYRELOG_E_OK)
    return result;
  result = duckdb_temp_child_binding_new (child, fd, out_binding);
  if (result != WYRELOG_E_OK) {
    close (fd);
    return result;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_binding_revalidate (WylFactDuckdbTempChildBinding *b)
{
  if (!b || !b->child)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = b->child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_binding_revalidate_unlocked (b);
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_binding_revalidate_fd (WylFactDuckdbTempChildBinding
    *b, gint fd)
{
  if (!b || !b->child)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = b->child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_binding_revalidate_fd_unlocked (b,
      fd);
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_binding_close (WylFactDuckdbTempChildBinding *b,
    gint *fd)
{
  if (!b || !b->child || !fd)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = b->child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_binding_revalidate_fd_unlocked (b,
      *fd);
  if (result == WYRELOG_E_OK) {
    gint issued = *fd;
    *fd = -1;
    b->active = FALSE;
    b->io_open = FALSE;
    b->working_fd = -1;
    if (close (issued) != 0) {
      duckdb_temp_child_binding_revoke_unlocked (b);
      result = WYRELOG_E_IO;
    }
  }
  g_mutex_unlock (&lease->mutex);
  return result;
}

void
wyl_fact_duckdb_temp_child_binding_free (WylFactDuckdbTempChildBinding *b)
{
  if (!b)
    return;
  WylFactDuckdbTempChild *child = b->child;
  if (child && child->root && child->root->lease) {
    g_mutex_lock (&child->root->lease->mutex);
    /* Free cannot prove that a still-live caller descriptor was later closed;
     * unlike an ordinary revoke this barrier is therefore terminal. */
    if (b->io_open)
      child->unowned_io_terminal = TRUE;
    if (child->bindings)
      g_ptr_array_remove_fast (child->bindings, b);
    g_mutex_unlock (&child->root->lease->mutex);
  }
  wyl_fact_duckdb_temp_child_free (child);
  g_free (b);
}

static wyrelog_error_t
main_binding_revalidate_fd_unlocked (WylFactArtifactMainBinding *binding,
    gint working_fd)
{
  wyrelog_error_t result = main_binding_revalidate_unlocked (binding);
  struct stat working;
  if (result == WYRELOG_E_OK
      && (working_fd < 0 || fstat (working_fd, &working) != 0
          || !S_ISREG (working.st_mode) || working.st_nlink != 1
          || (working.st_mode & 07777) != 0600
          || (guint64) working.st_uid != binding->lease->namespace_->owner
          || (guint64) working.st_dev != binding->device
          || (guint64) working.st_ino != binding->inode))
    result = WYRELOG_E_POLICY;
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_main_binding
    (WylFactArtifactMutationLease * lease,
    WylFactArtifactMainBinding ** out_binding, gint * out_fd) {
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!lease || !out_binding || !out_fd || !lease->exclusive)
    return WYRELOG_E_POLICY;

  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_without_named_main_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;
  struct stat named;
  if (fstatat (lease->namespace_->fd, name_for (WYL_FACT_ARTIFACT_MAIN),
          &named, AT_SYMLINK_NOFOLLOW) != 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
    goto done;
  }
  if (!S_ISREG (named.st_mode) || named.st_nlink != 1
      || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != lease->namespace_->owner
      || (guint64) named.st_dev != lease->namespace_->main_device
      || (guint64) named.st_ino != lease->namespace_->main_inode) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = lease_revalidate_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;
  gint fd = openat (lease->namespace_->fd, name_for (WYL_FACT_ARTIFACT_MAIN),
      O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND
        : (errno == ELOOP || errno == ENOTDIR || errno == EISDIR
        || errno == EACCES ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    goto done;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_BINDING_POST_OPEN_SUBSTITUTE))
  {
    result = namespace_test_substitute_regular (lease->namespace_,
        name_for (WYL_FACT_ARTIFACT_MAIN), TRUE);
    if (result != WYRELOG_E_OK) {
      close (fd);
      goto done;
    }
  }
  gint pin_fd = duplicate_cloexec (fd);
  struct stat pinned;
  if (pin_fd < 0 || fstat (pin_fd, &pinned) != 0) {
    if (pin_fd >= 0)
      close (pin_fd);
    close (fd);
    result = WYRELOG_E_IO;
    goto done;
  }
  WylFactArtifactMainBinding *binding = g_new0 (WylFactArtifactMainBinding, 1);
  binding->lease = mutation_lease_ref (lease);
  binding->pin_fd = pin_fd;
  binding->device = pinned.st_dev;
  binding->inode = pinned.st_ino;
  binding->active = TRUE;
  result = main_binding_revalidate_unlocked (binding);
  if (result != WYRELOG_E_OK) {
    wyl_fact_artifact_main_binding_free (binding);
    close (fd);
    goto done;
  }
  *out_binding = binding;
  *out_fd = fd;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_main_binding_revalidate (WylFactArtifactMainBinding *binding)
{
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = main_binding_revalidate_unlocked (binding);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_main_binding_revalidate_fd (WylFactArtifactMainBinding
    *binding, gint working_fd)
{
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = main_binding_revalidate_fd_unlocked (binding,
      working_fd);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_main_binding_close (WylFactArtifactMainBinding *binding,
    gint *working_fd)
{
  if (!binding || !binding->lease || !working_fd)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = main_binding_revalidate_fd_unlocked (binding,
      *working_fd);
  if (result == WYRELOG_E_OK) {
    gint fd = *working_fd;
    *working_fd = -1;
    binding->active = FALSE;
    result = close (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  }
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

void
wyl_fact_artifact_main_binding_free (WylFactArtifactMainBinding *binding)
{
  if (!binding)
    return;
  if (binding->pin_fd >= 0)
    close (binding->pin_fd);
  wyl_fact_artifact_mutation_lease_free (binding->lease);
  g_free (binding);
}

static wyrelog_error_t
reader_main_binding_matches_unlocked (WylFactArtifactReaderMainBinding *binding)
{
  WylFactArtifactMutationLease *lease = binding->lease;
  WylFactArtifactNamespace *namespace_ = lease->namespace_;
  struct stat pinned;
  if (!binding->active || fstat (binding->pin_fd, &pinned) != 0
      || !S_ISREG (pinned.st_mode) || pinned.st_nlink != 1
      || (pinned.st_mode & 07777) != 0600
      || (guint64) pinned.st_uid != namespace_->owner
      || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || binding->device != namespace_->main_device
      || binding->inode != namespace_->main_inode
      || check (namespace_) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reader_main_binding_revalidate_unlocked (WylFactArtifactReaderMainBinding
    *binding)
{
  if (!binding || !binding->lease || binding->lease->exclusive)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = lease_revalidate_unlocked (binding->lease);
  if (result == WYRELOG_E_OK)
    result = reader_main_binding_matches_unlocked (binding);
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

static wyrelog_error_t
    reader_main_binding_revalidate_fd_unlocked
    (WylFactArtifactReaderMainBinding * binding, gint working_fd)
{
  wyrelog_error_t result = reader_main_binding_revalidate_unlocked (binding);
  struct stat working;
  if (result == WYRELOG_E_OK
      && (working_fd < 0 || fstat (working_fd, &working) != 0
          || !S_ISREG (working.st_mode) || working.st_nlink != 1
          || (working.st_mode & 07777) != 0600
          || (guint64) working.st_uid != binding->lease->namespace_->owner
          || (guint64) working.st_dev != binding->device
          || (guint64) working.st_ino != binding->inode))
    result = WYRELOG_E_POLICY;
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_guard_open_main_binding
    (WylFactArtifactMutationLease * lease,
    WylFactArtifactReaderMainBinding ** out_binding, gint * out_fd) {
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!lease || !out_binding || !out_fd || lease->exclusive)
    return WYRELOG_E_POLICY;

  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_unlocked (lease);
  if (result != WYRELOG_E_OK || check (lease->namespace_) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_READER_MAIN_BINDING_PRE_OPEN_FIFO))
  {
    result = namespace_test_substitute_fifo (lease->namespace_,
        name_for (WYL_FACT_ARTIFACT_MAIN));
    if (result != WYRELOG_E_OK)
      goto done;
  }
  gint fd = openat (lease->namespace_->fd, name_for (WYL_FACT_ARTIFACT_MAIN),
      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND
        : (errno == ELOOP || errno == ENOTDIR || errno == EISDIR
        || errno == EACCES ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    goto done;
  }
  gint pin_fd = duplicate_cloexec (fd);
  struct stat pinned;
  if (pin_fd < 0 || fstat (pin_fd, &pinned) != 0) {
    if (pin_fd >= 0)
      close (pin_fd);
    close (fd);
    result = WYRELOG_E_IO;
    goto done;
  }
  WylFactArtifactReaderMainBinding *binding = g_new0
      (WylFactArtifactReaderMainBinding, 1);
  binding->lease = mutation_lease_ref (lease);
  binding->pin_fd = pin_fd;
  binding->device = pinned.st_dev;
  binding->inode = pinned.st_ino;
  binding->active = TRUE;
  result = reader_main_binding_revalidate_unlocked (binding);
  if (result != WYRELOG_E_OK) {
    wyl_fact_artifact_reader_main_binding_free (binding);
    close (fd);
    goto done;
  }
  *out_binding = binding;
  *out_fd = fd;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_main_binding_revalidate
    (WylFactArtifactReaderMainBinding * binding) {
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_main_binding_revalidate_unlocked (binding);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_main_binding_revalidate_fd
    (WylFactArtifactReaderMainBinding * binding, gint working_fd) {
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_main_binding_revalidate_fd_unlocked (binding,
      working_fd);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_main_binding_close
    (WylFactArtifactReaderMainBinding * binding, gint * working_fd) {
  if (!binding || !binding->lease || !working_fd)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_main_binding_revalidate_fd_unlocked (binding,
      *working_fd);
  if (result == WYRELOG_E_OK) {
    const gint fd = *working_fd;
    *working_fd = -1;
    binding->active = FALSE;
    result = close (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  }
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

void wyl_fact_artifact_reader_main_binding_free
    (WylFactArtifactReaderMainBinding * binding)
{
  if (!binding)
    return;
  if (binding->pin_fd >= 0)
    close (binding->pin_fd);
  wyl_fact_artifact_mutation_lease_free (binding->lease);
  g_free (binding);
}

static wyrelog_error_t
reader_wal_binding_matches_unlocked (WylFactArtifactReaderWalBinding *binding)
{
  WylFactArtifactNamespace *namespace_ = binding->lease->namespace_;
  struct stat pinned, named;
  if (!binding->active || fstat (binding->pin_fd, &pinned) != 0
      || !S_ISREG (pinned.st_mode) || pinned.st_nlink != 1
      || (pinned.st_mode & 07777) != 0600
      || (guint64) pinned.st_uid != namespace_->owner
      || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (namespace_->fd, name_for (WYL_FACT_ARTIFACT_WAL), &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named.st_mode)
      || named.st_nlink != 1 || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != namespace_->owner
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode
      || check (namespace_) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reader_wal_binding_revalidate_unlocked (WylFactArtifactReaderWalBinding
    *binding)
{
  if (!binding || !binding->lease || binding->lease->exclusive)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = lease_revalidate_unlocked (binding->lease);
  if (result == WYRELOG_E_OK)
    result = reader_wal_binding_matches_unlocked (binding);
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

static wyrelog_error_t
    reader_wal_binding_revalidate_fd_unlocked
    (WylFactArtifactReaderWalBinding * binding, gint working_fd)
{
  wyrelog_error_t result = reader_wal_binding_revalidate_unlocked (binding);
  struct stat working;
  if (result == WYRELOG_E_OK
      && (working_fd < 0 || fstat (working_fd, &working) != 0
          || !S_ISREG (working.st_mode) || working.st_nlink != 1
          || (working.st_mode & 07777) != 0600
          || (guint64) working.st_uid != binding->lease->namespace_->owner
          || (guint64) working.st_dev != binding->device
          || (guint64) working.st_ino != binding->inode))
    result = WYRELOG_E_POLICY;
  if (result != WYRELOG_E_OK)
    binding->active = FALSE;
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_guard_open_existing_wal_binding
    (WylFactArtifactMutationLease * lease,
    WylFactArtifactReaderWalBinding ** out_binding, gint * out_fd) {
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!lease || !out_binding || !out_fd || lease->exclusive)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_unlocked (lease);
  if (result != WYRELOG_E_OK || check (lease->namespace_) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_READER_WAL_BINDING_PRE_OPEN_FIFO))
  {
    result = namespace_test_substitute_fifo (lease->namespace_,
        name_for (WYL_FACT_ARTIFACT_WAL));
    if (result != WYRELOG_E_OK)
      goto done;
  }
  gint fd = openat (lease->namespace_->fd, name_for (WYL_FACT_ARTIFACT_WAL),
      O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND
        : (errno == ELOOP || errno == ENOTDIR || errno == EISDIR
        || errno == EACCES ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    goto done;
  }
  gint pin_fd = duplicate_cloexec (fd);
  struct stat pinned;
  if (pin_fd < 0 || fstat (pin_fd, &pinned) != 0) {
    if (pin_fd >= 0)
      close (pin_fd);
    close (fd);
    result = WYRELOG_E_IO;
    goto done;
  }
  WylFactArtifactReaderWalBinding *binding = g_new0
      (WylFactArtifactReaderWalBinding, 1);
  binding->lease = mutation_lease_ref (lease);
  binding->pin_fd = pin_fd;
  binding->device = pinned.st_dev;
  binding->inode = pinned.st_ino;
  binding->active = TRUE;
  result = reader_wal_binding_revalidate_unlocked (binding);
  if (result != WYRELOG_E_OK) {
    wyl_fact_artifact_reader_wal_binding_free (binding);
    close (fd);
    goto done;
  }
  *out_binding = binding;
  *out_fd = fd;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_wal_binding_revalidate
    (WylFactArtifactReaderWalBinding * binding) {
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_wal_binding_revalidate_unlocked (binding);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_wal_binding_revalidate_fd
    (WylFactArtifactReaderWalBinding * binding, gint working_fd) {
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_wal_binding_revalidate_fd_unlocked (binding,
      working_fd);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_reader_wal_binding_close
    (WylFactArtifactReaderWalBinding * binding, gint * working_fd) {
  if (!binding || !binding->lease || !working_fd)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = reader_wal_binding_revalidate_fd_unlocked (binding,
      *working_fd);
  if (result == WYRELOG_E_OK) {
    const gint fd = *working_fd;
    *working_fd = -1;
    binding->active = FALSE;
    result = close (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  }
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

void wyl_fact_artifact_reader_wal_binding_free
    (WylFactArtifactReaderWalBinding * binding)
{
  if (!binding)
    return;
  if (binding->pin_fd >= 0)
    close (binding->pin_fd);
  wyl_fact_artifact_mutation_lease_free (binding->lease);
  g_free (binding);
}

wyrelog_error_t
open_file_unchecked (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *o)
{
  if (o)
    *o = -1;
  if (!valid (a) || !o)
    return WYRELOG_E_INVALID;
  wyrelog_error_t r = check (n);
  if (r)
    return r;
  gint flags = (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
  if (create)
    flags |= O_CREAT | O_EXCL;
  gint fd = openat (n->fd, name_for (a), flags, 0600);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  struct stat s, named;
  if (fstat (fd, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1
      || fstatat (n->fd, name_for (a), &named, AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG (named.st_mode) || named.st_nlink != 1
      || (guint64) named.st_dev != (guint64) s.st_dev
      || (guint64) named.st_ino != (guint64) s.st_ino
      || check (n) != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *o = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_file (WylFactArtifactNamespace *n,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *o)
{
  if (o)
    *o = -1;
  if (!o)
    return WYRELOG_E_INVALID;
  /* Direct namespace access is read-only.  A guard is required before any
   * writable descriptor can be handed to a caller. */
  if (a == WYL_FACT_ARTIFACT_LOCK || create || writable)
    return WYRELOG_E_POLICY;
  if (a == WYL_FACT_ARTIFACT_MAIN)
    return duplicate_imported_main (n, o);
  return open_file_unchecked (n, a, FALSE, FALSE, o);
}

wyrelog_error_t
wyl_fact_artifact_namespace_unlink (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  (void) n;
  return valid (a) ? WYRELOG_E_POLICY : WYRELOG_E_INVALID;
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync (WylFactArtifactNamespace *n,
    WylFactArtifactName a)
{
  gint fd = -1;
  wyrelog_error_t r =
      wyl_fact_artifact_namespace_open_file (n, a, FALSE, FALSE, &fd);
  if (r)
    return r;
  r = fsync (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  close (fd);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_namespace_lock (WylFactArtifactNamespace *n, gboolean ex,
    gint *o)
{
  if (o)
    *o = -1;
  (void) ex;
  return !n || !o ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

static gboolean
temp_token_valid (const gchar *token)
{
  if (!token || !*token || strlen (token) > 48)
    return FALSE;
  for (const gchar * p = token; *p; p++)
    if (!(g_ascii_isalnum (*p) || *p == '-'))
      return FALSE;
  return TRUE;
}

wyrelog_error_t
open_temp_unchecked (WylFactArtifactNamespace *n,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!out_fd || !temp_token_valid (token))
    return WYRELOG_E_INVALID;
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  g_autofree gchar *name = g_strdup_printf ("tmp-%s", token);
  gint flags = (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
  if (create)
    flags |= O_CREAT | O_EXCL;
  gint fd = openat (n->fd, name, flags, 0600);
  if (fd < 0)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  struct stat s;
  if (fstat (fd, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1
      || check (n) != WYRELOG_E_OK) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_namespace_open_temp (WylFactArtifactNamespace *n,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (create || writable)
    return WYRELOG_E_POLICY;
  return open_temp_unchecked (n, token, FALSE, FALSE, out_fd);
}

wyrelog_error_t
wyl_fact_artifact_namespace_rename (WylFactArtifactNamespace *n,
    WylFactArtifactName source, WylFactArtifactName destination)
{
  (void) n;
  return !valid (source) || !valid (destination) || source == destination
      ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

/* A post-check is mandatory even when the syscall reports an error: it may
 * have raced after changing the namespace.  A failed identity check wins so
 * callers never continue after observing a substituted lock or directory. */
static wyrelog_error_t
post_mutation_check_unlocked (WylFactArtifactMutationLease *l,
    wyrelog_error_t result)
{
  wyrelog_error_t post = lease_revalidate_unlocked (l);
  return post == WYRELOG_E_OK ? result : post;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_file (WylFactArtifactMutationLease *l,
    WylFactArtifactName a, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!l || !out_fd)
    return WYRELOG_E_INVALID;
  if (!l->exclusive && (create || writable))
    return WYRELOG_E_POLICY;
  if (a == WYL_FACT_ARTIFACT_LOCK)
    return WYRELOG_E_POLICY;
  if (a == WYL_FACT_ARTIFACT_MAIN && (create || writable))
    return WYRELOG_E_POLICY;
  /* Fixed DuckDB sidecars carry replacement authority only through their
   * opaque binding.  Keep this legacy entry point read-only for them. */
  if (sidecar_name (a) && (create || writable))
    return WYRELOG_E_POLICY;
  g_mutex_lock (&l->mutex);
  wyrelog_error_t r = lease_revalidate_unlocked (l);
  if (r != WYRELOG_E_OK) {
    g_mutex_unlock (&l->mutex);
    return r;
  }
  if (a == WYL_FACT_ARTIFACT_MAIN) {
    r = duplicate_imported_main (l->namespace_, out_fd);
    g_mutex_unlock (&l->mutex);
    return r;
  }
  r = open_file_unchecked (l->namespace_, a, create, writable, out_fd);
  if (!create) {
    g_mutex_unlock (&l->mutex);
    return r;
  }
  r = post_mutation_check_unlocked (l, r);
  if (r != WYRELOG_E_OK) {
    if (*out_fd >= 0) {
      close (*out_fd);
      *out_fd = -1;
    }
  }
  g_mutex_unlock (&l->mutex);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp (WylFactArtifactMutationLease *l,
    const gchar *token, gboolean create, gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!l || !out_fd)
    return WYRELOG_E_INVALID;
  if ((!l->exclusive && (create || writable)) || (!create && writable))
    return WYRELOG_E_POLICY;
  g_mutex_lock (&l->mutex);
  wyrelog_error_t r = lease_revalidate_unlocked (l);
  if (r != WYRELOG_E_OK) {
    g_mutex_unlock (&l->mutex);
    return r;
  }
  r = open_temp_unchecked (l->namespace_, token, create, writable, out_fd);
  if (!create) {
    g_mutex_unlock (&l->mutex);
    return r;
  }
  r = post_mutation_check_unlocked (l, r);
  if (r != WYRELOG_E_OK) {
    if (*out_fd >= 0) {
      close (*out_fd);
      *out_fd = -1;
    }
  }
  g_mutex_unlock (&l->mutex);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_open_temp_binding (WylFactArtifactMutationLease
    *l, const gchar *token, gboolean create, gboolean writable,
    WylFactArtifactTempBinding **out_binding, gint *out_fd)
{
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!l || !out_binding || !out_fd)
    return WYRELOG_E_INVALID;
  if ((!l->exclusive && (create || writable)) || (!create && writable))
    return WYRELOG_E_POLICY;

  g_mutex_lock (&l->mutex);
  wyrelog_error_t r = lease_revalidate_unlocked (l);
  if (r != WYRELOG_E_OK)
    goto done;
  r = open_temp_unchecked (l->namespace_, token, create, writable, out_fd);
  if (r != WYRELOG_E_OK)
    goto done;

  struct stat s;
  gint pin_fd = dup (*out_fd);
  if (pin_fd < 0 || fcntl (pin_fd, F_SETFD, FD_CLOEXEC) != 0
      || fstat (pin_fd, &s) != 0 || !S_ISREG (s.st_mode) || s.st_nlink != 1) {
    if (pin_fd >= 0)
      close (pin_fd);
    r = WYRELOG_E_IO;
    goto fail_fd;
  }
  WylFactArtifactTempBinding *binding = g_new0 (WylFactArtifactTempBinding, 1);
  binding->token = g_strdup (token);
  if (!binding->token) {
    close (pin_fd);
    g_free (binding);
    r = WYRELOG_E_NOMEM;
    goto fail_fd;
  }
  binding->lease = mutation_lease_ref (l);
  binding->pin_fd = pin_fd;
  binding->device = s.st_dev;
  binding->inode = s.st_ino;
  binding->creator = create;
  binding->active = TRUE;
  if (create)
    r = post_mutation_check_unlocked (l, WYRELOG_E_OK);
  if (r != WYRELOG_E_OK) {
    wyl_fact_artifact_temp_binding_free (binding);
    goto fail_fd;
  }
  *out_binding = binding;
  goto done;

fail_fd:
  close (*out_fd);
  *out_fd = -1;
done:
  g_mutex_unlock (&l->mutex);
  return r;
}

void
wyl_fact_artifact_temp_binding_free (WylFactArtifactTempBinding *binding)
{
  if (!binding)
    return;
  if (binding->pin_fd >= 0)
    close (binding->pin_fd);
  wyl_fact_artifact_mutation_lease_free (binding->lease);
  g_free (binding->token);
  g_free (binding);
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_open (WylFactArtifactTempBinding *binding,
    gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!binding || !out_fd)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_autofree gchar *name = NULL;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t r;
  if (!binding->active || !binding->creator || (writable && !lease->exclusive)) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  r = lease_revalidate_unlocked (lease);
  if (r != WYRELOG_E_OK)
    goto done;
  struct stat named, pinned;
  name = g_strdup_printf ("tmp-%s", binding->token);
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1 || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG (named.st_mode) || named.st_nlink != 1
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  gint flags = (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
  gint fd = openat (lease->namespace_->fd, name, flags);
  if (fd < 0) {
    r = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
    goto done;
  }
  struct stat opened;
  if (fstat (fd, &opened) != 0 || !S_ISREG (opened.st_mode)
      || opened.st_nlink != 1 || (guint64) opened.st_dev != binding->device
      || (guint64) opened.st_ino != binding->inode) {
    close (fd);
    r = WYRELOG_E_POLICY;
    goto done;
  }
  *out_fd = fd;
  r = WYRELOG_E_OK;
done:
  g_mutex_unlock (&lease->mutex);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_unlink (WylFactArtifactTempBinding *binding)
{
  if (!binding)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_autofree gchar *name = NULL;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t r;
  if (!binding->active || !binding->creator || !lease->exclusive) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  r = lease_revalidate_unlocked (lease);
  if (r != WYRELOG_E_OK)
    goto done;

  struct stat named, pinned;
  name = g_strdup_printf ("tmp-%s", binding->token);
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1 || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG (named.st_mode) || named.st_nlink != 1
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (unlinkat (lease->namespace_->fd, name, 0) != 0) {
    r = errno == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    r = post_mutation_check_unlocked (lease, r);
    goto done;
  }

  /* unlink is the linearization point.  Never leave an apparently reusable
   * binding after it succeeds, even if the durability report below fails. */
  binding->active = FALSE;
  close (binding->pin_fd);
  binding->pin_fd = -1;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_UNLINK_DIRECTORY_FSYNC)
      || fsync (lease->namespace_->fd) != 0)
    r = WYRELOG_E_IO;
  else
    r = WYRELOG_E_OK;
  r = post_mutation_check_unlocked (lease, r);
  if (fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW) == 0
      || errno != ENOENT)
    r = WYRELOG_E_POLICY;
done:
  g_mutex_unlock (&lease->mutex);
  return r;
}

static wyrelog_error_t
rename_no_replace (gint dirfd, const gchar *source, const gchar *destination)
{
#if defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
  if (syscall (SYS_renameat2, dirfd, source, dirfd, destination,
          RENAME_NOREPLACE) == 0)
    return WYRELOG_E_OK;
  if (errno == EEXIST)
    return WYRELOG_E_POLICY;
  if (errno == ENOSYS || errno == EINVAL || errno == ENOENT)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
#elif defined(__APPLE__)
  if (renameatx_np (dirfd, source, dirfd, destination, RENAME_EXCL) == 0)
    return WYRELOG_E_OK;
  if (errno == EEXIST || errno == ENOENT)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
#else
  (void) dirfd;
  (void) source;
  (void) destination;
  return WYRELOG_E_POLICY;
#endif
}

/* Private deterministic seam: model a same-UID pathname substitution after a
 * caller's earlier validation.  Production callers never invoke this path. */
static wyrelog_error_t
namespace_test_substitute_regular (WylFactArtifactNamespace *namespace_,
    const gchar *name, gboolean replace_existing)
{
  if (replace_existing && unlinkat (namespace_->fd, name, 0) != 0)
    return WYRELOG_E_IO;
  gint fd = openat (namespace_->fd, name,
      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return errno == EEXIST ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  close (fd);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
namespace_test_substitute_fifo (WylFactArtifactNamespace *namespace_,
    const gchar *name)
{
  if (unlinkat (namespace_->fd, name, 0) != 0)
    return WYRELOG_E_IO;
  return mkfifoat (namespace_->fd, name, 0600) == 0 ? WYRELOG_E_OK :
      WYRELOG_E_IO;
}

static wyrelog_error_t
lease_revalidate_sidecar_unlocked (WylFactArtifactMutationLease *lease)
{
  return lease_revalidate_unlocked (lease);
}

static wyrelog_error_t
sidecar_binding_matches_unlocked (WylFactArtifactSidecarBinding *binding)
{
  WylFactArtifactMutationLease *lease = binding->lease;
  struct stat pinned, named;
  if (!binding->active || !sidecar_name (binding->sidecar)
      || fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1 || (pinned.st_mode & 07777) != 0600
      || (guint64) pinned.st_uid != lease->namespace_->owner
      || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, name_for (binding->sidecar), &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named.st_mode)
      || named.st_nlink != 1 || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != lease->namespace_->owner
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static void sidecar_binding_revoke_unlocked
    (WylFactArtifactSidecarBinding * binding);

static wyrelog_error_t
sidecar_binding_revalidate_unlocked (WylFactArtifactSidecarBinding *binding)
{
  if (!binding || !binding->lease || !binding->lease->exclusive)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = lease_revalidate_sidecar_unlocked (binding->lease);
  if (result == WYRELOG_E_OK)
    result = sidecar_binding_matches_unlocked (binding);
  /* Lifecycle identity loss is terminal too.  The sole non-terminal state
   * transition is a successful checked close, which relinquishes only I/O. */
  if (result != WYRELOG_E_OK)
    sidecar_binding_revoke_unlocked (binding);
  return result;
}

static void
sidecar_binding_revoke_unlocked (WylFactArtifactSidecarBinding *binding)
{
  binding->active = FALSE;
  binding->io_open = FALSE;
  binding->working_fd = -1;
}

static wyrelog_error_t
sidecar_binding_working_fd_matches_unlocked (WylFactArtifactSidecarBinding
    *binding, gint working_fd)
{
  struct stat working;
  if (!binding->io_open || working_fd < 0 || working_fd != binding->working_fd
      || fstat (working_fd, &working) != 0 || !S_ISREG (working.st_mode)
      || working.st_nlink != 1 || (working.st_mode & 07777) != 0600
      || (guint64) working.st_uid != binding->lease->namespace_->owner
      || (guint64) working.st_dev != binding->device
      || (guint64) working.st_ino != binding->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

/* The returned descriptor is a separate capability from the binding pin.  A
 * caller can close it and have its number reused, so checking only the pin
 * would permit raw DuckDB I/O on a foreign object. */
static wyrelog_error_t
sidecar_binding_revalidate_fd_unlocked (WylFactArtifactSidecarBinding *binding,
    gint working_fd)
{
  wyrelog_error_t result = sidecar_binding_revalidate_unlocked (binding);
  if (result == WYRELOG_E_OK)
    result = sidecar_binding_working_fd_matches_unlocked (binding, working_fd);
  /* Unlike the general lifecycle revalidation, an I/O-boundary failure
   * revokes this raw-descriptor authority permanently. */
  if (result != WYRELOG_E_OK)
    sidecar_binding_revoke_unlocked (binding);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_sidecar_binding
    (WylFactArtifactMutationLease * lease, WylFactArtifactName sidecar,
    gboolean create, gboolean writable,
    WylFactArtifactSidecarBinding ** out_binding, gint * out_fd) {
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  if (!lease || !out_binding || !out_fd || !lease->exclusive
      || !sidecar_name (sidecar) || (!create && writable))
    return WYRELOG_E_POLICY;

  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;
  result = open_file_unchecked (lease->namespace_, sidecar, create, writable,
      out_fd);
  if (result != WYRELOG_E_OK) {
    /* The strict creator never adopts an extant name.  EEXIST is deliberately
     * normalized by the narrow sidecar authority to POLICY, so a recovery
     * caller can distinguish a hostile/colliding fixed name from I/O. */
    if (create && result == WYRELOG_E_IO) {
      struct stat collision;
      if (fstatat (lease->namespace_->fd, name_for (sidecar), &collision,
              AT_SYMLINK_NOFOLLOW) == 0)
        result = WYRELOG_E_POLICY;
    }
    goto done;
  }

  struct stat pinned;
  gint pin_fd = dup (*out_fd);
  if (pin_fd < 0 || fcntl (pin_fd, F_SETFD, FD_CLOEXEC) != 0
      || fstat (pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1) {
    if (pin_fd >= 0)
      close (pin_fd);
    result = WYRELOG_E_IO;
    goto fail_fd;
  }
  WylFactArtifactSidecarBinding *binding = g_new0
      (WylFactArtifactSidecarBinding, 1);
  binding->lease = mutation_lease_ref (lease);
  binding->sidecar = sidecar;
  binding->pin_fd = pin_fd;
  binding->device = pinned.st_dev;
  binding->inode = pinned.st_ino;
  binding->creator = create;
  binding->active = TRUE;
  binding->working_fd = *out_fd;
  binding->io_open = TRUE;
  result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK || sidecar_binding_matches_unlocked (binding)
      != WYRELOG_E_OK) {
    wyl_fact_artifact_sidecar_binding_free (binding);
    goto fail_fd;
  }
  *out_binding = binding;
  goto done;

fail_fd:
  close (*out_fd);
  *out_fd = -1;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
    (WylFactArtifactMutationLease * lease, WylFactArtifactName sidecar,
    gboolean writable, WylFactArtifactSidecarBinding ** out_binding,
    gint * out_fd) {
  if (out_binding)
    *out_binding = NULL;
  if (out_fd)
    *out_fd = -1;
  /* This narrow recovery authority intentionally has no read-only or create
   * mode.  General sidecar opens remain unavailable. */
  if (!lease || !out_binding || !out_fd || !lease->exclusive || !writable
      || !sidecar_name (sidecar))
    return WYRELOG_E_POLICY;

  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;

  gint fd = openat (lease->namespace_->fd, name_for (sidecar),
      O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND
        : (errno == ELOOP || errno == ENOTDIR || errno == EISDIR
        || errno == EACCES ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    goto done;
  }
  gint pin_fd = duplicate_cloexec (fd);
  struct stat pinned;
  if (pin_fd < 0 || fstat (pin_fd, &pinned) != 0) {
    if (pin_fd >= 0)
      close (pin_fd);
    close (fd);
    result = WYRELOG_E_IO;
    goto done;
  }
  WylFactArtifactSidecarBinding *binding = g_new0
      (WylFactArtifactSidecarBinding, 1);
  binding->lease = mutation_lease_ref (lease);
  binding->sidecar = sidecar;
  binding->pin_fd = pin_fd;
  binding->device = pinned.st_dev;
  binding->inode = pinned.st_ino;
  binding->creator = FALSE;
  binding->active = TRUE;
  binding->working_fd = fd;
  binding->io_open = TRUE;
  result = sidecar_binding_revalidate_unlocked (binding);
  if (result != WYRELOG_E_OK) {
    wyl_fact_artifact_sidecar_binding_free (binding);
    close (fd);
    goto done;
  }
  *out_binding = binding;
  *out_fd = fd;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_revalidate (WylFactArtifactSidecarBinding
    *binding)
{
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = sidecar_binding_revalidate_unlocked (binding);
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_revalidate_fd (WylFactArtifactSidecarBinding
    *binding, gint working_fd)
{
  if (!binding || !binding->lease)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = sidecar_binding_revalidate_fd_unlocked (binding,
      working_fd);
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_close (WylFactArtifactSidecarBinding
    *binding, gint *working_fd)
{
  if (!binding || !binding->lease || !working_fd)
    return WYRELOG_E_POLICY;
  g_mutex_lock (&binding->lease->mutex);
  wyrelog_error_t result = sidecar_binding_revalidate_fd_unlocked (binding,
      *working_fd);
  if (result == WYRELOG_E_OK) {
    gint fd = *working_fd;
    *working_fd = -1;
    binding->io_open = FALSE;
    binding->working_fd = -1;
    result = close (fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
    if (result != WYRELOG_E_OK)
      sidecar_binding_revoke_unlocked (binding);
  }
  g_mutex_unlock (&binding->lease->mutex);
  return result;
}

void
wyl_fact_artifact_sidecar_binding_free (WylFactArtifactSidecarBinding *binding)
{
  if (!binding)
    return;
  if (binding->pin_fd >= 0)
    close (binding->pin_fd);
  wyl_fact_artifact_mutation_lease_free (binding->lease);
  g_free (binding);
}

wyrelog_error_t
    wyl_fact_artifact_sidecar_binding_publish_no_replace
    (WylFactArtifactSidecarBinding * binding, WylFactArtifactName destination) {
  if (!binding || !sidecar_name (destination))
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result;
  if (!lease->exclusive || !binding->active || !binding->creator
      || binding->sidecar == destination) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  /* Publication changes the fixed pathname, so it may not race a DuckDB
   * descriptor.  A raw close or number reuse is an integrity failure, not a
   * reason to proceed with a rename. */
  if (binding->io_open) {
    if (sidecar_binding_working_fd_matches_unlocked (binding,
            binding->working_fd) != WYRELOG_E_OK)
      sidecar_binding_revoke_unlocked (binding);
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK || sidecar_binding_matches_unlocked (binding)
      != WYRELOG_E_OK) {
    if (result == WYRELOG_E_OK)
      result = WYRELOG_E_POLICY;
    goto done;
  }
  /* The source must reach stable storage before namespace publication. */
  if (fsync (binding->pin_fd) != 0) {
    result = WYRELOG_E_IO;
    goto done;
  }
  const gchar *source_name = name_for (binding->sidecar);
  const gchar *destination_name = name_for (destination);
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_PUBLISH_PRE_RENAME_INSERT))
  {
    result =
        namespace_test_substitute_regular (lease->namespace_, destination_name,
        FALSE);
    if (result != WYRELOG_E_OK)
      goto done;
  }
  struct stat final_destination;
  if (fstatat (lease->namespace_->fd, destination_name, &final_destination,
          AT_SYMLINK_NOFOLLOW) == 0) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (errno != ENOENT) {
    result = WYRELOG_E_IO;
    goto done;
  }
  if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK
      || sidecar_binding_matches_unlocked (binding) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = rename_no_replace (lease->namespace_->fd, source_name,
      destination_name);
  if (result != WYRELOG_E_OK) {
    wyrelog_error_t post = lease_revalidate_sidecar_unlocked (lease);
    if (post != WYRELOG_E_OK)
      result = post;
    goto done;
  }

  /* renameat2/renameatx_np is the linearization point. */
  binding->sidecar = destination;
  result = fsync (lease->namespace_->fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  wyrelog_error_t post = lease_revalidate_sidecar_unlocked (lease);
  if (post != WYRELOG_E_OK)
    result = post;
  struct stat source_stat, destination_stat;
  if (fstatat (lease->namespace_->fd, source_name, &source_stat,
          AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT
      || fstatat (lease->namespace_->fd, destination_name, &destination_stat,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (destination_stat.st_mode)
      || destination_stat.st_nlink != 1
      || (guint64) destination_stat.st_dev != binding->device
      || (guint64) destination_stat.st_ino != binding->inode)
    result = WYRELOG_E_POLICY;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_sidecar_binding_replace_existing_wal
    (WylFactArtifactSidecarBinding * source,
    WylFactArtifactSidecarBinding * destination,
    WylFactArtifactSidecarReplaceResult * out_result) {
  if (out_result)
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
  if (!source || !destination || !out_result || source == destination
      || !source->lease || source->lease != destination->lease)
    return WYRELOG_E_POLICY;

  WylFactArtifactMutationLease *lease = source->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result;
  gint old_destination_pin = -1;
  guint64 old_destination_device = 0, old_destination_inode = 0;

  if (!lease->exclusive || !source->active || !destination->active
      || (source->sidecar != WYL_FACT_ARTIFACT_CHECKPOINT
          && source->sidecar != WYL_FACT_ARTIFACT_RECOVERY)
      || destination->sidecar != WYL_FACT_ARTIFACT_WAL) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  /* A live issued descriptor is never implicitly closed by replacement.  If
   * raw close or descriptor reuse is detected, revoke that binding before
   * returning so the foreign descriptor cannot regain authority. */
  if (source->io_open || destination->io_open) {
    if (source->io_open
        && sidecar_binding_working_fd_matches_unlocked (source,
            source->working_fd) != WYRELOG_E_OK)
      sidecar_binding_revoke_unlocked (source);
    if (destination->io_open
        && sidecar_binding_working_fd_matches_unlocked (destination,
            destination->working_fd) != WYRELOG_E_OK)
      sidecar_binding_revoke_unlocked (destination);
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = lease_revalidate_sidecar_unlocked (lease);
  if (result == WYRELOG_E_OK)
    result = sidecar_binding_revalidate_unlocked (source);
  if (result == WYRELOG_E_OK)
    result = sidecar_binding_revalidate_unlocked (destination);
  if (result != WYRELOG_E_OK)
    goto done;

  /* The exact source identity is stable before the namespace change. */
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_SOURCE_FSYNC)
      || fsync (source->pin_fd) != 0) {
    result = WYRELOG_E_IO;
    goto done;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_PRE_RENAME)) {
    result = WYRELOG_E_IO;
    goto done;
  }
  /* Revalidate both exact names after source synchronization and immediately
   * before the replacing rename. */
  if (sidecar_binding_revalidate_unlocked (source) != WYRELOG_E_OK
      || sidecar_binding_revalidate_unlocked (destination) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }

  const gchar *source_name = name_for (source->sidecar);
  const gchar *destination_name = name_for (destination->sidecar);
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_RENAME)) {
    result = WYRELOG_E_IO;
    goto done;
  }
  gboolean ambiguous_rename_fault = namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_RENAME_AMBIGUOUS);
  gint rename_result;
  gint rename_error;
  if (ambiguous_rename_fault) {
    /* Deterministic test-only model of a replacing rename which reports an
     * error after the destination unexpectedly disappears while source
     * remains.  Production never removes the WAL outside the rename. */
    rename_result = unlinkat (lease->namespace_->fd, destination_name, 0);
    rename_error = rename_result == 0 ? EIO : errno;
    rename_result = -1;
  } else {
    rename_result = renameat (lease->namespace_->fd, source_name,
        lease->namespace_->fd, destination_name);
    rename_error = errno;
  }
  if (rename_result != 0) {
    struct stat named_source, named_destination;
    gboolean unchanged =
        fstatat (lease->namespace_->fd, source_name, &named_source,
        AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG (named_source.st_mode)
        && named_source.st_nlink == 1
        && (named_source.st_mode & 07777) == 0600
        && (guint64) named_source.st_uid == lease->namespace_->owner
        && (guint64) named_source.st_dev == source->device
        && (guint64) named_source.st_ino == source->inode
        && fstatat (lease->namespace_->fd, destination_name,
        &named_destination, AT_SYMLINK_NOFOLLOW) == 0
        && S_ISREG (named_destination.st_mode)
        && named_destination.st_nlink == 1
        && (named_destination.st_mode & 07777) == 0600
        && (guint64) named_destination.st_uid == lease->namespace_->owner
        && (guint64) named_destination.st_dev == destination->device
        && (guint64) named_destination.st_ino == destination->inode;
    if (!unchanged) {
      /* POSIX rename normally reports success once linearized.  Nevertheless,
       * reconcile an observable post-state rather than returning stale
       * source or destination authority if a platform reports ambiguity. */
      gboolean replaced =
          fstatat (lease->namespace_->fd, source_name, &named_source,
          AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT
          && fstatat (lease->namespace_->fd, destination_name,
          &named_destination, AT_SYMLINK_NOFOLLOW) == 0
          && S_ISREG (named_destination.st_mode)
          && named_destination.st_nlink == 1
          && (guint64) named_destination.st_dev == source->device
          && (guint64) named_destination.st_ino == source->inode;
      if (!replaced) {
        sidecar_binding_revoke_unlocked (source);
        sidecar_binding_revoke_unlocked (destination);
        result = rename_error == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
        *out_result =
            WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
        goto done;
      }
      result = WYRELOG_E_IO;
    } else {
      result = rename_error == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
      goto done;
    }
  } else {
    result = WYRELOG_E_OK;
  }

  /* renameat is the linearization point.  Transfer the source pin and
   * identity before any operation that may fail, and retain the old
   * destination pin only long enough to prove that replacement unlinked it. */
  old_destination_pin = destination->pin_fd;
  old_destination_device = destination->device;
  old_destination_inode = destination->inode;
  destination->pin_fd = source->pin_fd;
  destination->device = source->device;
  destination->inode = source->inode;
  destination->creator = FALSE;
  source->pin_fd = -1;
  source->active = FALSE;

  struct stat old_destination;
  if (fstat (old_destination_pin, &old_destination) != 0
      || !S_ISREG (old_destination.st_mode) || old_destination.st_nlink != 0
      || (guint64) old_destination.st_dev != old_destination_device
      || (guint64) old_destination.st_ino != old_destination_inode)
    result = WYRELOG_E_POLICY;
  close (old_destination_pin);
  old_destination_pin = -1;

  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_POST_LINEARIZATION))
  {
    if (result == WYRELOG_E_OK)
      result = WYRELOG_E_IO;
    goto terminal;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_DIRECTORY_FSYNC)
      || fsync (lease->namespace_->fd) != 0) {
    if (result == WYRELOG_E_OK)
      result = WYRELOG_E_IO;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_POST_VALIDATION))
  {
    result = WYRELOG_E_POLICY;
    goto terminal;
  }

  struct stat absent_source, named_destination;
  if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK) {
    sidecar_binding_revoke_unlocked (destination);
    result = WYRELOG_E_POLICY;
  } else if (fstatat (lease->namespace_->fd, source_name, &absent_source,
          AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
    result = WYRELOG_E_POLICY;
  } else if (sidecar_binding_revalidate_unlocked (destination)
      != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
  } else if (fstatat (lease->namespace_->fd, destination_name,
          &named_destination, AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG (named_destination.st_mode)
      || named_destination.st_nlink != 1
      || (guint64) named_destination.st_dev != destination->device
      || (guint64) named_destination.st_ino != destination->inode) {
    sidecar_binding_revoke_unlocked (destination);
    result = WYRELOG_E_POLICY;
  }

terminal:
  *out_result = result == WYRELOG_E_OK
      ? WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_REPLACED_DURABLE
      : WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
done:
  if (old_destination_pin >= 0)
    close (old_destination_pin);
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_sidecar_binding_retire (WylFactArtifactSidecarBinding
    *binding, WylFactArtifactSidecarRetireResult *out_result)
{
  if (out_result)
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  if (!binding || !out_result)
    return WYRELOG_E_POLICY;

  WylFactArtifactMutationLease *lease = binding->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result;
  if (!lease->exclusive || !binding->active || !sidecar_name (binding->sidecar)) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (binding->io_open) {
    if (sidecar_binding_working_fd_matches_unlocked (binding,
            binding->working_fd) != WYRELOG_E_OK)
      sidecar_binding_revoke_unlocked (binding);
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;

  const gchar *name = name_for (binding->sidecar);
  struct stat pinned, named;
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || (pinned.st_mode & 07777) != 0600
      || (guint64) pinned.st_uid != lease->namespace_->owner
      || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno != ENOENT) {
      result = WYRELOG_E_IO;
      goto done;
    }
    /* Active-binding absence is external state, never a successful cleanup
     * result.  The source pin remains evidence for reconciliation only. */
    binding->active = FALSE;
    result = post_mutation_check_unlocked (lease, WYRELOG_E_POLICY);
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
    goto terminal;
  }
  if (!S_ISREG (named.st_mode) || named.st_nlink != 1 || pinned.st_nlink != 1
      || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != lease->namespace_->owner
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_PRE_UNLINK_SUBSTITUTE))
  {
    result = namespace_test_substitute_regular (lease->namespace_, name, TRUE);
    if (result != WYRELOG_E_OK)
      goto done;
  }
  /* Deterministic seam: substitute after the normal identity check but before
   * the final recheck. It proves an observed substitution is rejected without
   * unlink; #612 documents the remaining final-check-to-unlink same-UID
   * nonparticipant window as outside the portable POSIX guarantee. */
  if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK
      || sidecar_binding_matches_unlocked (binding) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }

  if (unlinkat (lease->namespace_->fd, name, 0) != 0) {
    gint unlink_error = errno;
    gboolean exact_absent = fstat (binding->pin_fd, &pinned) == 0
        && S_ISREG (pinned.st_mode) && pinned.st_nlink == 0
        && (guint64) pinned.st_dev == binding->device
        && (guint64) pinned.st_ino == binding->inode
        && fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW)
        != 0 && errno == ENOENT;
    if (!exact_absent && unlink_error != ENOENT) {
      result = unlink_error == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
      result = post_mutation_check_unlocked (lease, result);
      goto done;
    }
    /* Even an exact nlink=0/ENOENT observation cannot establish that this
     * call performed durable cleanup.  It is terminal reconciliation. */
    binding->active = FALSE;
    result = post_mutation_check_unlocked (lease,
        unlink_error == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO);
    *out_result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
    goto terminal;
  }

  /* unlinkat is the linearization point.  Inactivate before fsync or any
   * post-operation check, so an error can never leave deletion authority. */
  binding->active = FALSE;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_DIRECTORY_FSYNC)
      || fsync (lease->namespace_->fd) != 0)
    result = WYRELOG_E_IO;
  else
    result = WYRELOG_E_OK;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_POLICY))
    result = WYRELOG_E_POLICY;
  else
    result = post_mutation_check_unlocked (lease, result);
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_SUBSTITUTE))
  {
    wyrelog_error_t substitution =
        namespace_test_substitute_regular (lease->namespace_, name, FALSE);
    if (substitution != WYRELOG_E_OK)
      result = substitution;
  }
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 0 || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW)
      == 0 || errno != ENOENT)
    result = WYRELOG_E_POLICY;
  *out_result = result == WYRELOG_E_OK
      ? WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED
      : WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;

terminal:
  close (binding->pin_fd);
  binding->pin_fd = -1;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
    wyl_fact_artifact_temp_binding_replace_sidecar
    (WylFactArtifactTempBinding * source,
    WylFactArtifactSidecarBinding * destination) {
  if (!source || !destination || source->lease != destination->lease)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = source->lease;
  g_autofree gchar *source_name = NULL;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result;
  if (!lease->exclusive || !source->active || !source->creator
      || !destination->active || destination->io_open
      || !sidecar_name (destination->sidecar)) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  result = lease_revalidate_sidecar_unlocked (lease);
  if (result != WYRELOG_E_OK)
    goto done;

  struct stat source_pinned, source_named;
  source_name = g_strdup_printf ("tmp-%s", source->token);
  if (!source_name || fstat (source->pin_fd, &source_pinned) != 0
      || !S_ISREG (source_pinned.st_mode) || source_pinned.st_nlink != 1
      || (guint64) source_pinned.st_dev != source->device
      || (guint64) source_pinned.st_ino != source->inode
      || fstatat (lease->namespace_->fd, source_name, &source_named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (source_named.st_mode)
      || source_named.st_nlink != 1
      || (guint64) source_named.st_dev != source->device
      || (guint64) source_named.st_ino != source->inode
      || sidecar_binding_matches_unlocked (destination) != WYRELOG_E_OK) {
    result = source_name ? WYRELOG_E_POLICY : WYRELOG_E_NOMEM;
    goto done;
  }
  /* The replacement contents are durable before their namespace name moves. */
  if (fsync (source->pin_fd) != 0) {
    result = WYRELOG_E_IO;
    goto done;
  }
  const gchar *destination_name = name_for (destination->sidecar);
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_PRE_RENAME_SUBSTITUTE))
  {
    result =
        namespace_test_substitute_regular (lease->namespace_, destination_name,
        TRUE);
    if (result != WYRELOG_E_OK)
      goto done;
  }
  if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK
      || sidecar_binding_matches_unlocked (destination) != WYRELOG_E_OK) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  gboolean renamed = renameat (lease->namespace_->fd, source_name,
      lease->namespace_->fd, destination_name) == 0;
  gint rename_errno = errno;
  if (!renamed) {
    struct stat after_source, after_destination;
    if (fstatat (lease->namespace_->fd, source_name, &after_source,
            AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT
        && fstatat (lease->namespace_->fd, destination_name,
            &after_destination, AT_SYMLINK_NOFOLLOW) == 0
        && S_ISREG (after_destination.st_mode)
        && after_destination.st_nlink == 1
        && (guint64) after_destination.st_dev == source->device
        && (guint64) after_destination.st_ino == source->inode) {
      /* A namespace may report an error after linearization.  Reconcile the
       * binding to the observable state instead of leaving stale authority. */
      renamed = TRUE;
      result = WYRELOG_E_IO;
    } else {
      result = rename_errno == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
      if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK
          || sidecar_binding_matches_unlocked (destination) != WYRELOG_E_OK)
        result = WYRELOG_E_POLICY;
      goto done;
    }
  }
  if (renamed) {
    /* renameat is the linearization point.  Transfer the source pin to the
     * destination binding before reporting durability or reconciliation errors. */
    close (destination->pin_fd);
    destination->pin_fd = source->pin_fd;
    destination->device = source->device;
    destination->inode = source->inode;
    destination->creator = FALSE;
    source->pin_fd = -1;
    source->active = FALSE;
  }
  if (renamed && namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_POST_RENAME_SUBSTITUTE))
  {
    wyrelog_error_t substitution =
        namespace_test_substitute_regular (lease->namespace_, destination_name,
        TRUE);
    if (substitution != WYRELOG_E_OK)
      result = substitution;
  }
  if (renamed && (!namespace_fault_take
          (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_DIRECTORY_FSYNC)
          && fsync (lease->namespace_->fd) == 0)) {
    /* Keep a prior syscall error: it is durable-state uncertainty, not a
     * successful operation report. */
  } else if (result == WYRELOG_E_OK) {
    result = WYRELOG_E_IO;
  }
  if (lease_revalidate_sidecar_unlocked (lease) != WYRELOG_E_OK)
    result = WYRELOG_E_POLICY;
  struct stat old_source, named_destination;
  if (fstatat (lease->namespace_->fd, source_name, &old_source,
          AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT
      || sidecar_binding_matches_unlocked (destination) != WYRELOG_E_OK
      || fstatat (lease->namespace_->fd, destination_name, &named_destination,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named_destination.st_mode)
      || named_destination.st_nlink != 1
      || (guint64) named_destination.st_dev != destination->device
      || (guint64) named_destination.st_ino != destination->inode)
    result = WYRELOG_E_POLICY;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_artifact_temp_binding_rename (WylFactArtifactTempBinding *binding,
    const gchar *destination_token)
{
  if (!binding)
    return WYRELOG_E_POLICY;
  if (!temp_token_valid (destination_token))
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_autofree gchar *destination = g_strdup_printf ("tmp-%s", destination_token);
  g_autofree gchar *next_token = NULL;
  g_autofree gchar *source = NULL;
  if (!destination)
    return WYRELOG_E_NOMEM;

  g_mutex_lock (&lease->mutex);
  wyrelog_error_t r;
  if (!binding->active || !binding->creator || !lease->exclusive) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (g_strcmp0 (binding->token, destination_token) == 0) {
    r = WYRELOG_E_INVALID;
    goto done;
  }
  next_token = g_strdup (destination_token);
  source = g_strdup_printf ("tmp-%s", binding->token);
  if (!next_token || !source) {
    r = WYRELOG_E_NOMEM;
    goto done;
  }
  r = lease_revalidate_unlocked (lease);
  if (r != WYRELOG_E_OK)
    goto done;
  struct stat source_stat, destination_stat, pinned;
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1 || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, source, &source_stat,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (source_stat.st_mode)
      || source_stat.st_nlink != 1
      || (guint64) source_stat.st_dev != binding->device
      || (guint64) source_stat.st_ino != binding->inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (fstatat (lease->namespace_->fd, destination, &destination_stat,
          AT_SYMLINK_NOFOLLOW) == 0) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (errno != ENOENT) {
    r = WYRELOG_E_IO;
    goto done;
  }
  r = rename_no_replace (lease->namespace_->fd, source, destination);
  if (r != WYRELOG_E_OK) {
    r = post_mutation_check_unlocked (lease, r);
    goto done;
  }

  /* rename is the linearization point.  The old token must never be exposed
   * by a live binding after this point, including an fsync failure below. */
  g_free (binding->token);
  binding->token = g_steal_pointer (&next_token);
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RENAME_DIRECTORY_FSYNC)
      || fsync (lease->namespace_->fd) != 0)
    r = WYRELOG_E_IO;
  else
    r = WYRELOG_E_OK;
  r = post_mutation_check_unlocked (lease, r);
  if (fstatat (lease->namespace_->fd, source, &source_stat,
          AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (fstatat (lease->namespace_->fd, destination, &destination_stat,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (destination_stat.st_mode)
      || destination_stat.st_nlink != 1
      || (guint64) destination_stat.st_dev != binding->device
      || (guint64) destination_stat.st_ino != binding->inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
done:
  g_mutex_unlock (&lease->mutex);
  return r;
}

wyrelog_error_t
    wyl_fact_artifact_temp_binding_export_recovery_evidence
    (WylFactArtifactTempBinding * binding,
    WylFactArtifactTempRecoveryEvidence ** out_evidence) {
  if (out_evidence)
    *out_evidence = NULL;
  if (!binding || !out_evidence)
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = binding->lease;
  g_autofree gchar *name = NULL;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t r;
  if (!binding->active || !binding->creator || !lease->exclusive) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  r = lease_revalidate_unlocked (lease);
  if (r != WYRELOG_E_OK)
    goto done;
  struct stat named, pinned;
  name = g_strdup_printf ("tmp-%s", binding->token);
  if (fstat (binding->pin_fd, &pinned) != 0 || !S_ISREG (pinned.st_mode)
      || pinned.st_nlink != 1 || (guint64) pinned.st_dev != binding->device
      || (guint64) pinned.st_ino != binding->inode
      || fstatat (lease->namespace_->fd, name, &named, AT_SYMLINK_NOFOLLOW) != 0
      || !S_ISREG (named.st_mode) || named.st_nlink != 1
      || (guint64) named.st_dev != binding->device
      || (guint64) named.st_ino != binding->inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  WylFactArtifactTempRecoveryEvidence *evidence =
      g_new0 (WylFactArtifactTempRecoveryEvidence, 1);
  evidence->token = g_strdup (binding->token);
  if (!evidence->token) {
    g_free (evidence);
    r = WYRELOG_E_NOMEM;
    goto done;
  }
  evidence->directory_device = lease->directory_device;
  evidence->directory_inode = lease->directory_inode;
  evidence->lock_device = lease->lock_device;
  evidence->lock_inode = lease->lock_inode;
  evidence->artifact_device = binding->device;
  evidence->artifact_inode = binding->inode;
  *out_evidence = evidence;
  r = WYRELOG_E_OK;
done:
  g_mutex_unlock (&lease->mutex);
  return r;
}

void wyl_fact_artifact_temp_recovery_evidence_free
    (WylFactArtifactTempRecoveryEvidence * evidence)
{
  if (!evidence)
    return;
  g_free (evidence->token);
  g_free (evidence);
}

#define TEMP_EVIDENCE_MAGIC "WTR1"
#define TEMP_EVIDENCE_HEADER_SIZE 53

wyrelog_error_t
wyl_fact_artifact_temp_recovery_evidence_encode (const
    WylFactArtifactTempRecoveryEvidence *evidence, GBytes **out_bytes)
{
  if (out_bytes)
    *out_bytes = NULL;
  if (!evidence || !out_bytes || !temp_token_valid (evidence->token))
    return WYRELOG_E_INVALID;
  const gsize token_size = strlen (evidence->token);
  guint8 *data = g_malloc (TEMP_EVIDENCE_HEADER_SIZE + token_size);
  memcpy (data, TEMP_EVIDENCE_MAGIC, 4);
  data[4] = (guint8) token_size;
  const guint64 fields[] = { evidence->directory_device,
    evidence->directory_inode, evidence->lock_device, evidence->lock_inode,
    evidence->artifact_device, evidence->artifact_inode
  };
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++) {
    const guint64 network = GUINT64_TO_BE (fields[i]);
    memcpy (data + 5 + i * sizeof network, &network, sizeof network);
  }
  memcpy (data + TEMP_EVIDENCE_HEADER_SIZE, evidence->token, token_size);
  *out_bytes = g_bytes_new_take (data, TEMP_EVIDENCE_HEADER_SIZE + token_size);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_temp_recovery_evidence_decode (GBytes *bytes,
    WylFactArtifactTempRecoveryEvidence **out_evidence)
{
  if (out_evidence)
    *out_evidence = NULL;
  if (!bytes || !out_evidence)
    return WYRELOG_E_INVALID;
  gsize size = 0;
  const guint8 *data = g_bytes_get_data (bytes, &size);
  if (size < TEMP_EVIDENCE_HEADER_SIZE
      || memcmp (data, TEMP_EVIDENCE_MAGIC, 4) != 0
      || size != TEMP_EVIDENCE_HEADER_SIZE + (gsize) data[4])
    return WYRELOG_E_INVALID;
  WylFactArtifactTempRecoveryEvidence *evidence =
      g_new0 (WylFactArtifactTempRecoveryEvidence, 1);
  evidence->token = g_strndup ((const gchar *) data + TEMP_EVIDENCE_HEADER_SIZE,
      data[4]);
  if (!temp_token_valid (evidence->token)) {
    wyl_fact_artifact_temp_recovery_evidence_free (evidence);
    return WYRELOG_E_INVALID;
  }
  guint64 *fields[] = { &evidence->directory_device,
    &evidence->directory_inode, &evidence->lock_device, &evidence->lock_inode,
    &evidence->artifact_device, &evidence->artifact_inode
  };
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++) {
    guint64 network;
    memcpy (&network, data + 5 + i * sizeof network, sizeof network);
    *fields[i] = GUINT64_FROM_BE (network);
  }
  *out_evidence = evidence;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_recover_temp (WylFactArtifactMutationLease *l,
    const WylFactArtifactTempRecoveryEvidence *evidence)
{
  if (!l || !evidence || !l->exclusive || !temp_token_valid (evidence->token))
    return WYRELOG_E_POLICY;
  g_autofree gchar *name = NULL;
  g_mutex_lock (&l->mutex);
  wyrelog_error_t r = lease_revalidate_unlocked (l);
  if (r != WYRELOG_E_OK)
    goto done;
  if (evidence->directory_device != l->directory_device
      || evidence->directory_inode != l->directory_inode
      || evidence->lock_device != l->lock_device
      || evidence->lock_inode != l->lock_inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  name = g_strdup_printf ("tmp-%s", evidence->token);
  struct stat artifact;
  if (fstatat (l->namespace_->fd, name, &artifact, AT_SYMLINK_NOFOLLOW) != 0) {
    r = errno == ENOENT ? WYRELOG_E_OK : WYRELOG_E_IO;
    goto done;
  }
  if (!S_ISREG (artifact.st_mode) || artifact.st_nlink != 1
      || (guint64) artifact.st_dev != evidence->artifact_device
      || (guint64) artifact.st_ino != evidence->artifact_inode) {
    r = WYRELOG_E_POLICY;
    goto done;
  }
  if (unlinkat (l->namespace_->fd, name, 0) != 0) {
    r = errno == ENOENT ? WYRELOG_E_OK : WYRELOG_E_IO;
    r = post_mutation_check_unlocked (l, r);
    goto done;
  }
  r = !namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RECOVER_DIRECTORY_FSYNC)
      && fsync (l->namespace_->fd) == 0 ? WYRELOG_E_OK : WYRELOG_E_IO;
  r = post_mutation_check_unlocked (l, r);
  if (fstatat (l->namespace_->fd, name, &artifact, AT_SYMLINK_NOFOLLOW) == 0
      || errno != ENOENT)
    r = WYRELOG_E_POLICY;
done:
  g_mutex_unlock (&l->mutex);
  return r;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_unlink (WylFactArtifactMutationLease *l,
    WylFactArtifactName a)
{
  if (!valid (a))
    return WYRELOG_E_INVALID;
  (void) l;
  /* Main/lock and fixed sidecars have no generic unlink authority.  Temporary
   * lifecycle uses TempBinding; sidecar publication/replacement uses its
   * dedicated binding. */
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_mutation_lease_rename (WylFactArtifactMutationLease *l,
    WylFactArtifactName source, WylFactArtifactName destination)
{
  if (!valid (source) || !valid (destination) || source == destination)
    return WYRELOG_E_INVALID;
  (void) l;
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_namespace_sync_directory (WylFactArtifactNamespace *n)
{
  if (check (n) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  return fsync (n->fd) == 0 && check (n) == WYRELOG_E_OK
      ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static WylFactDuckdbTempRoot *
duckdb_temp_root_ref (WylFactDuckdbTempRoot *root)
{
  if (root)
    g_atomic_int_inc (&root->references);
  return root;
}

static void
duckdb_temp_root_unref (WylFactDuckdbTempRoot *root)
{
  if (!root || !g_atomic_int_dec_and_test (&root->references))
    return;
  if (root->fd >= 0)
    close (root->fd);
  g_clear_pointer (&root->children, g_ptr_array_unref);
  wyl_fact_artifact_mutation_lease_free (root->lease);
  g_free (root->name);
  g_free (root->logical_name);
  g_free (root);
}

static WylFactDuckdbTempChild *
duckdb_temp_child_ref (WylFactDuckdbTempChild *child)
{
  if (child)
    g_atomic_int_inc (&child->references);
  return child;
}

static gboolean
duckdb_temp_child_name_is_valid (const gchar *name)
{
  static const gchar storage[] = "duckdb_temp_storage_";
  static const gchar block[] = "duckdb_temp_block-";
  const gchar *p;
  if (!name || strchr (name, '/') || strchr (name, '\\'))
    return FALSE;
  if (g_str_has_prefix (name, storage)) {
    p = name + strlen (storage);
    if (g_str_has_prefix (p, "DEFAULT"))
      p += strlen ("DEFAULT");
    else {
      static const gchar *const classes[] = {
        "S32K", "S64K", "S96K", "S128K", "S160K", "S192K", "S224K",
      };
      gboolean matched = FALSE;
      for (guint i = 0; i < G_N_ELEMENTS (classes); i++)
        if (g_str_has_prefix (p, classes[i])) {
          p += strlen (classes[i]);
          matched = TRUE;
          break;
        }
      if (!matched)
        return FALSE;
    }
    if (*p++ != '-')
      return FALSE;
    const gchar *digits = p;
    while (g_ascii_isdigit (*p))
      p++;
    return p != digits && (digits[0] == '0' ? p == digits + 1 :
        digits[0] != '0' && (p - digits) <= 20) && g_strcmp0 (p, ".tmp") == 0;
  }
  if (!g_str_has_prefix (name, block))
    return FALSE;
  p = name + strlen (block);
  const gchar *digits = p;
  while (g_ascii_isdigit (*p))
    p++;
  return p != digits && (digits[0] == '0' ? p == digits + 1 :
      digits[0] != '0' && (p - digits) <= 20) && g_strcmp0 (p, ".block") == 0;
}

static gboolean
duckdb_temp_storage_name_is_valid (const gchar *name)
{
  return duckdb_temp_child_name_is_valid (name)
      && g_str_has_prefix (name, "duckdb_temp_storage_");
}

static wyrelog_error_t
duckdb_temp_set_orphan_evidence (const gchar *logical_name,
    WylFactDuckdbTempOrphanEvidence **out_evidence)
{
  WylFactDuckdbTempOrphanEvidence *e = g_new0
      (WylFactDuckdbTempOrphanEvidence, 1);
  if (!e)
    return WYRELOG_E_NOMEM;
  e->logical_name = g_strdup (logical_name);
  if (!e->logical_name) {
    g_free (e);
    return WYRELOG_E_NOMEM;
  }
  *out_evidence = e;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
duckdb_temp_root_matches_unlocked (WylFactDuckdbTempRoot *root)
{
  struct stat held, named;
  WylFactArtifactMutationLease *lease = root ? root->lease : NULL;
  if (!root || !root->active || !lease || !lease->exclusive
      || lease_revalidate_unlocked (lease) != WYRELOG_E_OK
      || root->fd < 0 || fstat (root->fd, &held) != 0
      || !S_ISDIR (held.st_mode) || (held.st_mode & 07777) != 0700
      || (guint64) held.st_uid != lease->namespace_->owner
      || (guint64) held.st_dev != root->device
      || (guint64) held.st_ino != root->inode
      || fstatat (lease->namespace_->fd, root->name, &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR (named.st_mode)
      || (named.st_mode & 07777) != 0700
      || (guint64) named.st_uid != lease->namespace_->owner
      || (guint64) named.st_dev != root->device
      || (guint64) named.st_ino != root->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t duckdb_temp_root_audit_unlocked
    (WylFactDuckdbTempRoot * root);

/* Creation is not reported until the parent-directory durability barrier has
 * completed.  If a later check fails, the freshly minted entry is still held
 * by exact identity and can therefore be retired without adopting a name. */
static wyrelog_error_t
duckdb_temp_root_discard_unpublished_unlocked (WylFactDuckdbTempRoot *root)
{
  WylFactArtifactMutationLease *lease = root->lease;
  if (duckdb_temp_root_matches_unlocked (root) != WYRELOG_E_OK
      || duckdb_temp_root_audit_unlocked (root) != WYRELOG_E_OK
      || (root->children && root->children->len != 0))
    return WYRELOG_E_POLICY;
  if (unlinkat (lease->namespace_->fd, root->name, AT_REMOVEDIR) != 0)
    return errno == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  root->active = FALSE;
  return fsync (lease->namespace_->fd) == 0
      && lease_revalidate_unlocked (lease) == WYRELOG_E_OK
      ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
duckdb_temp_child_matches_unlocked (WylFactDuckdbTempChild *child)
{
  struct stat held, named;
  if (!child || !child->active || !child->root
      || duckdb_temp_root_matches_unlocked (child->root) != WYRELOG_E_OK
      || child->pin_fd < 0 || fstat (child->pin_fd, &held) != 0
      || !S_ISREG (held.st_mode) || held.st_nlink != 1
      || (held.st_mode & 07777) != 0600
      || (guint64) held.st_uid != child->root->lease->namespace_->owner
      || (guint64) held.st_dev != child->device
      || (guint64) held.st_ino != child->inode
      || fstatat (child->root->fd, child->name, &named,
          AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG (named.st_mode)
      || named.st_nlink != 1 || (named.st_mode & 07777) != 0600
      || (guint64) named.st_uid != child->root->lease->namespace_->owner
      || (guint64) named.st_dev != child->device
      || (guint64) named.st_ino != child->inode)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static void
duckdb_temp_child_binding_revoke_unlocked (WylFactDuckdbTempChildBinding *b)
{
  if (!b)
    return;
  b->active = FALSE;
  b->io_open = FALSE;
  b->working_fd = -1;
  if (b->child)
    b->child->io_revoked = TRUE;
}

static wyrelog_error_t
duckdb_temp_child_binding_revalidate_unlocked (WylFactDuckdbTempChildBinding *b)
{
  if (!b || !b->active || !b->child)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = duckdb_temp_child_matches_unlocked (b->child);
  if (result == WYRELOG_E_OK)
    result = duckdb_temp_root_audit_unlocked (b->child->root);
  if (result != WYRELOG_E_OK)
    duckdb_temp_child_binding_revoke_unlocked (b);
  return result;
}

static wyrelog_error_t
duckdb_temp_child_binding_revalidate_fd_unlocked (WylFactDuckdbTempChildBinding
    *b, gint fd)
{
  if (!b || !b->active)
    return WYRELOG_E_POLICY;
  wyrelog_error_t result = duckdb_temp_child_binding_revalidate_unlocked (b);
  struct stat st;
  if (result == WYRELOG_E_OK && (!b->io_open || fd < 0 || fd != b->working_fd
          || fstat (fd, &st) != 0 || !S_ISREG (st.st_mode) || st.st_nlink != 1
          || (st.st_mode & 07777) != 0600
          || (guint64) st.st_uid != b->child->root->lease->namespace_->owner
          || (guint64) st.st_dev != b->child->device
          || (guint64) st.st_ino != b->child->inode))
    result = WYRELOG_E_POLICY;
  if (result != WYRELOG_E_OK)
    duckdb_temp_child_binding_revoke_unlocked (b);
  return result;
}

/* A live descriptor blocks namespace mutation.  We validate it instead of
 * trusting its number: raw close/reuse is terminal and still performs no
 * unlink, leaving the foreign descriptor untouched. */
static wyrelog_error_t
duckdb_temp_child_io_barrier_unlocked (WylFactDuckdbTempChild *child)
{
  if (child && (child->io_revoked || child->unowned_io_terminal))
    return WYRELOG_E_POLICY;
  gboolean live = FALSE;
  for (guint i = 0; child && child->bindings && i < child->bindings->len; i++) {
    WylFactDuckdbTempChildBinding *b = g_ptr_array_index (child->bindings, i);
    if (!b || !b->active)
      continue;
    if (b->io_open) {
      live = TRUE;
      if (duckdb_temp_child_binding_revalidate_fd_unlocked (b,
              b->working_fd) != WYRELOG_E_OK)
        continue;
    }
  }
  return live ? WYRELOG_E_POLICY : WYRELOG_E_OK;
}

static wyrelog_error_t
duckdb_temp_child_discard_unpublished_unlocked (WylFactDuckdbTempChild *child)
{
  WylFactDuckdbTempRoot *root = child->root;
  if (duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  if (unlinkat (root->fd, child->name, 0) != 0)
    return errno == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  child->active = FALSE;
  if (child->pin_fd >= 0) {
    close (child->pin_fd);
    child->pin_fd = -1;
  }
  return fsync (root->fd) == 0
      && duckdb_temp_root_audit_unlocked (root) == WYRELOG_E_OK
      ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static WylFactDuckdbTempChild *
duckdb_temp_find_child (WylFactDuckdbTempRoot *root, const gchar *name)
{
  for (guint i = 0; root && root->children && i < root->children->len; i++) {
    WylFactDuckdbTempChild *child = g_ptr_array_index (root->children, i);
    if (child->active && g_strcmp0 (child->name, name) == 0)
      return child;
  }
  return NULL;
}

/* A mutation never acts on a partially understood directory.  DuckDB's broad
 * cleanup observation is not authority: one foreign entry poisons the whole
 * root before any unlink/create/rmdir can linearize. */
static wyrelog_error_t
duckdb_temp_root_audit_unlocked (WylFactDuckdbTempRoot *root)
{
  if (duckdb_temp_root_matches_unlocked (root) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  gint fd = openat (root->fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC
      | O_NOFOLLOW);
  DIR *dir = fd >= 0 ? fdopendir (fd) : NULL;
  if (!dir) {
    if (fd >= 0)
      close (fd);
    return WYRELOG_E_IO;
  }
  wyrelog_error_t result = WYRELOG_E_OK;
  errno = 0;
  for (struct dirent * entry; (entry = readdir (dir)) != NULL;) {
    if (g_strcmp0 (entry->d_name, ".") == 0
        || g_strcmp0 (entry->d_name, "..") == 0)
      continue;
    WylFactDuckdbTempChild *child =
        duckdb_temp_find_child (root, entry->d_name);
    if (!duckdb_temp_child_name_is_valid (entry->d_name) || !child
        || duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK) {
      result = WYRELOG_E_POLICY;
      break;
    }
  }
  if (errno && result == WYRELOG_E_OK)
    result = WYRELOG_E_IO;
  if (closedir (dir) != 0 && result == WYRELOG_E_OK)
    result = WYRELOG_E_IO;
  /* Directory enumeration alone cannot observe an externally removed bound
   * child.  Every live binding must still name its exact identity too. */
  if (result == WYRELOG_E_OK)
    for (guint i = 0; root->children && i < root->children->len; i++) {
      WylFactDuckdbTempChild *child = g_ptr_array_index (root->children, i);
      if (child->active
          && duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK) {
        result = WYRELOG_E_POLICY;
        break;
      }
    }
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create (WylFactArtifactMutationLease *lease,
    WylFactDuckdbTempRoot **out_root)
{
  (void) lease;
  if (out_root)
    *out_root = NULL;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyl_fact_duckdb_temp_root_create_with_orphan_evidence
    (WylFactArtifactMutationLease * lease, WylFactDuckdbTempRoot ** out_root,
    WylFactDuckdbTempOrphanEvidence ** out_evidence) {
  if (out_root)
    *out_root = NULL;
  if (out_evidence)
    *out_evidence = NULL;
  if (!lease || !out_root || !out_evidence || !lease->exclusive)
    return WYRELOG_E_INVALID;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = lease_revalidate_unlocked (lease);
  wyl_id_t id;
  gchar uuid[WYL_ID_STRING_BUF];
  if (result == WYRELOG_E_OK)
    result = wyl_id_new (&id);
  if (result == WYRELOG_E_OK)
    result = wyl_id_format (&id, uuid, sizeof uuid);
  g_autofree gchar *name = result == WYRELOG_E_OK
      ? g_strdup_printf (".duckdb-private-temp-%s", uuid) : NULL;
  if (result == WYRELOG_E_OK && !name)
    result = WYRELOG_E_NOMEM;
  if (result != WYRELOG_E_OK)
    goto done;
  if (mkdirat (lease->namespace_->fd, name, 0700) != 0) {
    result = errno == EEXIST ? WYRELOG_E_BUSY : WYRELOG_E_IO;
    goto done;
  }
  gint fd = openat (lease->namespace_->fd, name,
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_PRE_IDENTITY)
      || fd < 0 || fstat (fd, &st) != 0) {
    if (fd >= 0)
      close (fd);
    g_autofree gchar *logical_name = g_strdup_printf ("wyrelog-duckdb-temp:%s",
        uuid);
    if (!logical_name || duckdb_temp_set_orphan_evidence (logical_name,
            out_evidence) != WYRELOG_E_OK) {
      result = WYRELOG_E_NOMEM;
      goto done;
    }
    result = WYRELOG_E_POLICY;
    goto done;
  }
  WylFactDuckdbTempRoot temporary = {
    .lease = lease,
    .fd = fd,
    .name = name,
    .device = st.st_dev,
    .inode = st.st_ino,
    .active = TRUE,
  };
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_OPEN_IDENTITY)
      || !S_ISDIR (st.st_mode)
      || (st.st_mode & 07777) != 0700 || st.st_uid != geteuid ()) {
    wyrelog_error_t discard = duckdb_temp_root_discard_unpublished_unlocked
        (&temporary);
    close (fd);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  WylFactDuckdbTempRoot *root = g_new0 (WylFactDuckdbTempRoot, 1);
  if (!root) {
    wyrelog_error_t discard = duckdb_temp_root_discard_unpublished_unlocked
        (&temporary);
    close (fd);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_NOMEM;
    goto done;
  }
  root->references = 1;
  root->lease = mutation_lease_ref (lease);
  root->fd = fd;
  root->name = g_steal_pointer (&name);
  root->logical_name = g_strdup_printf ("wyrelog-duckdb-temp:%s", uuid);
  root->device = st.st_dev;
  root->inode = st.st_ino;
  root->active = TRUE;
  root->children = g_ptr_array_new ();
  if (!root->logical_name || !root->children
      || namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_MKDIR)
      || fsync (lease->namespace_->fd) != 0
      || duckdb_temp_root_audit_unlocked (root) != WYRELOG_E_OK) {
    wyrelog_error_t discard = root->children
        ? duckdb_temp_root_discard_unpublished_unlocked (root)
        : WYRELOG_E_POLICY;
    duckdb_temp_root_unref (root);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  *out_root = root;
  result = WYRELOG_E_OK;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

void
wyl_fact_duckdb_temp_orphan_evidence_free (WylFactDuckdbTempOrphanEvidence *e)
{
  if (!e)
    return;
  g_free (e->logical_name);
  g_free (e);
}

gchar *wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name
    (const WylFactDuckdbTempOrphanEvidence * e)
{
  return e ? g_strdup (e->logical_name) : NULL;
}

void
wyl_fact_duckdb_temp_root_free (WylFactDuckdbTempRoot *root)
{
  duckdb_temp_root_unref (root);
}

gchar *
wyl_fact_duckdb_temp_root_dup_logical_name (WylFactDuckdbTempRoot *root)
{
  if (!root)
    return NULL;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  gchar *copy = duckdb_temp_root_audit_unlocked (root) == WYRELOG_E_OK
      ? g_strdup (root->logical_name) : NULL;
  g_mutex_unlock (&lease->mutex);
  return copy;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_child_exists (WylFactDuckdbTempRoot *root,
    const gchar *name, gboolean *out_exists)
{
  if (out_exists)
    *out_exists = FALSE;
  if (!root || !name || !out_exists || !duckdb_temp_child_name_is_valid (name))
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_root_audit_unlocked (root);
  if (result == WYRELOG_E_OK) {
    WylFactDuckdbTempChild *child = duckdb_temp_find_child (root, name);
    if (child)
      *out_exists = TRUE;
  }
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_foreach_child (WylFactDuckdbTempRoot *root,
    WylFactDuckdbTempChildVisitor visitor, gpointer data)
{
  if (!root || !visitor)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_root_audit_unlocked (root);
  GPtrArray *snapshot = NULL;
  if (result == WYRELOG_E_OK) {
    snapshot = g_ptr_array_new_with_free_func ((GDestroyNotify)
        wyl_fact_duckdb_temp_child_free);
    if (!snapshot)
      result = WYRELOG_E_NOMEM;
  }
  if (result == WYRELOG_E_OK)
    for (guint i = 0; i < root->children->len; i++) {
      WylFactDuckdbTempChild *child = g_ptr_array_index (root->children, i);
      if (!child->active) {
        result = WYRELOG_E_POLICY;
        break;
      }
      g_ptr_array_add (snapshot, duckdb_temp_child_ref (child));
    }
  g_mutex_unlock (&lease->mutex);
  if (result == WYRELOG_E_OK)
    for (guint i = 0; i < snapshot->len; i++) {
      WylFactDuckdbTempChild *child = g_ptr_array_index (snapshot, i);
      if (!visitor (child, child->name, data)) {
        result = WYRELOG_E_POLICY;
        break;
      }
    }
  g_clear_pointer (&snapshot, g_ptr_array_unref);
  return result;
}

gchar *
wyl_fact_duckdb_temp_child_dup_logical_name (WylFactDuckdbTempChild *child)
{
  if (!child)
    return NULL;
  WylFactArtifactMutationLease *lease = child->root->lease;
  g_mutex_lock (&lease->mutex);
  gchar *copy = duckdb_temp_child_matches_unlocked (child) == WYRELOG_E_OK
      ? g_strdup (child->name) : NULL;
  g_mutex_unlock (&lease->mutex);
  return copy;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_create_child (WylFactDuckdbTempRoot *root,
    const gchar *name, WylFactDuckdbTempChild **out_child, gint *out_fd)
{
  (void) root;
  (void) name;
  if (out_child)
    *out_child = NULL;
  if (out_fd)
    *out_fd = -1;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
    (WylFactDuckdbTempRoot * root, const gchar * name,
    WylFactDuckdbTempChild ** out_child, gint * out_fd,
    WylFactDuckdbTempOrphanEvidence ** out_evidence)
{
  if (out_child)
    *out_child = NULL;
  if (out_fd)
    *out_fd = -1;
  if (out_evidence)
    *out_evidence = NULL;
  if (!root || !out_child || !out_fd || !out_evidence
      || !duckdb_temp_child_name_is_valid (name))
    return WYRELOG_E_INVALID;
  /* DuckDB 1.5.5 evidence shows block names only under FileExists.  Do not
   * manufacture lifecycle authority from that observation. */
  if (!duckdb_temp_storage_name_is_valid (name))
    return WYRELOG_E_POLICY;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_root_matches_unlocked (root);
  if (result == WYRELOG_E_OK)
    result = duckdb_temp_root_audit_unlocked (root);
  if (result != WYRELOG_E_OK)
    goto done;
  if (duckdb_temp_find_child (root, name)) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  gint fd = openat (root->fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC
      | O_NOFOLLOW, 0600);
  if (fd < 0) {
    result = errno == EEXIST ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  struct stat st;
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_PRE_IDENTITY)
      || fstat (fd, &st) != 0) {
    close (fd);
    g_autofree gchar *logical_name = g_strdup_printf ("%s/%s",
        root->logical_name, name);
    result = logical_name ? duckdb_temp_set_orphan_evidence (logical_name,
        out_evidence) : WYRELOG_E_NOMEM;
    if (result == WYRELOG_E_OK)
      result = WYRELOG_E_POLICY;
    goto done;
  }
  WylFactDuckdbTempChild temporary = {
    .root = root,
    .pin_fd = fd,
    .name = (gchar *) name,
    .device = st.st_dev,
    .inode = st.st_ino,
    .active = TRUE,
  };
  if (namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_OPEN_IDENTITY)
      || !S_ISREG (st.st_mode) || st.st_nlink != 1
      || (st.st_mode & 07777) != 0600 || st.st_uid != geteuid ()) {
    wyrelog_error_t discard = duckdb_temp_child_discard_unpublished_unlocked
        (&temporary);
    if (temporary.pin_fd >= 0)
      close (temporary.pin_fd);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  WylFactDuckdbTempChild *child = g_new0 (WylFactDuckdbTempChild, 1);
  if (!child || !(child->name = g_strdup (name))) {
    g_free (child);
    wyrelog_error_t discard = duckdb_temp_child_discard_unpublished_unlocked
        (&temporary);
    if (temporary.pin_fd >= 0)
      close (temporary.pin_fd);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_NOMEM;
    goto done;
  }
  child->references = 1;
  child->root = duckdb_temp_root_ref (root);
  child->pin_fd = duplicate_cloexec (fd);
  child->device = st.st_dev;
  child->inode = st.st_ino;
  child->active = child->pin_fd >= 0;
  child->bindings = g_ptr_array_new ();
  if (child->active)
    g_ptr_array_add (root->children, child);
  if (!child->active || !child->bindings
      || namespace_fault_take
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_CREATE)
      || fsync (fd) != 0 || fsync (root->fd) != 0
      || duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK
      || duckdb_temp_root_audit_unlocked (root) != WYRELOG_E_OK) {
    wyrelog_error_t discard = child->active
        ? duckdb_temp_child_discard_unpublished_unlocked (child)
        : WYRELOG_E_POLICY;
    wyl_fact_duckdb_temp_child_free (child);
    close (fd);
    result = discard == WYRELOG_E_POLICY ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  *out_child = child;
  *out_fd = fd;
  result = WYRELOG_E_OK;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_open (WylFactDuckdbTempChild *child,
    gboolean writable, gint *out_fd)
{
  if (out_fd)
    *out_fd = -1;
  if (!child || !out_fd)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_matches_unlocked (child);
  if (result == WYRELOG_E_OK)
    result = duckdb_temp_root_audit_unlocked (child->root);
  if (result != WYRELOG_E_OK)
    goto done;
  gint fd = openat (child->root->fd, child->name,
      (writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    result = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
    goto done;
  }
  struct stat st;
  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode) || st.st_nlink != 1
      || (guint64) st.st_dev != child->device
      || (guint64) st.st_ino != child->inode
      || duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK) {
    close (fd);
    result = WYRELOG_E_POLICY;
    goto done;
  }
  *out_fd = fd;
  result = WYRELOG_E_OK;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_list_children (WylFactDuckdbTempRoot *root,
    GPtrArray **out_children)
{
  if (out_children)
    *out_children = NULL;
  if (!root || !out_children)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_root_matches_unlocked (root);
  if (result == WYRELOG_E_OK)
    result = duckdb_temp_root_audit_unlocked (root);
  GPtrArray *listed = NULL;
  if (result != WYRELOG_E_OK)
    goto done;
  /* dup() shares a directory stream offset with root->fd.  A fresh relative
   * open makes every audit start at the first entry and prevents an earlier
   * list from hiding later foreign children. */
  gint scan_fd = openat (root->fd, ".",
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  DIR *dir = scan_fd >= 0 ? fdopendir (scan_fd) : NULL;
  if (!dir) {
    if (scan_fd >= 0)
      close (scan_fd);
    result = WYRELOG_E_IO;
    goto done;
  }
  listed = g_ptr_array_new_with_free_func ((GDestroyNotify)
      wyl_fact_duckdb_temp_child_free);
  if (!listed) {
    closedir (dir);
    result = WYRELOG_E_NOMEM;
    goto done;
  }
  errno = 0;
  for (struct dirent * entry; (entry = readdir (dir)) != NULL;) {
    if (g_strcmp0 (entry->d_name, ".") == 0
        || g_strcmp0 (entry->d_name, "..") == 0)
      continue;
    WylFactDuckdbTempChild *child =
        duckdb_temp_find_child (root, entry->d_name);
    if (!duckdb_temp_child_name_is_valid (entry->d_name) || !child
        || duckdb_temp_child_matches_unlocked (child) != WYRELOG_E_OK) {
      result = WYRELOG_E_POLICY;
      break;
    }
    g_ptr_array_add (listed, duckdb_temp_child_ref (child));
  }
  if (errno != 0 && result == WYRELOG_E_OK)
    result = WYRELOG_E_IO;
  closedir (dir);
  if (result == WYRELOG_E_OK
      && duckdb_temp_root_matches_unlocked (root) != WYRELOG_E_OK)
    result = WYRELOG_E_POLICY;
  if (result != WYRELOG_E_OK) {
    g_clear_pointer (&listed, g_ptr_array_unref);
    goto done;
  }
  *out_children = listed;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

wyrelog_error_t
wyl_fact_duckdb_temp_child_retire (WylFactDuckdbTempChild *child,
    WylFactDuckdbTempRetireResult *out_result)
{
  if (out_result)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  if (!child || !out_result)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = child->root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_child_matches_unlocked (child);
  if (result != WYRELOG_E_OK)
    goto done;
  result = duckdb_temp_root_audit_unlocked (child->root);
  if (result != WYRELOG_E_OK)
    goto done;
  result = duckdb_temp_child_io_barrier_unlocked (child);
  if (result != WYRELOG_E_OK)
    goto done;
  if (fsync (child->pin_fd) != 0) {
    result = WYRELOG_E_IO;
    goto done;
  }
  if (unlinkat (child->root->fd, child->name, 0) != 0) {
    result = errno == ENOENT ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  child->active = FALSE;
  close (child->pin_fd);
  child->pin_fd = -1;
  if (fsync (child->root->fd) != 0)
    result = WYRELOG_E_IO;
  else if (duckdb_temp_root_audit_unlocked (child->root) != WYRELOG_E_OK)
    result = WYRELOG_E_POLICY;
  else
    result = WYRELOG_E_OK;
  *out_result =
      result ==
      WYRELOG_E_OK ? WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED :
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}

void
wyl_fact_duckdb_temp_child_free (WylFactDuckdbTempChild *child)
{
  if (!child || !g_atomic_int_dec_and_test (&child->references))
    return;
  if (child->root && child->root->children)
    g_ptr_array_remove_fast (child->root->children, child);
  if (child->pin_fd >= 0)
    close (child->pin_fd);
  g_clear_pointer (&child->bindings, g_ptr_array_unref);
  duckdb_temp_root_unref (child->root);
  g_free (child->name);
  g_free (child);
}

wyrelog_error_t
wyl_fact_duckdb_temp_root_retire (WylFactDuckdbTempRoot *root,
    WylFactDuckdbTempRetireResult *out_result)
{
  if (out_result)
    *out_result = WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  if (!root || !out_result)
    return WYRELOG_E_INVALID;
  WylFactArtifactMutationLease *lease = root->lease;
  g_mutex_lock (&lease->mutex);
  wyrelog_error_t result = duckdb_temp_root_matches_unlocked (root);
  if (result != WYRELOG_E_OK)
    goto done;
  result = duckdb_temp_root_audit_unlocked (root);
  if (result != WYRELOG_E_OK)
    goto done;
  /* Root retirement is also an I/O boundary: audit every child binding so a
   * raw-close/reuse cannot hide behind an earlier valid sibling binding. */
  for (guint i = 0; i < root->children->len; i++)
    if (duckdb_temp_child_io_barrier_unlocked (g_ptr_array_index
            (root->children, i)) != WYRELOG_E_OK) {
      result = WYRELOG_E_POLICY;
      goto done;
    }
  /* Any active child, including a child externally removed, prevents broad
   * cleanup.  The caller must reconcile its exact binding first. */
  if (root->children->len != 0) {
    result = WYRELOG_E_POLICY;
    goto done;
  }
  if (unlinkat (lease->namespace_->fd, root->name, AT_REMOVEDIR) != 0) {
    result = errno == ENOTEMPTY
        || errno == EEXIST ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto done;
  }
  root->active = FALSE;
  if (fsync (lease->namespace_->fd) != 0)
    result = WYRELOG_E_IO;
  else if (fstatat (lease->namespace_->fd, root->name, &(struct stat) { 0 },
          AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT
      || lease_revalidate_unlocked (lease) != WYRELOG_E_OK)
    result = WYRELOG_E_POLICY;
  else
    result = WYRELOG_E_OK;
  *out_result =
      result ==
      WYRELOG_E_OK ? WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED :
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED;
done:
  g_mutex_unlock (&lease->mutex);
  return result;
}
#endif
