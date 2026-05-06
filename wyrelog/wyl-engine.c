/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyl-engine-private.h"
#include "wyl-common-private.h"

G_STATIC_ASSERT (sizeof (gint64) == sizeof (int64_t));
G_STATIC_ASSERT (sizeof (gint32) == sizeof (int32_t));

/*
 * Fixed dependency order for policy template files.
 *
 * The order is load-bearing: later files may reference relations declared
 * in earlier files. Do not reorder without updating the dependency analysis.
 */
static const char *const TEMPLATE_FILES[] = {
  "bootstrap.dl",
  "fsm/principal.dl",
  "fsm/session.dl",
  "fsm/permission_scope.dl",
  "lobac/decision.dl",
};

G_STATIC_ASSERT (G_N_ELEMENTS (TEMPLATE_FILES) == WYL_ENGINE_TEMPLATE_COUNT);

#define WYL_ENGINE_LOBAC_DECISION_TEMPLATE "lobac/decision.dl"
#define WYL_ENGINE_LEGACY_DECISION_TEMPLATE "decision.dl"

typedef struct
{
  WylTupleCallback cb;
  gpointer user_data;
} wyl_engine_tuple_cookie_t;

struct _WylDeltaCookie
{
  WylDeltaCallback callback;
  gpointer user_data;
};

static void
wyl_engine_tuple_trampoline (const char *relation, const int64_t *row,
    uint32_t ncols, void *user)
{
  const wyl_engine_tuple_cookie_t *cookie = user;

  cookie->cb (relation, (const gint64 *) row, (guint) ncols, cookie->user_data);
}

static gboolean
relation_emits_delta_callback (const char *relation)
{
  if (g_strcmp0 (relation, "guard_row") == 0
      || g_strcmp0 (relation, "guard_cmp_row") == 0
      || g_strcmp0 (relation, "guard_and_row") == 0
      || g_strcmp0 (relation, "perm_window_guard") == 0
      || g_strcmp0 (relation, "perm_window_guard_observed") == 0)
    return FALSE;

  return TRUE;
}

static void
wyl_engine_delta_trampoline (const char *relation, const int64_t *row,
    uint32_t ncols, int32_t diff, void *user)
{
  const WylDeltaCookie *cookie = user;
  WylDeltaKind kind;

  if (!relation_emits_delta_callback (relation))
    return;

  if (diff == 1) {
    kind = WYL_DELTA_INSERT;
  } else if (diff == -1) {
    kind = WYL_DELTA_REMOVE;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: unexpected delta diff value (skipping callback)");
    return;
  }

  cookie->callback (relation, (const gint64 *) row, (guint) ncols, kind,
      cookie->user_data);
}

/* --- GObject boilerplate ------------------------------------------- */

G_DEFINE_FINAL_TYPE (WylEngine, wyl_engine, G_TYPE_OBJECT);

static void
wyl_engine_finalize (GObject *object)
{
  WylEngine *self = WYL_ENGINE (object);

  g_clear_pointer (&self->session, wl_easy_close);
  g_clear_pointer (&self->delta_cookie, g_free);

  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    g_clear_pointer (&self->dl_src_logical_paths[i], g_free);

  G_OBJECT_CLASS (wyl_engine_parent_class)->finalize (object);
}

static void
wyl_engine_class_init (WylEngineClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_engine_finalize;
}

static void
wyl_engine_init (WylEngine *self)
{
  self->session = NULL;
  self->mode = WYL_ENGINE_MODE_NONE;
  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    self->dl_src_logical_paths[i] = NULL;
}

/* --- Internal helpers --------------------------------------------- */

wyrelog_error_t
wyl_engine_map_wirelog_error (wirelog_error_t wl_err)
{
  switch (wl_err) {
    case WIRELOG_OK:
      return WYRELOG_E_OK;
    case WIRELOG_ERR_PARSE:
    case WIRELOG_ERR_INVALID_IR:
      return WYRELOG_E_POLICY;
    case WIRELOG_ERR_EXEC:
      return WYRELOG_E_EXEC;
    case WIRELOG_ERR_MEMORY:
      return WYRELOG_E_NOMEM;
    case WIRELOG_ERR_IO:
      return WYRELOG_E_IO;
    case WIRELOG_ERR_COMPOUND_SATURATED:
    case WIRELOG_ERR_COMPOUND_BUSY:
      return WYRELOG_E_EXEC;
    case WIRELOG_ERR_UNKNOWN:
      return WYRELOG_E_INTERNAL;
    default:
      return WYRELOG_E_INTERNAL;
  }
}

wyrelog_error_t
wyl_engine_load_templates (const gchar *template_dir, gchar **dl_src_out,
    gsize *dl_src_len_out)
{
  g_autoptr (GString) combined = g_string_new (NULL);
  gsize total_content_bytes = 0;

  for (gsize i = 0; i < G_N_ELEMENTS (TEMPLATE_FILES); i++) {
    const gchar *logical_path = TEMPLATE_FILES[i];
    g_autofree gchar *path =
        g_build_filename (template_dir, logical_path, NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    g_autoptr (GError) err = NULL;

    if (!g_file_get_contents (path, &contents, &len, &err)) {
      if (g_strcmp0 (logical_path, WYL_ENGINE_LOBAC_DECISION_TEMPLATE) == 0
          && g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
        g_clear_error (&err);
        g_clear_pointer (&path, g_free);
        path = g_build_filename (template_dir,
            WYL_ENGINE_LEGACY_DECISION_TEMPLATE, NULL);
        logical_path = WYL_ENGINE_LEGACY_DECISION_TEMPLATE;
        if (g_file_get_contents (path, &contents, &len, &err)) {
          WYL_LOG_INFO (WYL_LOG_SECTION_BOOT,
              "loaded legacy decision template: %s", logical_path);
        }
      }
    }

    if (contents == NULL) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
          "missing or unreadable template: %s", TEMPLATE_FILES[i]);
      return WYRELOG_E_IO;
    }

    /* Insert newline between files unconditionally for concat-boundary safety. */
    if (i > 0)
      g_string_append_c (combined, '\n');

    g_string_append_len (combined, contents, (gssize) len);
    total_content_bytes += len;
  }

  /* In-tree invariant: the 5 template files must collectively contain at
   * least one byte of policy content.  A zero total means all files are
   * empty, which is a wyrelog-side invariant violation (not operator-authored
   * bad policy).  Separator newlines inserted above are not counted. */
  if (total_content_bytes == 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_BOOT,
        "engine: invariant violated — in-tree templates produced zero bytes");
    return WYRELOG_E_INTERNAL;
  }

  /* Capture the authoritative byte count before transferring ownership of the
   * underlying buffer.  strlen() must not be used for the subsequent memset
   * because it short-circuits at the first embedded NUL byte. */
  *dl_src_len_out = combined->len;
  *dl_src_out = g_string_free (g_steal_pointer (&combined), FALSE);
  return WYRELOG_E_OK;
}

/* --- Public API ---------------------------------------------------- */

wyrelog_error_t
wyl_engine_open (const gchar *template_dir, guint32 num_workers,
    WylEngine **out)
{
  /* Set out-param to NULL at entry; every failure path leaves it NULL. */
  if (out != NULL)
    *out = NULL;

  if (out == NULL)
    return WYRELOG_E_INVALID;

  if (template_dir == NULL)
    return WYRELOG_E_INVALID;

  gchar *dl_src = NULL;
  gsize dl_src_len = 0;
  wyrelog_error_t rc =
      wyl_engine_load_templates (template_dir, &dl_src, &dl_src_len);
  if (rc != WYRELOG_E_OK)
    return rc;

  wl_easy_open_opts_t opts = {
    .size = sizeof (opts),
    .num_workers = num_workers,
    .eager_build = true,
    ._reserved = NULL,
  };

  wl_easy_session_t *session = NULL;
  wirelog_error_t wl_rc = wl_easy_open_opts (dl_src, &opts, &session);

  /* FC4: zero-fill the policy source buffer before freeing to avoid leaving
   * policy text in core dumps or swap.  Use the tracked length rather than
   * strlen() to ensure every byte — including any tail past an embedded NUL —
   * is overwritten. */
  memset (dl_src, 0, dl_src_len);
  g_free (dl_src);
  dl_src = NULL;

  if (wl_rc != WIRELOG_OK) {
    /* wl_easy_open_opts sets *out to NULL on error per its contract,
     * but be defensive: close any partial session that may have been
     * returned despite the error. */
    if (session != NULL)
      wl_easy_close (session);
    return wyl_engine_map_wirelog_error (wl_rc);
  }

  WylEngine *engine = g_object_new (WYL_TYPE_ENGINE, NULL);
  engine->session = session;
  /* Keep the initial mode explicit instead of relying on zero-fill. */
  engine->mode = WYL_ENGINE_MODE_NONE;

  /* Store logical paths for diagnostic logging. */
  for (gsize i = 0; i < WYL_ENGINE_TEMPLATE_COUNT; i++)
    engine->dl_src_logical_paths[i] = g_strdup (TEMPLATE_FILES[i]);

  *out = engine;
  return WYRELOG_E_OK;
}

void
wyl_engine_close (WylEngine *engine)
{
  if (engine == NULL)
    return;
  g_object_unref (engine);
}

wyrelog_error_t
wyl_engine_intern_symbol (WylEngine *self, const gchar *symbol, gint64 *out_id)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (symbol == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  int64_t id = wl_easy_intern (self->session, symbol);
  if (id < 0) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: symbol interning failed for symbol of length %zu",
        strlen (symbol));
    return WYRELOG_E_INTERNAL;
  }

  *out_id = id;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_make_compound (WylEngine *self, const gchar *functor,
    const wirelog_compound_arg_t *args, gsize nargs, gint64 *out_id)
{
  if (out_id != NULL)
    *out_id = (gint64) WIRELOG_COMPOUND_HANDLE_NULL;

  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (functor == NULL || functor[0] == '\0' || args == NULL || out_id == NULL)
    return WYRELOG_E_INVALID;
  if (nargs == 0 || nargs > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  uint64_t handle = WIRELOG_COMPOUND_HANDLE_NULL;
  wirelog_error_t wl_rc =
      wirelog_easy_make_compound (self->session, functor, (uint32_t) nargs,
      args, &handle);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: compound allocation failed for functor '%s/%" G_GSIZE_FORMAT
        "' (rc=%d)", functor, nargs, (int) rc);
    return rc;
  }

  if (handle == WIRELOG_COMPOUND_HANDLE_NULL || handle > (uint64_t) G_MAXINT64) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: compound allocation returned an invalid handle");
    return WYRELOG_E_INTERNAL;
  }

  *out_id = (gint64) handle;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_insert (WylEngine *self, const gchar *relation, const gint64 *row,
    gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || ncols == 0 || ncols > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (row == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc =
      wl_easy_insert (self->session, relation, (const int64_t *) row,
      (uint32_t) ncols);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: insert failed for relation '%s' with %" G_GSIZE_FORMAT
        " columns", relation, ncols);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_step (WylEngine *self)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_SNAPSHOT)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc = wl_easy_step (self->session);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc == WYRELOG_E_OK) {
    self->mode = WYL_ENGINE_MODE_STEP;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: step failed (rc=%d)", (int) rc);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_snapshot (WylEngine *self, const gchar *relation,
    WylTupleCallback cb, gpointer user_data)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || cb == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_STEP)
    return WYRELOG_E_INVALID;

  wyl_engine_tuple_cookie_t cookie = { cb, user_data };
  wirelog_error_t wl_rc =
      wl_easy_snapshot (self->session, relation, wyl_engine_tuple_trampoline,
      &cookie);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc == WYRELOG_E_OK) {
    self->mode = WYL_ENGINE_MODE_SNAPSHOT;
  } else {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: snapshot failed for relation '%s' (rc=%d)", relation,
        (int) rc);
  }

  return rc;
}

wyrelog_error_t
wyl_engine_set_delta_callback (WylEngine *self, WylDeltaCallback cb,
    gpointer user_data)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;
  if (self->mode == WYL_ENGINE_MODE_SNAPSHOT)
    return WYRELOG_E_INVALID;

  if (cb == NULL) {
    /* Clear the substrate hook before releasing the cookie it may reference. */
    wirelog_error_t wl_rc = wl_easy_set_delta_cb (self->session, NULL, NULL);
    wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
    if (rc != WYRELOG_E_OK) {
      WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
          "engine: clear delta callback failed (rc=%d)", (int) rc);
      return rc;
    }

    g_clear_pointer (&self->delta_cookie, g_free);
    return WYRELOG_E_OK;
  }

  WylDeltaCookie *new_cookie = g_new0 (WylDeltaCookie, 1);
  new_cookie->callback = cb;
  new_cookie->user_data = user_data;

  wirelog_error_t wl_rc =
      wl_easy_set_delta_cb (self->session, wyl_engine_delta_trampoline,
      new_cookie);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    g_free (new_cookie);
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: install delta callback failed (rc=%d)", (int) rc);
    return rc;
  }

  WylDeltaCookie *old = self->delta_cookie;
  self->delta_cookie = new_cookie;
  g_free (old);

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_engine_remove (WylEngine *self, const gchar *relation, const gint64 *row,
    gsize ncols)
{
  if (self == NULL || !WYL_IS_ENGINE (self))
    return WYRELOG_E_INVALID;
  if (relation == NULL || ncols == 0 || ncols > G_MAXUINT32)
    return WYRELOG_E_INVALID;
  if (row == NULL)
    return WYRELOG_E_INVALID;
  if (self->session == NULL)
    return WYRELOG_E_INVALID;

  wirelog_error_t wl_rc =
      wl_easy_remove (self->session, relation, (const int64_t *) row,
      (uint32_t) ncols);
  wyrelog_error_t rc = wyl_engine_map_wirelog_error (wl_rc);
  if (rc != WYRELOG_E_OK) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_POLICY,
        "engine: remove failed for relation '%s' with %" G_GSIZE_FORMAT
        " columns", relation, ncols);
  }

  return rc;
}
