/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-log-private.h"

#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- Section name table -------------------------------------------- */

static const char *const section_names[WYL_LOG_SECTION_LAST_] = {
  [WYL_LOG_SECTION_BOOT] = "BOOT",
  [WYL_LOG_SECTION_POLICY] = "POLICY",
  [WYL_LOG_SECTION_SESSION] = "SESSION",
  [WYL_LOG_SECTION_DECISION] = "DECISION",
  [WYL_LOG_SECTION_AUDIT] = "AUDIT",
  [WYL_LOG_SECTION_IO] = "IO",
  [WYL_LOG_SECTION_GENERAL] = "GENERAL",
};

const char *
wyl_log_section_name (wyl_log_section_t section)
{
  if ((gint) section < 0 || (gint) section >= WYL_LOG_SECTION_LAST_)
    return NULL;
  return section_names[section];
}

gint
wyl_log_section_count (void)
{
  return (gint) WYL_LOG_SECTION_LAST_;
}

/* --- Spec parser --------------------------------------------------- */

static gint
parse_level_token (const char *tok)
{
  if (g_ascii_isdigit ((guchar) tok[0])) {
    gint n = atoi (tok);
    if (n < 0)
      return -1;
    if (n > WYL_LOG_LEVEL_TRACE)
      return WYL_LOG_LEVEL_TRACE;
    return n;
  }
  if (g_ascii_strcasecmp (tok, "none") == 0)
    return WYL_LOG_LEVEL_NONE;
  if (g_ascii_strcasecmp (tok, "error") == 0)
    return WYL_LOG_LEVEL_ERROR;
  if (g_ascii_strcasecmp (tok, "warn") == 0)
    return WYL_LOG_LEVEL_WARN;
  if (g_ascii_strcasecmp (tok, "info") == 0)
    return WYL_LOG_LEVEL_INFO;
  if (g_ascii_strcasecmp (tok, "debug") == 0)
    return WYL_LOG_LEVEL_DEBUG;
  if (g_ascii_strcasecmp (tok, "trace") == 0)
    return WYL_LOG_LEVEL_TRACE;
  return -1;
}

static gint
parse_section_token (const char *tok)
{
  if (strcmp (tok, "*") == 0)
    return -2;
  for (gint i = 0; i < WYL_LOG_SECTION_LAST_; i++) {
    if (g_ascii_strcasecmp (tok, section_names[i]) == 0)
      return i;
  }
  return -1;
}

void
wyl_log_internal_parse_spec (const char *spec,
    gint8 levels[WYL_LOG_SECTION_LAST_])
{
  for (gint i = 0; i < WYL_LOG_SECTION_LAST_; i++)
    levels[i] = (gint8) WYL_LOG_LEVEL_WARN;

  if (spec == NULL || spec[0] == '\0')
    return;

  g_auto (GStrv) entries = g_strsplit (spec, ",", -1);
  for (gint i = 0; entries[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strstrip (g_strdup (entries[i]));
    if (trimmed[0] == '\0')
      continue;
    g_auto (GStrv) parts = g_strsplit (trimmed, ":", 2);
    if (g_strv_length (parts) != 2)
      continue;
    const char *sec_tok = g_strstrip (parts[0]);
    const char *lvl_tok = g_strstrip (parts[1]);
    gint level = parse_level_token (lvl_tok);
    if (level < 0)
      continue;
    gint sec = parse_section_token (sec_tok);
    if (sec == -2) {
      for (gint j = 0; j < WYL_LOG_SECTION_LAST_; j++)
        levels[j] = (gint8) level;
    } else if (sec >= 0) {
      levels[sec] = (gint8) level;
    }
    /* Unknown section silently ignored: an operator typo should not
     * destabilise the daemon. The price is silent miscalibration if a
     * deployed config drifts; documented as such in the K4 design. */
  }
}

/* --- Runtime threshold table + writer install --------------------- */

static GMutex log_mutex;
static gint8 section_levels[WYL_LOG_SECTION_LAST_];
static gsize init_once = 0;

/* File sink state. Protected by sink_mutex; NULL means use stderr. */
static GMutex sink_mutex;
static FILE *log_file_sink = NULL;

static gint
glib_level_to_wyl (GLogLevelFlags level)
{
  if (level & G_LOG_LEVEL_ERROR)
    return WYL_LOG_LEVEL_ERROR;
  if (level & G_LOG_LEVEL_CRITICAL)
    return WYL_LOG_LEVEL_ERROR;
  if (level & G_LOG_LEVEL_WARNING)
    return WYL_LOG_LEVEL_WARN;
  if (level & G_LOG_LEVEL_MESSAGE)
    return WYL_LOG_LEVEL_INFO;
  if (level & G_LOG_LEVEL_INFO)
    return WYL_LOG_LEVEL_INFO;
  if (level & G_LOG_LEVEL_DEBUG)
    return WYL_LOG_LEVEL_DEBUG;
  return WYL_LOG_LEVEL_INFO;
}

static GLogWriterOutput
log_writer (GLogLevelFlags log_level,
    const GLogField *fields, gsize n_fields, gpointer user_data)
{
  (void) user_data;

  wyl_log_section_t section = WYL_LOG_SECTION_GENERAL;
  const char *message = NULL;
  const char *domain = NULL;
  for (gsize i = 0; i < n_fields; i++) {
    if (strcmp (fields[i].key, "WYL_SECTION") == 0) {
      gint s = parse_section_token ((const char *) fields[i].value);
      if (s >= 0)
        section = (wyl_log_section_t) s;
    } else if (strcmp (fields[i].key, "MESSAGE") == 0) {
      message = (const char *) fields[i].value;
    } else if (strcmp (fields[i].key, "GLIB_DOMAIN") == 0) {
      domain = (const char *) fields[i].value;
    }
  }

  /* If the record is not from our domain, defer to GLib's default
   * writer. Embedders that link libwyrelog into a host with its own
   * GLib logging keep their normal behaviour. */
  if (domain == NULL || strcmp (domain, WYL_LOG_DOMAIN) != 0)
    return g_log_writer_default (log_level, fields, n_fields, NULL);

  gint wyl_level = glib_level_to_wyl (log_level);
  gint8 threshold;
  g_mutex_lock (&log_mutex);
  threshold = section_levels[section];
  g_mutex_unlock (&log_mutex);
  if (wyl_level > threshold)
    return G_LOG_WRITER_HANDLED;

  /* Route to WYL_LOG_FILE if open, else stderr. The mutex is
   * module-scope (sink_mutex) so the reload path can swap the fd
   * safely. Process-local only — not async-signal-safe. */
  g_mutex_lock (&sink_mutex);
  FILE *sink = log_file_sink != NULL ? log_file_sink : stderr;
  fprintf (sink, "[wyrelog %s] %s\n",
      section_names[section], message != NULL ? message : "(no message)");
  fflush (sink);
  g_mutex_unlock (&sink_mutex);

  return G_LOG_WRITER_HANDLED;
}

static void
ensure_init (void)
{
  if (g_once_init_enter (&init_once)) {
    g_mutex_init (&log_mutex);
    g_mutex_init (&sink_mutex);
    const char *spec = g_getenv ("WYL_LOG");
    wyl_log_internal_parse_spec (spec, section_levels);

    const char *path = g_getenv ("WYL_LOG_FILE");
    if (path != NULL && path[0] != '\0') {
      FILE *f = fopen (path, "a");
      if (f != NULL) {
        /* fflush() per record in the writer handles ordering;
         * setvbuf line-buffering is redundant and not used. */
        log_file_sink = f;
      } else {
        fprintf (stderr, "[wyrelog WARN] WYL_LOG_FILE=%s unwritable: %s\n",
            path, g_strerror (errno));
      }
    }

    /* g_log_set_writer_func is set-once per process; subsequent calls
     * trigger a one-line GLib warning and are ignored. Embedders that
     * also call it lose to whichever caller wins the race. */
    g_log_set_writer_func (log_writer, NULL, NULL);
    g_once_init_leave (&init_once, 1);
  }
}

void
wyl_log_internal_reconfigure (void)
{
  ensure_init ();

  /* Re-read WYL_LOG spec under log_mutex. */
  const char *spec = g_getenv ("WYL_LOG");
  gint8 new_levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec (spec, new_levels);
  g_mutex_lock (&log_mutex);
  for (gint i = 0; i < WYL_LOG_SECTION_LAST_; i++)
    section_levels[i] = new_levels[i];
  g_mutex_unlock (&log_mutex);

  /* Re-open WYL_LOG_FILE under sink_mutex. fflush() per record in the
   * writer already handles ordering; setvbuf line-buffering is
   * redundant and dropped here. */
  const char *path = g_getenv ("WYL_LOG_FILE");
  g_mutex_lock (&sink_mutex);
  if (log_file_sink != NULL) {
    fclose (log_file_sink);
    log_file_sink = NULL;
  }
  if (path != NULL && path[0] != '\0') {
    FILE *f = fopen (path, "a");
    if (f != NULL) {
      log_file_sink = f;
    } else {
      fprintf (stderr, "[wyrelog WARN] WYL_LOG_FILE=%s unwritable: %s\n",
          path, g_strerror (errno));
    }
  }
  g_mutex_unlock (&sink_mutex);
}

gint
wyl_log_internal_get_section_level (wyl_log_section_t section)
{
  if ((gint) section < 0 || (gint) section >= WYL_LOG_SECTION_LAST_)
    return -1;
  ensure_init ();
  g_mutex_lock (&log_mutex);
  gint level = section_levels[section];
  g_mutex_unlock (&log_mutex);
  return level;
}

void
wyl_log_structured (wyl_log_section_t section,
    GLogLevelFlags level, const char *fmt, ...)
{
  if ((gint) section < 0 || (gint) section >= WYL_LOG_SECTION_LAST_)
    section = WYL_LOG_SECTION_GENERAL;

  ensure_init ();

  va_list ap;
  va_start (ap, fmt);
  g_autofree gchar *msg = g_strdup_vprintf (fmt, ap);
  va_end (ap);

  GLogField fields[3] = {
    {"GLIB_DOMAIN", WYL_LOG_DOMAIN, -1},
    {"WYL_SECTION", section_names[section], -1},
    {"MESSAGE", msg, -1},
  };
  g_log_structured_array (level, fields, G_N_ELEMENTS (fields));
}
