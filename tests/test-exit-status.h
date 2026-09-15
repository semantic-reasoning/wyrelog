/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_TEST_EXIT_STATUS_H
#define WYL_TEST_EXIT_STATUS_H

#include <stdio.h>

/* Failure identity belongs in the diagnostic stream, not in the process
 * status.  The latter is only a success/failure bit at the test boundary. */
static inline int
wyl_test_report_exit_status (const char *file, const char *function,
    int line, int status)
{
  if (status == 0)
    return 0;
  (void) fprintf (stderr,
      "WYRELOG_TEST_FAILURE file=%s function=%s line=%d code=%d\n", file,
      function, line, status);
  (void) fflush (stderr);
  return 1;
}

#define wyl_test_normalize_exit_status(status_expression) \
  wyl_test_report_exit_status (__FILE__, __func__, __LINE__, \
      (status_expression))
#define wyl_test_normalize_exit_status_named(name, status_expression) \
  wyl_test_report_exit_status (__FILE__, (name), __LINE__, \
      (status_expression))

#ifndef _WIN32
#define WYL_TEST_EXIT_CAPTURE_NAME_I(line) wyl_test_exit_status_capture_ ## line
#define WYL_TEST_EXIT_CAPTURE_NAME(line) WYL_TEST_EXIT_CAPTURE_NAME_I (line)

/* Keep these as statement macros: after fork(), the child must call the
 * original async-signal-safe primitive directly, without a helper function. */
#define WYL_TEST__EXIT(status_expression) \
  do { \
    int WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) = (status_expression); \
    if (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) != 0 \
        && WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) % 256 == 0) { \
      WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) = 1; \
    } \
    _Exit (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__)); \
  } while (0)
#define WYL_TEST_EXIT(status_expression) \
  do { \
    int WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) = (status_expression); \
    if (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) != 0 \
        && WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) % 256 == 0) { \
      WYL_TEST_EXIT_CAPTURE_NAME (__LINE__) = 1; \
    } \
    _exit (WYL_TEST_EXIT_CAPTURE_NAME (__LINE__)); \
  } while (0)
#else
#define WYL_TEST__EXIT(status_expression) _Exit (status_expression)
#define WYL_TEST_EXIT(status_expression) _exit (status_expression)
#endif

#endif
