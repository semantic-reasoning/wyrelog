/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_TEST_EXIT_STATUS_H
#define WYL_TEST_EXIT_STATUS_H

/* Shells observe only the low byte of a POSIX process status.  Keep a failed
 * test from becoming a success when its status is a nonzero multiple of 256.
 * Windows process exit codes are not subject to this shell truncation. */
static inline int
wyl_test_normalize_exit_status (int status)
{
#ifndef _WIN32
  if (status != 0 && status % 256 == 0)
    return 1;
#endif
  return status;
}

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
