/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include "wyrelog/daemon/http-body-limit-private.h"

typedef struct
{
  GOutputStream parent;
  guint calls;
  gsize accepted;
  gsize step;
  gsize fail_at;
  GIOErrorEnum error;
  gboolean zero;
} LimitOutput;

typedef struct
{
  GOutputStreamClass parent;
} LimitOutputClass;

static void limit_output_pollable_init (GPollableOutputStreamInterface *iface);
G_DEFINE_TYPE_WITH_CODE (LimitOutput, limit_output, G_TYPE_OUTPUT_STREAM,
    G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
    limit_output_pollable_init))

static gboolean
output_ready (GPollableOutputStream *output)
{
  (void) output;
  return TRUE;
}

static gssize
output_write (GPollableOutputStream *output, const void *buffer,
    gsize count, GError **error)
{
  (void) buffer;
  LimitOutput *self = (LimitOutput *) output;
  self->calls++;
  if (self->zero)
    return 0;
  if (self->accepted >= self->fail_at) {
    g_set_error_literal (error, G_IO_ERROR, self->error, "injected write failure");
    return -1;
  }
  gsize written = MIN (count, self->step);
  self->accepted += written;
  return (gssize) written;
}

static void
limit_output_pollable_init (GPollableOutputStreamInterface *iface)
{
  iface->can_poll = output_ready;
  iface->is_writable = output_ready;
  iface->write_nonblocking = output_write;
}

static void
limit_output_class_init (LimitOutputClass *klass)
{
  (void) klass;
}

static void
limit_output_init (LimitOutput *self)
{
  self->step = 2;
  self->fail_at = G_MAXSIZE;
  self->error = G_IO_ERROR_WOULD_BLOCK;
}

static void
check_partial_writes (void)
{
  LimitOutput *output = g_object_new (limit_output_get_type (), NULL);
  g_assert_true (wyl_daemon_http_write_body_limit_response (
        G_OUTPUT_STREAM (output), "abcdefg", 7));
  g_assert_cmpuint (output->calls, ==, 4);
  g_assert_cmpuint (output->accepted, ==, 7);
  g_object_unref (output);
}

static void
check_failed_writes (void)
{
  const GIOErrorEnum errors[] = { G_IO_ERROR_WOULD_BLOCK, G_IO_ERROR_BROKEN_PIPE };
  for (guint i = 0; i < G_N_ELEMENTS (errors); i++) {
    LimitOutput *output = g_object_new (limit_output_get_type (), NULL);
    output->fail_at = 4;
    output->error = errors[i];
    g_assert_false (wyl_daemon_http_write_body_limit_response (
          G_OUTPUT_STREAM (output), "abcdefg", 7));
    g_assert_cmpuint (output->calls, ==, 3);
    g_assert_cmpuint (output->accepted, ==, 4);
    g_object_unref (output);
  }
}

static void
check_zero_and_nonpollable (void)
{
  LimitOutput *output = g_object_new (limit_output_get_type (), NULL);
  output->zero = TRUE;
  g_assert_false (wyl_daemon_http_write_body_limit_response (
        G_OUTPUT_STREAM (output), "abcdefg", 7));
  g_assert_cmpuint (output->calls, ==, 1);
  g_object_unref (output);
  g_autoptr (GOutputStream) base = g_memory_output_stream_new_resizable ();
  g_autoptr (GDataOutputStream) buffered = g_data_output_stream_new (base);
  g_assert_false (G_IS_POLLABLE_OUTPUT_STREAM (buffered));
  g_assert_false (wyl_daemon_http_write_body_limit_response (
        G_OUTPUT_STREAM (buffered), "abcdefg", 7));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/body-limit/partial-writes", check_partial_writes);
  g_test_add_func ("/body-limit/failed-writes", check_failed_writes);
  g_test_add_func ("/body-limit/no-progress", check_zero_and_nonpollable);
  return wyl_test_normalize_exit_status (g_test_run ());
}
