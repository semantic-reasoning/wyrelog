/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Reproduction for #872.
 *
 * Uncrustify's cmt_multi_check_last heuristic removes the leading space from a
 * block comment's continuation lines when the FIRST and LAST lines are the
 * same length, measured from the first non-space character.  The stars are
 * pulled one column left so they no longer line up under the star of the
 * opening slash-star, and the result is idempotent -- so the misaligned form
 * becomes the only fixed point, and under CLAUDE.md's ledger rule the only
 * committable one.
 *
 * The trigger is length equality.  It is NOT line width and NOT comment size:
 * it reproduces at six characters with a single continuation line, and
 * uniform-width comments are stable at every width from 30 to 78 columns.
 * Padding the opener, shortening the text, moving the closing star-slash to
 * its own line, or changing any character count all suppress it by breaking
 * the equality rather than by satisfying a size condition.
 *
 * tools/uncrustify.cfg sets cmt_indent_multi = false to stop it, and
 * tools/check-comment-alignment.sh asserts this file is a fixed point.  That
 * check fails against a config without the option, which is the evidence it
 * has teeth rather than passing vacuously.
 */
static int
block_comment_alignment_fixture (void)
{
  /* The control: two intents really are PENDING before the rename, so a zero
   * count below is the survey failing and not an empty fixture.  This is a
   * seeding check, not a convergence check -- no reconcile pass runs here. */
  return 0;
}
