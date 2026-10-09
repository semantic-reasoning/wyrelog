/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-program-private.h"

G_BEGIN_DECLS;

/* Input-size bounds on a rule pack.  They keep the parse and the acceptance
 * check bounded; they are NOT a bound on evaluation cost.  A single two-atom
 * rule over n facts can enumerate n^2 candidate pairs whatever these numbers
 * are (#1213), and per-query evaluation is bounded only once wirelog enforces
 * an evaluation budget (semantic-reasoning/wirelog#1817). */
#define WYL_FACT_RULE_PACK_MAX_BYTES 65536
#define WYL_FACT_RULE_PACK_MAX_RULES 256
#define WYL_FACT_RULE_PACK_MAX_BODY_ATOMS 16

/* Why a pack was refused.  Appended only: the names below are what an
 * operator sees, and the values may be persisted by a later unit. */
typedef enum
{
  WYL_FACT_RULE_PACK_REJECT_NONE = 0,
  /* The pack is longer than WYL_FACT_RULE_PACK_MAX_BYTES. */
  WYL_FACT_RULE_PACK_REJECT_TOO_LARGE,
  /* More than WYL_FACT_RULE_PACK_MAX_RULES rules. */
  WYL_FACT_RULE_PACK_REJECT_TOO_MANY_RULES,
  /* A rule has more than WYL_FACT_RULE_PACK_MAX_BODY_ATOMS body atoms. */
  WYL_FACT_RULE_PACK_REJECT_TOO_MANY_BODY_ATOMS,
  /* The text is not "head :- body." on one line. */
  WYL_FACT_RULE_PACK_REJECT_SYNTAX,
  /* A constant is out of range, malformed, or carries a control byte. */
  WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT,
  /* An atom names no relation registered for the graph. */
  WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION,
  /* An atom's name matches more than one registered relation. */
  WYL_FACT_RULE_PACK_REJECT_AMBIGUOUS_RELATION,
  /* An atom's argument count differs from its relation's column count. */
  WYL_FACT_RULE_PACK_REJECT_ARITY,
  /* A head argument is '_'. */
  WYL_FACT_RULE_PACK_REJECT_HEAD_WILDCARD,
  /* A head variable occurs in no positive body atom. */
  WYL_FACT_RULE_PACK_REJECT_UNSAFE_HEAD_VARIABLE,
  /* A variable under '!' occurs in no positive body atom. */
  WYL_FACT_RULE_PACK_REJECT_UNSAFE_NEGATED_VARIABLE,
  /* A variable or constant meets columns of different declared types,
   * or a compound variable meets compound columns of two namespaces. */
  WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH,
  /* The rules derive a relation from itself, directly or through others. */
  WYL_FACT_RULE_PACK_REJECT_CYCLE,
  /* The rendered program does not compile.  Never expected after the checks
   * above pass; the parse API carries no message, so no detail exists. */
  WYL_FACT_RULE_PACK_REJECT_COMPILE,
} wyl_fact_rule_pack_reject_t;

typedef struct
{
  wyl_fact_rule_pack_reject_t reason;
  /* 1-based ordinal of the offending rule, counting rules and not lines; 0
   * when the pack as a whole is refused (TOO_LARGE, COMPILE). */
  guint rule_index;
  /* 0 for the head, n for the nth body atom.  Set for SYNTAX,
   * INVALID_CONSTANT, the relation, arity, safety and type reasons. */
  guint atom_index;
  /* CYCLE only: every rule on a cycle, ascending.  rule_index is the first. */
  guint *cycle_rules;
  guint n_cycle_rules;
} wyl_fact_rule_pack_rejection_t;

/* Checks a rule pack against the relations registered for one graph and
 * renders it as wirelog rules.
 *
 * The pack is one rule per line, "head :- body." with '#' starting a comment.
 * An atom is "rel(args)" or "ns.rel(args)"; the name resolves to the one
 * registered relation whose relation name, or "namespace.relation", equals
 * it.  A body atom may be prefixed with '!'.  An argument is a variable
 * (an uppercase ASCII letter, then letters, digits or '_'), '_', a
 * double-quoted string in which only \" and \\ are escapes, a decimal int64,
 * or true/false.
 *
 * @relations must be the relations the graph's program will declare, in
 * customer names.  The checks run in this order and the first failure in rule
 * order is reported: size and syntax over the whole text; then per rule,
 * relation resolution and arity, head wildcards, range restriction, negation
 * safety and type agreement; then acyclicity across the pack; then the full
 * program, as wyl_fact_graph_program_render() builds it, must compile.
 *
 * Returns WYRELOG_E_OK and sets @out_rules to the rendered rules (empty for a
 * pack with no rules), or WYRELOG_E_POLICY with @out_rejection filled.
 * @out_rejection must be cleared with wyl_fact_rule_pack_rejection_clear(). */
wyrelog_error_t wyl_fact_rule_pack_compile (const gchar * text, gsize text_len,
    const wyl_fact_graph_program_relation_t * relations, gsize n_relations,
    gchar ** out_rules, wyl_fact_rule_pack_rejection_t * out_rejection);

void wyl_fact_rule_pack_rejection_clear (wyl_fact_rule_pack_rejection_t *
    rejection);

/* Stable snake_case name of a reason, e.g. "rule_pack_cycle". */
const gchar *wyl_fact_rule_pack_reject_name (wyl_fact_rule_pack_reject_t
    reason);

G_END_DECLS;
