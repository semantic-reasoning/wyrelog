/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-program-private.h"

G_BEGIN_DECLS;

/* Input-size bounds on a rule pack.  They keep the parse and the acceptance
 * check bounded; they are NOT a bound on evaluation cost.  A single two-atom
 * rule over n facts can enumerate n^2 candidate pairs whatever these numbers
 * are (#1213). Existing backend controls do not provide an end-to-end work
 * bound. semantic-reasoning/wirelog#1817 is related control work, not a
 * prerequisite for the finite-domain recursive compiler capability. */
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
  /* The pack holds no rule.  Set by registration, never by the compiler,
   * which accepts an empty pack. */
  WYL_FACT_RULE_PACK_REJECT_EMPTY,
  /* A recursive dependency component contains a negated edge. */
  WYL_FACT_RULE_PACK_REJECT_NEGATIVE_CYCLE,
} wyl_fact_rule_pack_reject_t;

/* Internal language capability, not stored metadata or authorization.
 * Production registration/replay continue to use the acyclic wrappers. */
typedef enum
{
  WYL_FACT_RULE_PACK_ACYCLIC = 0,
  WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
} wyl_fact_rule_pack_mode_t;

typedef struct
{
  wyl_fact_rule_pack_reject_t reason;
  /* 1-based ordinal of the offending rule, counting rules and not lines; 0
   * when the pack as a whole is refused (TOO_LARGE, COMPILE, EMPTY). */
  guint rule_index;
  /* 0 for the head, n for the nth body atom.  Set for SYNTAX,
   * INVALID_CONSTANT, the relation, arity, safety and type reasons. */
  guint atom_index;
  /* CYCLE: every rule on any cycle, ascending; rule_index is the first.
   * NEGATIVE_CYCLE: every rule with an internal edge in the selected bad
   * SCC, ascending and unique. Seed-only rules and other SCCs are excluded.
   * rule_index/atom_index instead identify the first internal negative edge
   * in source rule/body order, so rule_index may differ from cycle_rules[0]. */
  guint *cycle_rules;
  guint n_cycle_rules;
  /* NEGATIVE_CYCLE only: owned resolved identities of that negative edge.
   * Keep namespace and relation separate: both can contain dots. */
  gchar *cycle_head_namespace;
  gchar *cycle_head_relation;
  gchar *cycle_body_namespace;
  gchar *cycle_body_relation;
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

/* As wyl_fact_rule_pack_compile(), and on success also sets @out_canonical,
 * when it is not NULL, to a NULL-terminated array holding each rule's
 * canonical text in rule order: the rule re-rendered in customer names as
 * written, with no spaces or comment, integers in shortest decimal form,
 * booleans as true/false and only \" and \\ escaped.  A canonical rule is
 * one line, valid UTF-8, never longer than its source text, and compiles to
 * the same rendered rule.  Free with g_strfreev(). */
wyrelog_error_t wyl_fact_rule_pack_compile_canonical (const gchar * text,
    gsize text_len, const wyl_fact_graph_program_relation_t * relations,
    gsize n_relations, gchar ** out_rules, gchar *** out_canonical,
    wyl_fact_rule_pack_rejection_t * out_rejection);

void wyl_fact_rule_pack_rejection_clear (wyl_fact_rule_pack_rejection_t *
    rejection);

/* Explicit internal opt-in variant with the same outputs and ownership as
 * compile_canonical(). POSITIVE_RECURSION accepts positive SCCs and stratified
 * negation; an internal negative dependency produces NEGATIVE_CYCLE. All
 * other parsing, schema, type and safety checks remain mandatory. ACYCLIC
 * preserves the old wrappers' contract; unknown modes return E_INVALID.
 * Canonical bytes are independent of mode. This is not production admission
 * activation: callers in registration and replay must stay on the old API
 * until the storage/activation contracts in #1505/#1506 are implemented. */
wyrelog_error_t wyl_fact_rule_pack_compile_with_mode (const gchar * text,
    gsize text_len, const wyl_fact_graph_program_relation_t * relations,
    gsize n_relations, wyl_fact_rule_pack_mode_t mode, gchar ** out_rules,
    gchar *** out_canonical, wyl_fact_rule_pack_rejection_t * out_rejection);

/* Stable snake_case name of a reason, e.g. "rule_pack_cycle". */
const gchar *wyl_fact_rule_pack_reject_name (wyl_fact_rule_pack_reject_t
    reason);

G_END_DECLS;
