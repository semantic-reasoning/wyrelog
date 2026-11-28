/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/* Exact graph replacement delete guard installed before #1570. */
static const gchar fixture_restore_replacement_delete_guard_sql[] =
    "CREATE TRIGGER IF NOT EXISTS fact_graph_restore_replacement_delete_guard "
    "BEFORE DELETE ON fact_graph_restore_replacements WHEN NOT EXISTS(SELECT 1 FROM "
    "fact_offline_restore_terminal_guard g JOIN fact_offline_restore_receipts r "
    "ON r.operation_uuid=g.operation_uuid JOIN fact_offline_restore_terminal_history h "
    "ON h.operation_uuid=g.operation_uuid AND h.graph_id=OLD.graph_id AND "
    "h.replacement_uuid=OLD.replacement_uuid WHERE g.operation_uuid=OLD.restore_operation_uuid "
    "AND r.terminal_state='committed' AND r.scope='graph') BEGIN "
    "SELECT RAISE(ABORT,'restore replacement is recovery owned'); END;";
