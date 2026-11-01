#pragma once

#include <algorithm>
#include <cctype>
#include <session/format.hpp>
#include <session/sqlite.hpp>
#include <string>
#include <string_view>
#include <vector>

/// A normalised description of a database's schema, for asserting that two ways of arriving at one
/// schema agree -- in practice, building from full_schema.sql versus replaying the migrations.
///
/// Comparing sqlite_master.sql text directly does not work: ALTER TABLE ADD COLUMN appends to the
/// *stored* CREATE TABLE text, so a migrated database's DDL differs from a hand-written declaration
/// of the same columns.  The pragmas describe the schema as SQLite understands it, which is what we
/// actually care about.
///
/// The pragmas do not cover everything, though.  CHECK constraints and AUTOINCREMENT have no pragma
/// at all, partial indexes report only that they are partial and not on what, and trigger bodies
/// exist solely as text.  Those are recovered from sqlite_master.sql, normalised for whitespace and
/// comments, which is safe because ALTER TABLE does not rewrite an expression's own text.
namespace session::test {

namespace detail {

    /// Collapses whitespace runs and strips `--` comments, so formatting differences between a
    /// hand-written declaration and one SQLite rewrote do not register as schema differences.
    inline std::string normalise_sql(std::string_view sql) {
        std::string out;
        out.reserve(sql.size());
        bool space_pending = false;
        for (size_t i = 0; i < sql.size(); i++) {
            if (sql[i] == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
                while (i < sql.size() && sql[i] != '\n')
                    i++;
                space_pending = !out.empty();
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(sql[i]))) {
                space_pending = !out.empty();
                continue;
            }
            if (space_pending) {
                out += ' ';
                space_pending = false;
            }
            out += sql[i];
        }
        return out;
    }

    inline std::string uppercase(std::string s) {
        std::ranges::transform(
                s, s.begin(), [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
        return s;
    }

    /// Extracts every CHECK constraint from a CREATE TABLE statement, by balancing parentheses from
    /// the one that opens each `CHECK(`.  Does not attempt to skip string literals, so a CHECK
    /// containing an unbalanced paren inside quotes would confuse it; none does.
    inline std::vector<std::string> extract_checks(std::string_view sql) {
        auto norm = normalise_sql(sql);
        auto upper = uppercase(norm);

        std::vector<std::string> checks;
        for (size_t pos = upper.find("CHECK"); pos != std::string::npos;
             pos = upper.find("CHECK", pos + 1)) {
            auto open = norm.find('(', pos);
            if (open == std::string::npos)
                continue;
            int depth = 0;
            for (size_t i = open; i < norm.size(); i++) {
                if (norm[i] == '(')
                    depth++;
                else if (norm[i] == ')' && --depth == 0) {
                    checks.push_back(norm.substr(open, i - open + 1));
                    break;
                }
            }
        }
        std::ranges::sort(checks);
        return checks;
    }

}  // namespace detail

/// Builds the fingerprint.  The result is deterministic and diffable: on mismatch, Catch2 prints
/// both, and the differing line names the object.
inline std::string schema_fingerprint(sqlite::Connection& c) {
    using namespace session::literals;
    std::string out;

    auto objects = [&](std::string_view type) {
        std::vector<std::pair<std::string, std::string>> rows;
        for (auto [name, sql] : c.prepared_results<std::string, std::optional<std::string>>(
                     "SELECT name, sql FROM sqlite_master WHERE type = ?"
                     " AND name NOT LIKE 'sqlite_%' ORDER BY name",
                     type))
            rows.emplace_back(std::move(name), sql.value_or(""));
        return rows;
    };

    for (const auto& [table, sql] : objects("table")) {
        out += "table {}\n"_format(table);

        for (auto [cid, name, type, notnull, dflt, pk, hidden] :
             c.prepared_results<
                     int64_t,
                     std::string,
                     std::string,
                     int,
                     std::optional<std::string>,
                     int,
                     int>("PRAGMA table_xinfo({})"_format(table)))
            out += "  col {} {} notnull={} default={} pk={} hidden={}\n"_format(
                    name, type, notnull, dflt.value_or("-"), pk, hidden);

        for (const auto& check : detail::extract_checks(sql))
            out += "  check {}\n"_format(check);

        // No pragma reports AUTOINCREMENT, and its sqlite_sequence row is skipped above along with
        // every other internal table.
        if (detail::uppercase(detail::normalise_sql(sql)).find("AUTOINCREMENT") !=
            std::string::npos)
            out += "  autoincrement\n";

        for (auto [id, seq, ref_table, from, to, on_update, on_delete, match] :
             c.prepared_results<
                     int64_t,
                     int64_t,
                     std::string,
                     std::string,
                     std::optional<std::string>,
                     std::string,
                     std::string,
                     std::string>("PRAGMA foreign_key_list({})"_format(table)))
            out += "  fk {} -> {}.{} on_update={} on_delete={}\n"_format(
                    from, ref_table, to.value_or("-"), on_update, on_delete);

        // Indexes are described by their columns rather than their names, because an index implied
        // by a UNIQUE constraint is named positionally (sqlite_autoindex_<table>_N) and those
        // numbers shift if the constraints are declared in a different order.
        std::vector<std::string> indexes;
        for (auto [seq, name, uniq, origin, partial] :
             c.prepared_results<int64_t, std::string, int, std::string, int>(
                     "PRAGMA index_list({})"_format(table))) {
            std::string desc = "  index unique={} origin={} on"_format(uniq, origin);
            for (auto [iseq, cid, col, rev, coll, key] :
                 c.prepared_results<
                         int64_t,
                         int64_t,
                         std::optional<std::string>,
                         int,
                         std::string,
                         int>("PRAGMA index_xinfo({})"_format(name)))
                if (key)
                    desc += " {}{}/{}"_format(col.value_or("<rowid>"), rev ? " DESC" : "", coll);

            if (partial) {
                // index_list only says *that* it is partial; the predicate is in the DDL.
                auto ddl = c.prepared_get<std::optional<std::string>>(
                        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", name);
                auto norm = detail::normalise_sql(ddl.value_or(""));
                if (auto w = norm.find(" WHERE "); w != std::string::npos)
                    desc += " where{}"_format(norm.substr(w + 6));
            }
            indexes.push_back(std::move(desc));
        }
        std::ranges::sort(indexes);
        for (const auto& i : indexes)
            out += i + "\n";
    }

    for (const auto& [name, sql] : objects("trigger"))
        out += "trigger {} {}\n"_format(name, detail::normalise_sql(sql));

    for (const auto& [name, sql] : objects("view"))
        out += "view {} {}\n"_format(name, detail::normalise_sql(sql));

    return out;
}

}  // namespace session::test
