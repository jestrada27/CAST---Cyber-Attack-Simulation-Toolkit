from flask import Blueprint, jsonify, render_template, request

from castrange.config import state
from castrange.db import get_conn

bp = Blueprint("search", __name__)


def _run_query(q, level):
    conn = get_conn()
    try:
        if level == "easy":
            # V1 SQLi (easy): raw f-string into LIKE
            sql = (
                "SELECT id, name, department, title FROM employees "
                f"WHERE name LIKE '%{q}%'"
            )
            rows = conn.execute(sql).fetchall()
        elif level == "medium":
            # V1 SQLi (medium): naive single-quote doubling
            qq = q.replace("'", "''")
            sql = (
                "SELECT id, name, department, title FROM employees "
                f"WHERE name LIKE '%{qq}%'"
            )
            rows = conn.execute(sql).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, name, department, title FROM employees "
                "WHERE name LIKE ?",
                (f"%{q}%",),
            ).fetchall()
        return [dict(r) for r in rows], None
    except Exception as ex:
        return [], ex
    finally:
        conn.close()


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    cfg = state.get()
    results, ex = _run_query(q, cfg["level"])
    error = None
    if ex is not None:
        # V10 verbose error reflection at easy
        error = f"SQL error: {ex}" if cfg["level"] == "easy" else "Search failed."
    # V2 reflected XSS happens in the template via {{ q|safe }}
    return render_template("search.html", q=q, results=results, error=error)


@bp.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    cfg = state.get()
    results, ex = _run_query(q, cfg["level"])
    if ex is not None:
        if cfg["level"] == "easy":
            return jsonify({"query": q, "error": str(ex)}), 500
        return jsonify({"query": q, "error": "Search failed."}), 500
    return jsonify({"query": q, "results": results})
