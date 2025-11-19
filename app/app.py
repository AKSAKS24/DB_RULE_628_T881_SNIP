# app.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any, Iterable, Tuple
import re

app = FastAPI(
    title="Rule 628 — Redirect access to T881/T881T/T882G",
    version="1.0.2"
)

# -----------------------------------------------------------------------------
# Models (aligned with reference: header + findings)
# -----------------------------------------------------------------------------
class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None   # "DirectRead" | "DisallowedWrite"
    severity: Optional[str] = None      # "info" | "warning" | "error"
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None       # full line where issue occurs


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
TARGET_TABLES = ("t881", "t881t", "t882g")

METHOD_MAP = {
    "t881":  "cl_fins_acdoc_util=>get_t881_emu",
    "t881t": "cl_fins_acdoc_util=>get_t881t_emu",
    "t882g": "cl_fins_acdoc_util=>get_t882g_emu",
}

def canon(s: Optional[str]) -> Optional[str]:
    return s.lower() if s else None


def rm_strings_and_comments(src: str) -> str:
    """
    Pragmatic ABAP sanitation:
    - Remove full-line comments: lines starting with '*' in column 1
    - Strip inline comments starting with double quote "
    - Replace string literals '...'(with '' escapes) by spaces of same length
    Keeps offsets stable to preserve line calculations.
    """
    lines = src.splitlines(keepends=True)
    out = []
    for ln in lines:
        if ln.startswith("*"):  # full line comment
            out.append(" " * len(ln))
            continue
        buf = list(ln)
        in_str = False
        i = 0
        while i < len(buf):
            ch = buf[i]
            if ch == "'":
                # toggle string; handle doubled quotes ('')
                if in_str:
                    if i + 1 < len(buf) and buf[i + 1] == "'":
                        i += 2
                        continue
                    else:
                        in_str = False
                else:
                    in_str = True
                i += 1
                continue
            if ch == '"' and not in_str:
                # comment till end of line
                for j in range(i, len(buf)):
                    buf[j] = " "
                break
            if in_str:
                buf[i] = " "  # blank out string content
            i += 1
        out.append("".join(buf))
    return "".join(out)


# ---------------------------------------------------------------------
# HELPER: GET FULL LINE SNIPPET FOR A MATCH (same style as reference)
# ---------------------------------------------------------------------
def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Given a match span (start, end), return the full line in which
    that match occurs (no extra lines).
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1  # right after '\n'

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


# -----------------------------------------------------------------------------
# Regex building blocks (fixed)
# -----------------------------------------------------------------------------
STMT_SELECT_RE = re.compile(r"(?is)\bSELECT\b[^.]*\.", re.DOTALL)
STMT_OPEN_CURSOR_RE = re.compile(r"(?is)\bOPEN\s+CURSOR\b[^.]*\.", re.DOTALL)

# SINGLE named group across both WITH and WITHOUT parentheses
TABLE_NAME_RE = r"(?:t881t?|t882g)"  # t881 OR t881t OR t882g
TABLE_TOKEN = rf"@?\s*\(?\s*(?P<table>{TABLE_NAME_RE})\s*\)?"

FROM_OR_JOIN_TARGET_RE = re.compile(
    rf"(?is)\b(?:FROM|JOIN)\s+{TABLE_TOKEN}\b"
)

WRITE_STMT_RE = re.compile(
    rf"""(?is)
    \b(INSERT|UPDATE|MODIFY)\s+(?:@?\s*\(\s*)?(?P<table1>t881t?|t882g)\s*(?:\)\s*)?[^.]*\.
    |
    \bDELETE\s+(?:FROM\s+)?(?:@?\s*\(\s*)?(?P<table2>t881t?|t882g)\s*(?:\)\s*)?[^.]*\.
    """,
    re.VERBOSE | re.DOTALL,
)


def find_tables_in_select(stmt: str) -> Iterable[Tuple[str, int, int]]:
    for m in FROM_OR_JOIN_TARGET_RE.finditer(stmt):
        tb = canon(m.group("table"))
        if tb in TARGET_TABLES:
            yield tb, m.start(), m.end()


# -----------------------------------------------------------------------------
# Suggestions (unchanged functional behaviour)
# -----------------------------------------------------------------------------
def suggestion_for_read(table: str) -> str:
    method = METHOD_MAP[table]
    if table == "t881":
        return (
            f"Replace direct read of {table.upper()} with {method}.\n\n"
            "Example:\n"
            "  DATA(ls_t881) = VALUE t881( ).\n"
            "  cl_fins_acdoc_util=>get_t881_emu(\n"
            "    EXPORTING iv_rldnr = lv_rldnr\n"
            "    IMPORTING es_t881  = ls_t881\n"
            "    EXCEPTIONS not_found = 1 OTHERS = 2 ).\n"
        )
    if table == "t881t":
        return (
            f"Replace direct read of {table.upper()} with {method}.\n\n"
            "Example:\n"
            "  DATA(ls_t881t) = VALUE t881t( ).\n"
            "  cl_fins_acdoc_util=>get_t881t_emu(\n"
            "    EXPORTING iv_rldnr = lv_rldnr iv_spras = sy-langu\n"
            "    IMPORTING es_t881t = ls_t881t\n"
            "    EXCEPTIONS not_found = 1 OTHERS = 2 ).\n"
        )
    if table == "t882g":
        return (
            f"Replace direct read of {table.upper()} with {method}.\n\n"
            "Example:\n"
            "  DATA(ls_t882g) = VALUE t882g( ).\n"
            "  cl_fins_acdoc_util=>get_t882g_emu(\n"
            "    EXPORTING iv_bukrs = lv_bukrs iv_rldnr = lv_rldnr\n"
            "    IMPORTING es_t882g = ls_t882g\n"
            "    EXCEPTIONS not_found = 1 OTHERS = 2 ).\n"
        )
    return f"Use {method}."


def suggestion_for_write(table: str) -> str:
    return (
        f"Direct writes to {table.upper()} are disallowed in S/4HANA. "
        "These tables are obsolete customizing; redesign to use the supported "
        "configuration/APIs and remove the DML."
    )


# -----------------------------------------------------------------------------
# Scanner (aligned with reference: per-finding line calc + snippet)
# -----------------------------------------------------------------------------
def scan_unit(unit: Unit) -> Unit:
    raw = unit.code or ""
    src = rm_strings_and_comments(raw)
    findings: List[Finding] = []

    base_start = unit.start_line or 0  # block start in full program

    # Helper: build finding with reference-style start/end/snippet
    def build_finding(
        *,
        stmt_start: int,
        stmt_end: int,
        table: str,
        issues_type: str,
        severity: str,
        message: str,
        suggestion: str,
    ) -> Finding:
        # Line within this block (1-based)
        line_in_block = src[:stmt_start].count("\n") + 1

        # Snippet: full line containing the match (from RAW code)
        snippet_line = get_line_snippet(raw, stmt_start, stmt_end)
        snippet_line_count = snippet_line.count("\n") + 1  # usually 1

        # Absolute line numbers
        start_line_abs = base_start + line_in_block
        end_line_abs = base_start + line_in_block + snippet_line_count

        return Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=start_line_abs,
            ending_line=end_line_abs,
            issues_type=issues_type,
            severity=severity,
            message=message,
            suggestion=suggestion,
            snippet=snippet_line.replace("\n", "\\n"),
        )

    # SELECT ... FROM/JOIN ...
    for m in STMT_SELECT_RE.finditer(src):
        stmt = m.group(0)
        s0, s1 = m.start(), m.end()
        for tb, tstart, tend in find_tables_in_select(stmt):
            msg = (
                f"Direct read from {tb.upper()} detected in SELECT. "
                f"Use {METHOD_MAP[tb]} instead of SELECT … FROM {tb.upper()}."
            )
            f = build_finding(
                stmt_start=s0,
                stmt_end=s1,
                table=tb,
                issues_type="DirectRead",
                severity="error",  # same as original rule behaviour
                message=msg,
                suggestion=suggestion_for_read(tb),
            )
            findings.append(f)

    # OPEN CURSOR ... FOR SELECT ...
    for m in STMT_OPEN_CURSOR_RE.finditer(src):
        stmt = m.group(0)
        s0, s1 = m.start(), m.end()
        for tb, tstart, tend in find_tables_in_select(stmt):
            msg = (
                f"Direct read from {tb.upper()} via OPEN CURSOR FOR SELECT. "
                f"Use {METHOD_MAP[tb]} instead."
            )
            f = build_finding(
                stmt_start=s0,
                stmt_end=s1,
                table=tb,
                issues_type="DirectRead",
                severity="error",  # same as original rule behaviour
                message=msg,
                suggestion=suggestion_for_read(tb),
            )
            findings.append(f)

    # INSERT/UPDATE/MODIFY/DELETE ...
    for m in WRITE_STMT_RE.finditer(src):
        s0, s1 = m.start(), m.end()
        tb = canon(m.group("table1") or m.group("table2"))
        if tb and tb in TARGET_TABLES:
            msg = f"Disallowed write to {tb.upper()} detected. Avoid DML on obsolete tables."
            f = build_finding(
                stmt_start=s0,
                stmt_end=s1,
                table=tb,
                issues_type="DisallowedWrite",
                severity="error",  # same as original rule behaviour
                message=msg,
                suggestion=suggestion_for_write(tb),
            )
            findings.append(f)

    # Build response Unit: copy header and attach findings
    out_unit = Unit(**unit.model_dump())
    out_unit.findings = findings
    return out_unit


# -----------------------------------------------------------------------------
# Endpoints (aligned with reference: return Units with findings)
# -----------------------------------------------------------------------------
@app.post("/remediate-array", response_model=List[Unit])
async def scan_rule_array(units: List[Unit]):
    results: List[Unit] = []
    for u in units:
        res = scan_unit(u)
        # keep functional behaviour: only return units that have findings
        if res.findings:
            results.append(res)
    return results


@app.post("/remediate", response_model=Unit)
async def scan_rule_single(unit: Unit):
    return scan_unit(unit)


@app.get("/health")
async def health():
    return {"ok": True, "rule": 628, "version": "1.0.2"}
