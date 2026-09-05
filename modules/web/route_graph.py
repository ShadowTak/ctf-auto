"""Stateful route/attack graph for authorized CTF web scans.

Static discovery produces more useful output when routes, methods, auth state,
and observations are represented together.  This module is intentionally
small and stdlib-only; it does not replace the legacy scanners, it gives them
a shared evidence surface and a safe export format.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import threading
import urllib.parse
from typing import Iterable, Optional

from core import httpx
from core.flag import extract_flags

_SECRET_QUERY = re.compile(
    r"(?i)(token|key|secret|password|passwd|auth|session|sig|signature|jwt)"
    r"$"
)


def _safe_url(url: str) -> str:
    """Redact sensitive query values while retaining route shape."""
    try:
        parsed = urllib.parse.urlsplit(str(url))
        pairs = []
        for key, value in urllib.parse.parse_qsl(parsed.query,
                                                  keep_blank_values=True):
            pairs.append((key, "<redacted>" if _SECRET_QUERY.search(key)
                          else value[:120]))
        query = urllib.parse.urlencode(pairs)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                        parsed.path or "/", query, ""))
    except Exception:
        return str(url)[:500]


def _route_key(url: str, method: str) -> str:
    parsed = urllib.parse.urlsplit(str(url))
    route = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                     parsed.path or "/", "", ""))
    return f"{method.upper()} {route}"


@dataclass
class RouteNode:
    key: str
    url: str
    method: str = "GET"
    status: Optional[int] = None
    content_type: str = ""
    authenticated: bool = False
    depth: int = 0
    tags: set = field(default_factory=set)
    observations: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.key,
            "url": _safe_url(self.url),
            "method": self.method,
            "status": self.status,
            "content_type": self.content_type,
            "authenticated": self.authenticated,
            "depth": self.depth,
            "tags": sorted(self.tags),
            "observations": list(self.observations[-20:]),
        }


@dataclass
class RouteEdge:
    source: str
    target: str
    relation: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "relation": self.relation, "evidence": self.evidence}


class AttackGraph:
    """Thread-safe bounded graph suitable for live UI export."""

    def __init__(self, *, max_nodes=800, max_edges=1600):
        self.max_nodes = max(1, int(max_nodes or 800))
        self.max_edges = max(1, int(max_edges or 1600))
        self._nodes = {}
        self._edges = {}
        self._lock = threading.RLock()

    def add_route(self, url, *, method="GET", status=None, content_type="",
                  authenticated=False, depth=0, tags: Iterable[str] = (),
                  observation=None) -> Optional[RouteNode]:
        if not url:
            return None
        key = _route_key(url, method)
        with self._lock:
            node = self._nodes.get(key)
            if node is None:
                if len(self._nodes) >= self.max_nodes:
                    return None
                node = RouteNode(key, str(url), str(method).upper(), status,
                                 str(content_type or ""), bool(authenticated),
                                 int(depth or 0))
                self._nodes[key] = node
            else:
                if status is not None:
                    node.status = status
                if content_type:
                    node.content_type = str(content_type)
                node.authenticated = node.authenticated or bool(authenticated)
                node.depth = min(node.depth, int(depth or 0))
            node.tags.update(str(tag) for tag in tags if tag)
            if observation:
                text = str(observation)[:240]
                if text not in node.observations:
                    node.observations.append(text)
                    node.observations = node.observations[-20:]
            return node

    def add_edge(self, source, target, *, relation="discovered", evidence="",
                 source_method="GET", target_method="GET") -> Optional[RouteEdge]:
        left = self.add_route(source, method=source_method)
        right = self.add_route(target, method=target_method)
        if left is None or right is None:
            return None
        edge_key = (left.key, right.key, str(relation))
        with self._lock:
            if edge_key in self._edges:
                return self._edges[edge_key]
            if len(self._edges) >= self.max_edges:
                return None
            edge = RouteEdge(left.key, right.key, str(relation), str(evidence)[:240])
            self._edges[edge_key] = edge
            return edge

    def tag(self, url, tag, *, method="GET", observation=None):
        node = self.add_route(url, method=method, tags=(tag,),
                              observation=observation)
        return node

    def mark_auth(self, urls: Iterable[str] = ()):
        with self._lock:
            for node in self._nodes.values():
                if not urls or any(str(url).split("?", 1)[0] ==
                                   node.url.split("?", 1)[0] for url in urls):
                    node.authenticated = True
                    node.tags.add("authenticated")

    def as_dict(self) -> dict:
        with self._lock:
            nodes = [node.as_dict() for node in self._nodes.values()]
            edges = [edge.as_dict() for edge in self._edges.values()]
        nodes.sort(key=lambda item: (item["depth"], item["method"], item["url"]))
        edges.sort(key=lambda item: (item["source"], item["target"], item["relation"]))
        return {
            "nodes": nodes,
            "edges": edges,
            "limits": {"max_nodes": self.max_nodes, "max_edges": self.max_edges},
            "stats": {"nodes": len(nodes), "edges": len(edges),
                      "authenticated_nodes": sum(1 for item in nodes
                                                  if item["authenticated"])},
        }


def record_response(graph: Optional[AttackGraph], url, response, *, method="GET",
                    depth=0, authenticated=False, tags=()):
    """Record a response and return flags found in its body/header metadata."""
    if graph is None:
        return []
    status = getattr(response, "status", None)
    headers = getattr(response, "headers", {}) or {}
    content_type = headers.get("content-type", "")
    body = getattr(response, "text", "") if response is not None else ""
    flags = []
    known, candidates = extract_flags(body or "")
    flags.extend(known + candidates)
    graph.add_route(url, method=method, status=status,
                    content_type=content_type, authenticated=authenticated,
                    depth=depth, tags=tags,
                    observation=(f"HTTP {status}; flags={len(flags)}" if response
                                 is not None else "request failed"))
    return list(dict.fromkeys(flags))


def probe_authenticated(base, paths, *, graph=None, max_paths=48,
                        timeout=8, context=None):
    """Follow a successful login with bounded reads using the learned session.

    The caller must establish authentication first.  This function only sends
    GET requests to same-origin routes and records status/body differences;
    it never guesses or fabricates credentials.
    """
    base = str(base).rstrip("/")
    lines, flags = [], []
    seen = set()
    for raw in paths or ():
        if context is not None and context.cancelled:
            break
        value = str(raw or "").strip()
        if not value:
            continue
        url = value if value.startswith(("http://", "https://")) else \
            base + "/" + value.lstrip("/")
        parsed = urllib.parse.urlsplit(url)
        if parsed.netloc and parsed.netloc != urllib.parse.urlsplit(base).netloc:
            continue
        route = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                         parsed.path or "/", "", parsed.query))
        key = route.split("?", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > max_paths:
            break
        response = httpx.get(route, timeout=timeout)
        if response is None:
            continue
        got = record_response(graph, route, response, authenticated=True,
                              tags=("auth-follow-up",))
        flags.extend(got)
        if response.status in (200, 201, 204):
            lines.append(f"  [auth] GET {parsed.path or '/'} → {response.status} ({len(response.body)}B)")
            if got:
                lines.append(f"  [!] authenticated route exposed flag: {parsed.path or '/'}")
        elif response.status not in (401, 403, 404):
            lines.append(f"  [auth] GET {parsed.path or '/'} → {response.status}")
    return list(dict.fromkeys(lines)), list(dict.fromkeys(flags))
