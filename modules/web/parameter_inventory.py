"""Passive, bounded Web input inventory for authorized CTF scans.

This module extracts input surfaces from HTML/JS/OpenAPI responses. It does
not submit payloads, mutate state, or execute browser actions.
"""
import json
import re
from html.parser import HTMLParser


class _Inputs(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": attrs.get("action", ""),
                          "method": attrs.get("method", "GET").upper(),
                          "fields": []}
        elif self._form is not None and tag in {"input", "textarea", "select", "button"}:
            name = attrs.get("name")
            if name and name not in self._form["fields"]:
                self._form["fields"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _walk_json(value, path="$", output=None, depth=0):
    output = output if output is not None else []
    if depth > 8 or len(output) >= 256:
        return output
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(child, (dict, list)):
                _walk_json(child, child_path, output, depth + 1)
            else:
                output.append({"name": str(key), "path": child_path,
                               "type": type(child).__name__})
    elif isinstance(value, list):
        for index, child in enumerate(value[:64]):
            _walk_json(child, f"{path}[{index}]", output, depth + 1)
    return output


def inventory_html(body, page_url=""):
    parser = _Inputs()
    try:
        parser.feed(body or "")
    except Exception:
        pass
    query_params = sorted(set(re.findall(
        r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,63})=", body or "")))
    return {
        "url": page_url,
        "forms": parser.forms,
        "query_params": query_params,
        "field_names": sorted({field for form in parser.forms
                                for field in form["fields"]}),
    }


def inventory_json(body, page_url=""):
    try:
        value = json.loads(body or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"url": page_url, "fields": []}
    return {"url": page_url, "fields": _walk_json(value)}


def inventory_js(body, page_url=""):
    text = body or ""
    names = set()
    for pattern in (
        r"(?:URLSearchParams|params|query|data)\s*[.(]\s*[\"']([A-Za-z_][A-Za-z0-9_.-]{0,63})",
        r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,63})=",
    ):
        names.update(re.findall(pattern, text))
    return {"url": page_url, "field_names": sorted(names)}


def summarize(result):
    """Return compact, JSON-safe workflow metadata for reports/UI."""
    result = result or {}
    return {
        "kind": result.get("kind", "unknown"),
        "url": result.get("url", ""),
        "forms": len(result.get("forms", [])),
        "field_names": list(result.get("field_names", []))[:256],
        "query_params": list(result.get("query_params", []))[:256],
        "json_fields": list(result.get("fields", []))[:256],
    }


def inventory(body, content_type="", page_url=""):
    """Return a normalized passive input inventory."""
    content_type = str(content_type).lower()
    if "json" in content_type or (body or "").lstrip().startswith(("{", "[")):
        result = inventory_json(body, page_url)
        result["kind"] = "json"
        return result
    if "javascript" in content_type:
        result = inventory_js(body, page_url)
        result["kind"] = "javascript"
        return result
    result = inventory_html(body, page_url)
    result["kind"] = "html"
    return result
