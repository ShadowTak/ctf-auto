"""Public crypto planning facade."""
from .planner import plan


def describe(text):
    result = plan(text)
    return {"category": "crypto", "jobs": result["jobs"],
            "reasons": result["reasons"], "costs": result.get("costs", {}),
            "source_fingerprint": result.get("source_fingerprint", {})}
