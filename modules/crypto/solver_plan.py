"""Public crypto planning facade."""
from .planner import plan


def describe(text):
    result = plan(text)
    return {"category": "crypto", "jobs": result["jobs"],
            "reasons": result["reasons"]}
