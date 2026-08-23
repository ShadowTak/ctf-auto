"""Optional dependency and runtime capability detection."""
from dataclasses import dataclass
import importlib.util
import shutil


@dataclass(frozen=True)
class Capability:
    name: str
    available: bool
    detail: str
    optional: bool = True

    def as_dict(self):
        return {
            "name": self.name,
            "available": self.available,
            "detail": self.detail,
            "optional": self.optional,
        }


def _module(name, label):
    available = importlib.util.find_spec(name) is not None
    return Capability(name, available,
                      f"{label} available" if available else
                      f"{label} not installed")


def detect_capabilities():
    """Return optional solver/browser capabilities without importing them."""
    result = [
        _module("Crypto", "PyCryptodome"),
        _module("z3", "Z3 constraint solver"),
        _module("sympy", "SymPy number theory"),
        _module("fpylll", "fpylll lattice backend"),
        _module("playwright", "Playwright browser automation"),
        _module("requests", "Requests HTTP backend"),
        _module("PIL", "Pillow image pixel backend"),
    ]
    for name, command in (("nmap", "nmap"), ("tshark", "tshark"),
                          ("curl", "curl"), ("hashcat", "hashcat"),
                          ("john", "john"), ("ffuf", "ffuf"),
                          ("sqlmap", "sqlmap"), ("radare2", "r2"),
                          ("exiftool", "exiftool"),
                          ("tesseract", "tesseract"), ("zbarimg", "zbarimg"),
                          ("steghide", "steghide"), ("zsteg", "zsteg"),
                          ("binwalk", "binwalk"), ("identify", "identify")):
        found = shutil.which(command)
        result.append(Capability(name, bool(found),
                                  f"{command} at {found}" if found else
                                  f"{command} not found"))
    return result


def capability_map():
    return {item.name: item for item in detect_capabilities()}


def missing(names):
    available = capability_map()
    return [name for name in names if name not in available or
            not available[name].available]
