"""Offline ELF/PDF triage. Challenge binaries are parsed, never executed."""
import io
import re


def json_evidence(value, depth=0):
    """Bounded JSON representation for packet bytes, tuple keys and sets."""
    if depth > 8:
        return '[evidence depth limit]'
    if isinstance(value, bytes):
        return {'bytes': len(value), 'hex': value[:2048].hex(),
                'text': value[:2048].decode('utf-8', 'replace'),
                'truncated': len(value) > 2048}
    if isinstance(value, dict):
        result = {str(k): json_evidence(v, depth + 1) for k, v in list(value.items())[:200]}
        if len(value) > 200:
            result['_truncated_items'] = len(value) - 200
        return result
    if isinstance(value, (list, tuple, set)):
        result = [json_evidence(v, depth + 1) for v in list(value)[:200]]
        if len(value) > 200:
            result.append({'truncated_items': len(value) - 200})
        return result
    if isinstance(value, str):
        return value[:32768]
    return value if value is None or isinstance(value, (bool, int, float)) else str(value)[:1000]


def inspect_artifact(data):
    result = {"kind": "binary", "details": {}, "texts": [], "hints": []}
    if data.startswith(b"\x7fELF"):
        result["kind"] = "elf"
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            result["hints"].append("Install pyelftools for ELF headers, symbols and mitigations")
            return result
        try:
            elf = ELFFile(io.BytesIO(data))
            segments = list(elf.iter_segments())
            sections = list(elf.iter_sections())
            stack = [s for s in segments if s['p_type'] == 'PT_GNU_STACK']
            relro = any(s['p_type'] == 'PT_GNU_RELRO' for s in segments)
            bind_now = False
            for section in sections:
                if section['sh_type'] == 'SHT_DYNAMIC':
                    for tag in section.iter_tags():
                        bind_now |= (tag.entry.d_tag == 'DT_BIND_NOW' or
                                     (tag.entry.d_tag == 'DT_FLAGS' and bool(tag.entry.d_val & 8)) or
                                     (tag.entry.d_tag == 'DT_FLAGS_1' and bool(tag.entry.d_val & 1)))
            symbols = []
            for section in sections:
                if section['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                    for symbol in section.iter_symbols():
                        if symbol.name and len(symbols) < 4096:
                            symbols.append(symbol.name)
            names = set(symbols)
            result['details'] = {
                'architecture': elf.get_machine_arch(), 'bits': elf.elfclass,
                'endian': 'little' if elf.little_endian else 'big',
                'entry': hex(elf.header.e_entry), 'type': elf.header.e_type,
                'position_independent': elf.header.e_type == 'ET_DYN',
                'nx_stack': not bool(stack[0]['p_flags'] & 1) if stack else None,
                'relro': ('full' if bind_now else 'partial') if relro else 'none',
                'canary_symbol': '__stack_chk_fail' in names,
                'interesting_symbols': sorted(n for n in names if re.search(
                    r'(?i)(win|flag|secret|main|gets|strcpy|system|exec|printf)', n))[:100],
                'stripped': not any(s['sh_type'] == 'SHT_SYMTAB' for s in sections),
            }
            result['hints'].append('ELF metadata is triage evidence; it does not prove exploitability')
        except Exception as exc:
            result['hints'].append('ELF parser: ' + str(exc)[:200])
    elif data.startswith(b'%PDF'):
        result['kind'] = 'pdf'
        try:
            from pypdf import PdfReader
        except ImportError:
            result['hints'].append('Install pypdf for PDF text and metadata extraction')
            return result
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted and not reader.decrypt(''):
                result['hints'].append('Password-protected PDF; provide a decrypted artifact')
                return result
            result['details'] = {'pages': len(reader.pages),
                                 'encrypted': reader.is_encrypted}
            result['texts'].append(('pdf:metadata', str(reader.metadata)[:65536]))
            for index, page in enumerate(reader.pages[:32]):
                result['texts'].append(('pdf:page:' + str(index + 1),
                                        (page.extract_text() or '')[:262144]))
            if len(reader.pages) > 32:
                result['hints'].append('PDF text limited to first 32 pages')
        except Exception as exc:
            result['hints'].append('PDF parser: ' + str(exc)[:200])
    return result
