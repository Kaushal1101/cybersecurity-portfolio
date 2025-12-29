import re
import base64
from pathlib import Path

def replace_char_hex(s: str) -> str:
    # Replace [char]0xNN with actual character
    def repl(m):
        return chr(int(m.group(1), 16))
    return re.sub(r"\[char\]\s*0x([0-9a-fA-F]{2,4})", repl, s)

def find_base64_candidates(s: str):
    # Find long-ish base64-looking chunks (tune length if needed)
    # This grabs contiguous base64 alphabet chunks
    candidates = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", s)
    # De-dupe while preserving order
    seen = set()
    out = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def try_decode_bytes(b: bytes) -> str:
    # Try common PS payload encodings
    for enc in ("utf-16le", "utf-8", "latin-1", "ascii"):
        try:
            text = b.decode(enc)
            # Heuristic: keep if looks somewhat printable
            printable = sum(ch.isprintable() for ch in text) / max(1, len(text))
            if printable > 0.85:
                return f"[decoded as {enc}]\n{text}"
        except Exception:
            pass
    return "[decoded bytes not clean text]"

def safe_b64_decode(s: str) -> bytes | None:
    # Add padding if missing
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s + pad, validate=False)
    except Exception:
        return None

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Path to file containing the obfuscated PowerShell text")
    ap.add_argument("--outdir", default="deobf_out", help="Output folder")
    args = ap.parse_args()

    raw = Path(args.input).read_text(encoding="utf-8", errors="ignore")

    cleaned = replace_char_hex(raw)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    (outdir / "stage1_cleaned.txt").write_text(cleaned, encoding="utf-8", errors="ignore")
    print(f"[+] Wrote: {outdir/'stage1_cleaned.txt'}")

    cands = find_base64_candidates(cleaned)
    print(f"[+] Found {len(cands)} base64-looking candidates")

    for i, c in enumerate(cands, 1):
        b = safe_b64_decode(c)
        if b is None:
            continue

        (outdir / f"b64_{i}.txt").write_text(c, encoding="utf-8", errors="ignore")
        (outdir / f"b64_{i}.bin").write_bytes(b)

        decoded_text = try_decode_bytes(b)
        (outdir / f"b64_{i}_decoded.txt").write_text(decoded_text, encoding="utf-8", errors="ignore")

        print(f"    [+] Candidate {i}: wrote b64_{i}.bin and b64_{i}_decoded.txt")

    print("[+] Done. Review stage1_cleaned.txt and any *_decoded.txt outputs.")

if __name__ == "__main__":
    main()
