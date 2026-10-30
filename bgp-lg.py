#!/usr/bin/env python3
"""
bgp-lg.py - BGP looking glass: the AS path towards an IP (RIPEstat bgp-state)

Usage
    ./bgp-lg.py 8.8.8.8              # path, text topology and bgp_path_<ip>.pdf
    ./bgp-lg.py 8.8.8.8 --no-pdf     # do not write the PDF
    ./bgp-lg.py 8.8.8.8 --json       # one JSON document on stdout, for scripts

With --json the text topology is not printed, no PDF is written unless --pdf is
given, progress and warnings go to stderr, and errors become {"error": ...}
with exit code 1.
"""
import argparse
import ipaddress
import json
import re
import sys

import requests

RIPE_BGP_API = "https://stat.ripe.net/data/bgp-state/data.json"
PDF_SCALE = 1.0  # 1.0 = original size
RIPE_AS_API = "https://stat.ripe.net/data/as-overview/data.json"


def ripe_get(url, resource, timeout):
    """GET a RIPEstat endpoint as JSON, with one retry (the API occasionally times out)."""
    for attempt in (1, 2):
        try:
            r = requests.get(url, params={"resource": resource}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError):
            if attempt == 2:
                raise


def get_bgp_path(ip):
    data = ripe_get(RIPE_BGP_API, ip, 10)

    paths = data["data"]["bgp_state"]
    if not paths:
        raise Exception("No BGP path found")

    return paths[0]["path"]


def get_as_name(asn):
    payload = ripe_get(RIPE_AS_API, f"AS{asn}", 10)
    holder = payload.get("data", {}).get("holder")
    return holder or f"AS{asn}"


def draw_as_graph(path, names):
    if not path:
        raise ValueError("Path is empty")

    print("\nAS topology:\n")

    indent = 4
    labels = [f"AS{asn}" for asn in path]
    inner = max(len(label) for label in labels) + 6
    mid = inner // 2

    for i, (label, name) in enumerate(zip(labels, names)):
        last = i == len(labels) - 1
        print(" " * indent + "╭" + "─" * inner + "╮")
        print(" " * indent + "│" + label.center(inner) + "│" + f"   {name}")
        if last:
            print(" " * indent + "╰" + "─" * inner + "╯")
        else:
            print(" " * indent + "╰" + "─" * mid + "┬" + "─" * (inner - mid - 1) + "╯")
            print(" " * (indent + 1 + mid) + "▼")

    print()


def _pdf_escape(text):
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pill(x, y, w, h):
    r = h / 2
    k = 0.5523 * r
    return (
        f"{x + r:.2f} {y:.2f} m {x + w - r:.2f} {y:.2f} l "
        f"{x + w - r + k:.2f} {y:.2f} {x + w:.2f} {y + r - k:.2f} {x + w:.2f} {y + r:.2f} c "
        f"{x + w:.2f} {y + r + k:.2f} {x + w - r + k:.2f} {y + h:.2f} {x + w - r:.2f} {y + h:.2f} c "
        f"{x + r:.2f} {y + h:.2f} l "
        f"{x + r - k:.2f} {y + h:.2f} {x:.2f} {y + r + k:.2f} {x:.2f} {y + r:.2f} c "
        f"{x:.2f} {y + r - k:.2f} {x + r - k:.2f} {y:.2f} {x + r:.2f} {y:.2f} c h S\n"
    )


def export_pdf(ip, path, names):
    """Write the AS topology as a one-page vector PDF in the current directory."""
    s = PDF_SCALE
    margin, box_w, box_h, gap = 40 * s, 150 * s, 34 * s, 30 * s
    label_size, name_size, title_size = 12 * s, 10 * s, 14 * s
    name_x_off = box_w + 16 * s
    longest = max(len(n) for n in names)
    width = margin * 2 + name_x_off + longest * name_size * 0.55
    title_h = 40 * s
    height = margin * 2 + title_h + len(path) * box_h + (len(path) - 1) * gap

    ops = [f"{0.8 * s:.2f} w\n",
           f"BT /F1 {title_size:.2f} Tf {margin:.2f} {height - margin:.2f} Td "
           f"({_pdf_escape(f'BGP AS path for {ip}')}) Tj ET\n"]
    cx = margin + box_w / 2
    top = height - margin - title_h
    for i, (asn, name) in enumerate(zip(path, names)):
        y = top - box_h - i * (box_h + gap)
        ops.append(_pill(margin, y, box_w, box_h))
        label = f"AS{asn}"
        label_w = (0.667 * 2 + 0.556 * (len(label) - 2)) * label_size
        ops.append(f"BT /F2 {label_size:.2f} Tf {cx - label_w / 2:.2f} {y + box_h / 2 - 4 * s:.2f} Td "
                   f"({_pdf_escape(label)}) Tj ET\n")
        ops.append(f"BT /F1 {name_size:.2f} Tf {margin + name_x_off:.2f} {y + box_h / 2 - 3.5 * s:.2f} Td "
                   f"({_pdf_escape(name)}) Tj ET\n")
        if i < len(path) - 1:
            y_end = y - gap
            ops.append(f"{cx:.2f} {y:.2f} m {cx:.2f} {y_end + 6 * s:.2f} l S\n")
            ops.append(f"{cx - 4 * s:.2f} {y_end + 7 * s:.2f} m {cx + 4 * s:.2f} {y_end + 7 * s:.2f} l "
                       f"{cx:.2f} {y_end:.2f} l f\n")

    content = "".join(ops).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width:.2f} {height:.2f}] "
        f"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"endstream",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()

    safe_ip = re.sub(r"[^0-9A-Za-z.-]", "_", ip)
    filename = f"bgp_path_{safe_ip}.pdf"
    with open(filename, "wb") as f:
        f.write(out)
    return filename


def main():
    ap = argparse.ArgumentParser(description="BGP AS path towards an IP (RIPEstat looking glass).")
    ap.add_argument("ip", help="IPv4 or IPv6 address")
    ap.add_argument("--json", action="store_true", help="print one JSON document instead of the text report")
    ap.add_argument("--no-pdf", action="store_true", help="do not write the PDF")
    ap.add_argument("--pdf", action="store_true", help="with --json: also write the PDF")
    args = ap.parse_args()

    def fail(msg):
        print(json.dumps({"error": msg}) if args.json else f"Error: {msg}")
        return 1

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        return fail(f"'{args.ip}' is not a valid IP address")
    ip = args.ip

    if not args.json:
        print(f"\n BGP AS Path for {ip}\n")

    try:
        path = get_bgp_path(ip)
    except (requests.RequestException, KeyError, ValueError) as e:
        return fail(f"could not fetch the BGP path ({e})")
    except Exception as e:  # get_bgp_path raises a plain Exception when RIPEstat has no path
        return fail(str(e))

    names = []
    for i, asn in enumerate(path, 1):
        try:
            name = get_as_name(asn)
        except (requests.RequestException, ValueError):
            name = f"AS{asn}"
        names.append(name)
        if not args.json:
            print(f"{i}. AS{asn} — {name}")

    write_pdf = not args.no_pdf and (args.pdf or not args.json)
    pdf = export_pdf(ip, path, names) if write_pdf else None

    if args.json:
        print(json.dumps({"ip": ip, "path": [{"asn": f"AS{a}", "name": n} for a, n in zip(path, names)], "pdf": pdf},
                         indent=2, ensure_ascii=False))
        return 0

    draw_as_graph(path, names)
    if pdf:
        print(f"PDF saved to {pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
