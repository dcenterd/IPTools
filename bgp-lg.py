#!/usr/bin/env python3
import re
import sys

import requests

RIPE_BGP_API = "https://stat.ripe.net/data/bgp-state/data.json"
PDF_SCALE = 1.0  # 1.0 = original size
RIPE_AS_API = "https://stat.ripe.net/data/as-overview/data.json"


def get_bgp_path(ip):
    params = {"resource": ip}
    r = requests.get(RIPE_BGP_API, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()

    paths = data["data"]["bgp_state"]
    if not paths:
        raise Exception("No BGP path found")

    return paths[0]["path"]


def get_as_name(asn):
    params = {"resource": f"AS{asn}"}
    r = requests.get(RIPE_AS_API, params=params, timeout=10)
    r.raise_for_status()
    payload = r.json()
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
    if len(sys.argv) != 2:
        print("Usage: bgp-lg.py <ip>")
        sys.exit(1)

    ip = sys.argv[1]
    print(f"\n BGP AS Path for {ip}\n")

    path = get_bgp_path(ip)

    names = []
    for i, asn in enumerate(path, 1):
        name = get_as_name(asn)
        names.append(name)
        print(f"{i}. AS{asn} — {name}")

    draw_as_graph(path, names)

    print(f"PDF saved to {export_pdf(ip, path, names)}")


if __name__ == "__main__":
    main()
