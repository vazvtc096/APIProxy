"""Generate static/favicon.ico from the brand gradient + lightning bolt mark.

Pure-stdlib ICO writer that emits a full multi-resolution set
(16, 32, 48, 64, 128, 256) so the icon stays crisp on high-DPI displays.
Small sizes are stored as 32-bit BGRA BMP; the 256 entry is stored as a
compressed PNG inside the ICO to keep the file small.

Anti-aliasing is achieved by supersampling (rendering at Nx then box-downsampling),
which smooths the bolt edges and the rounded-rect corners.

Run once: python tools/gen_favicon.py
"""
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "static" / "favicon.ico"

# brand gradient corners (r,g,b)
C00 = (0x66, 0x7E, 0xEA)  # top-left  #667eea
C11 = (0x76, 0x4B, 0xA2)  # bottom-right #764ba2

RADIUS_RATIO = 0.22
SIZES = (16, 32, 48, 64, 128, 256)
PNG_SIZES = {256}  # store these as PNG inside the ICO


def lerp(a, b, t):
    return a + (b - a) * t


def bg(x, y, size):
    t = (x / (size - 1) + y / (size - 1)) / 2
    return (lerp(C00[0], C11[0], t), lerp(C00[1], C11[1], t), lerp(C00[2], C11[2], t))


# lightning bolt polygon in unit space (scaled to size)
BOLT = [(0.5625, 0.125), (0.28125, 0.5625), (0.46875, 0.5625),
        (0.40625, 0.9375), (0.75, 0.421875), (0.546875, 0.421875)]


def in_bolt(px, py, size):
    x, y = px / size, py / size
    inside = False
    n = len(BOLT)
    for i in range(n):
        x1, y1 = BOLT[i]
        x2, y2 = BOLT[(i + 1) % n]
        if (y1 > y) != (y2 > y):
            xin = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if x < xin:
                inside = not inside
    return inside


def in_rounded(px, py, size):
    r = RADIUS_RATIO * size
    if r <= 0:
        return True
    if r <= px < size - r and r <= py < size - r:
        return True
    cx = r if px < r else size - 1 - r
    cy = r if py < r else size - 1 - r
    dx, dy = abs(px - cx), abs(py - cy)
    return (dx * dx + dy * dy) <= r * r


def sample(px, py, size):
    """Return (r,g,b,a) for a sub-pixel centre, with 0/255 coverage."""
    if not in_rounded(px, py, size):
        return (0.0, 0.0, 0.0, 0.0)
    if in_bolt(px, py, size):
        return (255.0, 255.0, 255.0, 255.0)
    r, g, b = bg(px, py, size)
    return (r, g, b, 255.0)


def render_rgba(size, ss):
    """Supersample to `size` with `ss`x`ss` sub-samples per pixel."""
    out = bytearray(size * size * 4)
    n = ss * ss
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0.0
            for sy in range(ss):
                spy = y + (sy + 0.5) / ss
                for sx in range(ss):
                    spx = x + (sx + 0.5) / ss
                    cr, cg, cb, ca = sample(spx, spy, size)
                    r += cr
                    g += cg
                    b += cb
                    a += ca
            i = (y * size + x) * 4
            out[i] = int(r / n + 0.5)
            out[i + 1] = int(g / n + 0.5)
            out[i + 2] = int(b / n + 0.5)
            out[i + 3] = int(a / n + 0.5)
    return bytes(out)


def bmp_image(size, rgba):
    xor = b""
    for y in range(size - 1, -1, -1):  # bottom-up row order for BMP
        row = rgba[y * size * 4:(y + 1) * size * 4]
        # convert RGBA -> BGRA
        for i in range(0, len(row), 4):
            xor += bytes((row[i + 2], row[i + 1], row[i], row[i + 3]))
    and_row = ((size + 31) // 32) * 4  # 1bpp rows padded to 32 bits
    and_mask = b"\x00" * (and_row * size)  # fully opaque; alpha channel governs
    data_len = len(xor) + len(and_mask)
    bmp_header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0,
                             data_len, 0, 0, 0, 0)
    return bmp_header + xor + and_mask


def png_image(size, rgba):
    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    stride = size * 4
    raw = b""
    for y in range(size):
        raw += b"\x00" + rgba[y * stride:(y + 1) * stride]
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def build_ico():
    images = []
    for s in SIZES:
        ss = 8 if s <= 64 else (4 if s == 128 else 3)
        rgba = render_rgba(s, ss)
        if s in PNG_SIZES:
            data = png_image(s, rgba)
        else:
            data = bmp_image(s, rgba)
        images.append((s, data))

    count = len(images)
    out = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = b""
    for s, data in images:
        w = s if s < 256 else 0
        h = s if s < 256 else 0
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    OUT.write_bytes(out + entries + b"".join(d for _, d in images))
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes), sizes={SIZES}")


if __name__ == "__main__":
    build_ico()
