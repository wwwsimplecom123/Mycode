"""Generate deterministic PNG assets for the development MV3 extension."""

from pathlib import Path
import struct
import zlib


ROOT = Path(__file__).resolve().parent


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def inside_shield(x: float, y: float) -> bool:
    if y < 0.12 or y > 0.9:
        return False
    half_width = 0.34 if y < 0.48 else 0.34 * (0.9 - y) / 0.42
    return abs(x - 0.5) <= half_width


def make_icon(size: int) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            nx = (x + 0.5) / size
            ny = (y + 0.5) / size
            if inside_shield(nx, ny):
                border = not inside_shield(
                    0.5 + (nx - 0.5) * 1.13,
                    0.5 + (ny - 0.5) * 1.13,
                )
                color = (23, 32, 51, 255) if border else (22, 115, 74, 255)
                if abs(nx - 0.5) < 0.045 and 0.35 < ny < 0.69:
                    color = (246, 248, 251, 255)
                row.extend(color)
            else:
                row.extend((0, 0, 0, 0))
        rows.append(bytes(row))
    raw = b"".join(rows)
    signature = b"\x89PNG\r\n\x1a\n"
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return signature + png_chunk(b"IHDR", header) + png_chunk(
        b"IDAT", zlib.compress(raw, 9)
    ) + png_chunk(b"IEND", b"")


if __name__ == "__main__":
    for icon_size in (16, 32, 48, 128):
        (ROOT / f"shield-{icon_size}.png").write_bytes(make_icon(icon_size))
