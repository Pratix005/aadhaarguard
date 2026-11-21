"""Render docs/demo.gif from real CLI output.

    pip install pillow
    python scripts/make_demo.py [--font path/to/Recursive.ttf]

Runs the actual `aadhaarguard` commands on examples/customer.txt, so the GIF
always matches what the tool prints. Without --font it uses Consolas /
DejaVu Sans Mono.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")

# Dark palette shared with the Securegent dashboard: warm ink, one orange signal.
BG = "#121211"
PAPER = "#191917"
LINE = "#2c2b28"
INK = "#e8e6df"
MID = "#a7a399"
LOW = "#75726a"
SIGNAL = "#ff6a2c"

W, H = 1000, 510
PAD_X, TOP = 36, 70
SIZE, LH = 21, 31

KINDS = ("aadhaar", "pan", "gstin", "phone", "upi", "bank_account", "ifsc", "vehicle", "card", "email")


def load_font(path: str | None) -> ImageFont.FreeTypeFont:
    candidates = [path] if path else []
    candidates += ["C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
    for c in candidates:
        if c and os.path.exists(c):
            font = ImageFont.truetype(c, SIZE)
            try:  # Recursive: monospace + casual axes
                axes = {a["name"]: a for a in font.get_variation_axes()}
                values = []
                for a in font.get_variation_axes():
                    name = a["name"].decode() if isinstance(a["name"], bytes) else a["name"]
                    values.append({"Monospace": 1, "Casual": 1, "Weight": 420}.get(name, a["default"]))
                if axes:
                    font.set_variation_by_axes(values)
            except (OSError, AttributeError):
                pass
            return font
    sys.exit("no monospace font found; pass --font")


def run(args: list[str]) -> list[str]:
    out = subprocess.run(
        [sys.executable, "-m", "aadhaarguard", *args],
        cwd=EXAMPLES, capture_output=True, text=True, encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    return out.stdout.rstrip("\n").split("\n")


def colorize(line: str, masks: bool = False) -> list[tuple[str, str]]:
    """Split an output line into (text, color) runs."""
    if line.startswith("customer.txt:"):  # scan finding
        loc, _, rest = line.partition(": ")
        kind, _, tail = rest.partition(" ")
        value, _, conf = tail.rpartition(" ")
        return [(loc + ": ", LOW), (kind + " ", SIGNAL), (value + " ", INK), (conf, LOW)]
    if line.startswith("#"):
        return [(line, MID)]
    if masks and "X" in line:  # redact output: highlight the masked characters
        runs, cur, cur_c = [], "", INK
        for ch in line:
            c = SIGNAL if ch == "X" else INK
            if c != cur_c and cur:
                runs.append((cur, cur_c))
                cur = ""
            cur_c = c
            cur += ch
        runs.append((cur, cur_c))
        return runs
    return [(line, INK)]


class Term:
    def __init__(self, font):
        self.font = font
        self.cw = font.getlength("M")
        self.lines: list[list[tuple[str, str]]] = []
        self.frames: list[tuple[Image.Image, int]] = []

    def render(self, cursor: bool = False) -> Image.Image:
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((14, 14, W - 14, H - 14), 14, fill=PAPER, outline=LINE, width=2)
        for i, c in enumerate((LINE, LINE, LINE)):
            d.ellipse((36 + i * 24, 34, 48 + i * 24, 46), fill=c)
        d.text((W / 2, 40), "aadhaarguard", font=self.font, fill=LOW, anchor="mm")
        y = TOP
        for runs in self.lines:
            x = PAD_X
            for text, color in runs:
                d.text((x, y), text, font=self.font, fill=color)
                x += self.font.getlength(text)
            y += LH
        if cursor:
            x = PAD_X + sum(self.font.getlength(t) for t, _ in self.lines[-1]) if self.lines else PAD_X
            yy = TOP + LH * (len(self.lines) - 1)
            d.rectangle((x + 2, yy + 3, x + self.cw - 1, yy + SIZE + 3), fill=SIGNAL)
        return img

    def snap(self, ms: int, cursor: bool = False) -> None:
        self.frames.append((self.render(cursor), ms))

    def type(self, cmd: str) -> None:
        self.lines.append([("$ ", SIGNAL), ("", INK)])
        self.snap(500, cursor=True)
        for i in range(0, len(cmd), 2):
            self.lines[-1][1] = (cmd[: i + 2], INK)
            self.snap(55, cursor=True)
        self.snap(350, cursor=True)

    def output(self, lines: list[str], per_line_ms: int = 60, masks: bool = False) -> None:
        for line in lines:
            self.lines.append(colorize(line, masks))
            self.snap(per_line_ms)

    def clear(self) -> None:
        self.lines = []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--font")
    ap.add_argument("-o", "--output", default=os.path.join(ROOT, "docs", "demo.gif"))
    args = ap.parse_args()

    t = Term(load_font(args.font))

    with open(os.path.join(EXAMPLES, "customer.txt"), encoding="utf-8") as fh:
        raw = fh.read().rstrip("\n").split("\n")
    t.type("cat customer.txt")
    t.output(raw, 40)
    t.snap(2200)

    t.clear()
    t.type("aadhaarguard scan customer.txt")
    t.output(run(["scan", "customer.txt"]), 120)
    t.output(["", "# checksums + keywords: the order no., date and price", "# on the last line are not flagged"], 40)
    t.snap(3800)

    t.clear()
    t.type("aadhaarguard redact customer.txt --style partial")
    t.output(run(["redact", "customer.txt", "--style", "partial"]), 60, masks=True)
    t.snap(3800)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    frames = [f.quantize(colors=32, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f, _ in t.frames]
    frames[0].save(
        args.output, save_all=True, append_images=frames[1:],
        duration=[ms for _, ms in t.frames], loop=0, optimize=True, disposal=1,
    )
    print(f"{args.output}: {len(frames)} frames, {sum(ms for _, ms in t.frames) / 1000:.1f}s, "
          f"{os.path.getsize(args.output) / 1024:.0f} KB")


if __name__ == "__main__":
    main()
