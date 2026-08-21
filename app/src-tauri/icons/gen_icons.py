"""Generate veilweave app icons: a woven 'eye of threads' mark on a dark
rounded-square background. Output: pngs at several sizes, .ico, .icns."""

import math
import os
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFilter

S = 1024  # master canvas size
OUT = os.path.dirname(os.path.abspath(__file__))


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


INDIGO = (99, 102, 241)   # #6366f1
CYAN = (34, 211, 238)     # #22d3ee
VIOLET = (167, 139, 250)  # #a78bfa


def make_master() -> Image.Image:
    scale = 4  # supersample
    N = S * scale
    img = Image.new("RGBA", (N, N), (0, 0, 0, 0))

    # ── background: rounded square, near-black with subtle vertical gradient ──
    bg = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    d = ImageDraw.Draw(bg)
    radius = int(N * 0.225)
    for y in range(N):
        t = y / N
        col = lerp((13, 16, 23), (8, 10, 14), t)  # #0d1017 -> #080a0e
        d.line([(0, y), (N, y)], fill=col + (255,))
    mask = Image.new("L", (N, N), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, N - 1, N - 1], radius=radius, fill=255)
    img.paste(bg, (0, 0), mask)

    # subtle top border highlight inside the rounded square
    hl = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    ImageDraw.Draw(hl).rounded_rectangle(
        [scale, scale, N - scale, N - scale], radius=radius, outline=(255, 255, 255, 14),
        width=2 * scale,
    )
    img.alpha_composite(hl)

    # ── radial glow behind the mark ──
    glow = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse(
        [N * 0.18, N * 0.22, N * 0.82, N * 0.78], fill=(79, 90, 220, 70)
    )
    glow = glow.filter(ImageFilter.GaussianBlur(N * 0.09))
    img.alpha_composite(glow)

    # ── the eye of threads: 5 curved horizontal threads (lens outline arcs) ──
    cx, cy = N * 0.5, N * 0.5
    threads = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    td = ImageDraw.Draw(threads)

    # eye horizontal half-width and vertical half-height
    ex, ey = N * 0.30, N * 0.155

    def eye_arc(x_t):  # x in [-1,1] -> y offset of lens outline
        return ey * math.sqrt(max(0.0, 1.0 - x_t * x_t))

    n_lines = 5
    for li in range(n_lines):
        # spread threads between upper and lower lens outline
        f = li / (n_lines - 1)          # 0..1 top..bottom
        pts = []
        steps = 240
        for i in range(steps + 1):
            xt = -1.0 + 2.0 * i / steps
            x = cx + xt * ex
            top = cy - eye_arc(xt)
            bot = cy + eye_arc(xt)
            # threads converge at both eye corners, fan out in the middle
            pinch = 0.10 + 0.90 * abs(xt) ** 1.6
            y = top + (bot - top) * (f * (1 - pinch) + 0.5 * pinch)
            pts.append((x, y))
        col = lerp(INDIGO, CYAN, f)
        w = int(scale * (7 - 2 * abs(f - 0.5) * 2)) + scale * 3
        td.line(pts, fill=col + (235,), width=w, joint="curve")

    img.alpha_composite(threads)

    # ── two crossing diagonal threads (the weave) ──
    weave = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    wd = ImageDraw.Draw(weave)
    for sgn, col in [(1, VIOLET), (-1, CYAN)]:
        pts = []
        steps = 160
        for i in range(steps + 1):
            t = i / steps
            xt = -1.0 + 2.0 * t
            x = cx + xt * ex
            bend = sgn * ey * 0.55 * math.sin(math.pi * t)
            y = cy + bend
            pts.append((x, y))
        wd.line(pts, fill=col + (210,), width=int(scale * 5.5), joint="curve")
    img.alpha_composite(weave)

    # ── pupil: bright dot with halo ──
    halo = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    ImageDraw.Draw(halo).ellipse(
        [cx - N * 0.075, cy - N * 0.075, cx + N * 0.075, cy + N * 0.075],
        fill=(120, 160, 255, 120),
    )
    halo = halo.filter(ImageFilter.GaussianBlur(N * 0.02))
    img.alpha_composite(halo)
    pd = ImageDraw.Draw(img)
    r = N * 0.042
    pd.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(224, 242, 254, 255))

    # clip everything to the rounded-square mask
    out = Image.new("RGBA", (N, N), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out.resize((S, S), Image.LANCZOS)


def main():
    master = make_master()
    for size, name in [(32, "32x32.png"), (128, "128x128.png"), (256, "128x128@2x.png"),
                       (512, "icon.png")]:
        master.resize((size, size), Image.LANCZOS).save(os.path.join(OUT, name))
        print("wrote", name)

    # .ico with multiple sizes
    master.save(
        os.path.join(OUT, "icon.ico"),
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("wrote icon.ico")

    # .icns via png2icns substitute: build a minimal icns from png bytes
    # (icns = magic + ic10 (1024 png) entries; tool 'png2icns' may not exist on
    # Windows, so hand-roll the container — tauri only needs a valid icns)
    png512 = tempfile.NamedTemporaryFile(suffix=".png", delete=False).name
    master.resize((512, 512), Image.LANCZOS).save(png512)
    png1024 = tempfile.NamedTemporaryFile(suffix=".png", delete=False).name
    master.save(png1024)
    with open(png512, "rb") as f:
        b512 = f.read()
    with open(png1024, "rb") as f:
        b1024 = f.read()

    def entry(tag, data):
        return tag + (8 + len(data)).to_bytes(4, "big") + data

    body = entry(b"ic09", b512) + entry(b"ic10", b1024)
    with open(os.path.join(OUT, "icon.icns"), "wb") as f:
        f.write(b"icns" + (8 + len(body)).to_bytes(4, "big") + body)
    print("wrote icon.icns")
    os.unlink(png512)
    os.unlink(png1024)

    # preview for visual check
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "_preview.png"))


if __name__ == "__main__":
    main()
