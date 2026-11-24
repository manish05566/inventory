"""Generates the product icon (.ico) and logo PNGs used by the exe, the setup wizard and the portal."""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).parent / "assets"
TOP, BOTTOM = (59, 130, 246), (29, 78, 216)  # blue gradient


def blend(c, a, bg):
    return tuple(int(bg[i] * (1 - a) + c[i] * a) for i in range(3))


def logo(size=1024):
    s = 4  # supersample
    W = size * s
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    grad = Image.new("RGBA", (W, W))
    gd = ImageDraw.Draw(grad)
    for y in range(W):
        t = y / W
        gd.line([(0, y), (W, y)], fill=tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3)) + (255,))
    mask = Image.new("L", (W, W), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, W - 1, W - 1], radius=int(W * 0.22), fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    k = W / 1024
    P = lambda x, y: (x * k, y * k)
    top, ur, lr, bot, ll, ul, c = P(512, 232), P(760, 375), P(760, 665), P(512, 808), P(264, 665), P(264, 375), P(512, 518)
    mid = blend((255, 255, 255), 1, TOP)
    d.polygon([top, ur, c, ul], fill=(255, 255, 255, 255))
    d.polygon([ul, c, bot, ll], fill=(255, 255, 255, 205))
    d.polygon([c, ur, lr, bot], fill=(255, 255, 255, 140))
    gap = int(22 * k)
    edge = (37, 99, 235, 255)
    for a, b in [(ul, c), (c, ur), (c, bot)]:
        d.line([a, b], fill=edge, width=gap)
    # small "status" dot = live inventory
    r = 88 * k
    cx, cy = 760 * k, 268 * k
    d.ellipse([cx - r - 18 * k, cy - r - 18 * k, cx + r + 18 * k, cy + r + 18 * k], fill=edge)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(34, 197, 94, 255))
    _ = mid
    return img.resize((size, size), Image.LANCZOS)


def main():
    OUT.mkdir(exist_ok=True)
    big = logo(1024)
    big.save(OUT / "icon.ico", sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)])
    for px in (32, 48, 64, 96, 128, 256):
        big.resize((px, px), Image.LANCZOS).save(OUT / f"logo-{px}.png")
    web = Path(__file__).parent.parent / "server" / "public"
    if web.exists():
        big.resize((192, 192), Image.LANCZOS).save(web / "logo-192.png")
        big.resize((32, 32), Image.LANCZOS).save(web / "favicon.png")
    print("assets written to", OUT)


if __name__ == "__main__":
    sys.exit(main())
