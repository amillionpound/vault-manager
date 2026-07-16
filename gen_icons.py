"""Generate PWA icons for vault-manager (lock on brand-blue tile)."""
import os
from PIL import Image, ImageDraw

BRAND = (0x4f, 0x6e, 0xf7, 255)   # matches --brand in index.html
WHITE = (255, 255, 255, 255)


def draw_lock(d, cx, cy, s):
    """s = scale factor relative to a 512px base."""
    bw = 140 * s
    body_top = cy - 20 * s
    body_bot = cy + 90 * s
    d.rounded_rectangle([int(cx - bw / 2), int(body_top), int(cx + bw / 2), int(body_bot)],
                        radius=int(20 * s), fill=WHITE)
    r = bw / 2
    d.arc([int(cx - r), int(body_top - r), int(cx + r), int(body_top + r)],
          start=180, end=360, fill=WHITE, width=int(22 * s))
    kh = 28 * s
    d.ellipse([int(cx - kh / 2), int(cy + 30 * s), int(cx + kh / 2), int(cy + 30 * s + kh)], fill=BRAND)
    d.rectangle([int(cx - 7 * s), int(cy + 40 * s), int(cx + 7 * s), int(cy + 70 * s)], fill=BRAND)


def make_standard(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = int(size * 0.10)
    d.rounded_rectangle([m, m, size - m, size - m],
                        radius=int(size * 0.22), fill=BRAND)
    draw_lock(d, size / 2, size * 0.46, size / 512)
    return img


def make_maskable(size):
    img = Image.new('RGBA', (size, size), BRAND)
    d = ImageDraw.Draw(img)
    draw_lock(d, size / 2, size / 2, (size / 512) * 0.62)
    return img


os.makedirs('icons', exist_ok=True)
for sz in (192, 512):
    make_standard(sz).save(f'icons/icon-{sz}.png')
make_maskable(512).save('icons/icon-maskable-512.png')
print('icons written:', os.listdir('icons'))
