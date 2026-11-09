# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Azimjon Makhkamov
"""Server tomonda yaratiladigan rasmli captcha (tashqi servissiz)."""
import base64
import hashlib
import io
import random
import secrets

from fastapi import APIRouter, HTTPException, Request
from PIL import Image, ImageDraw, ImageFilter, ImageFont

from .kv import kv
from .security import client_ip

router = APIRouter(tags=["Captcha"])
ALPHABET = "ABCDEFHJKMNPRSTUVWXYZ2345678"
TTL = 300


def _render(text: str) -> bytes:
    rnd = random.SystemRandom()
    W, H = 200, 64
    img = Image.new("RGB", (W, H), (rnd.randint(235, 250), rnd.randint(235, 250), rnd.randint(235, 250)))
    d = ImageDraw.Draw(img)
    for _ in range(6):  # fon chiziqlari
        d.line([(rnd.randint(0, W), rnd.randint(0, H)), (rnd.randint(0, W), rnd.randint(0, H))],
               fill=(rnd.randint(150, 210),) * 3, width=1)
    x = 12
    for ch in text:
        font = ImageFont.load_default(size=rnd.randint(34, 42))
        layer = Image.new("RGBA", (56, 64), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text((10, 6), ch, font=font,
                                   fill=(rnd.randint(10, 90), rnd.randint(10, 90), rnd.randint(60, 140), 255))
        layer = layer.rotate(rnd.uniform(-28, 28), resample=Image.BICUBIC, expand=False)
        img.paste(layer, (x, rnd.randint(-6, 4)), layer)
        x += rnd.randint(30, 36)
    for _ in range(3):  # ustidan kesuvchi egri chiziqlar
        y0 = rnd.randint(10, H - 10)
        d.arc([rnd.randint(-40, 40), y0 - 30, rnd.randint(W - 40, W + 40), y0 + 30],
              rnd.randint(0, 180), rnd.randint(180, 360), fill=(rnd.randint(40, 120),) * 3, width=2)
    for _ in range(250):
        d.point((rnd.randint(0, W - 1), rnd.randint(0, H - 1)), fill=(rnd.randint(80, 200),) * 3)
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _h(cid: str, answer: str) -> str:
    return hashlib.sha256(f"{cid}:{answer.strip().upper()}".encode()).hexdigest()


async def new_captcha() -> dict:
    text = "".join(secrets.choice(ALPHABET) for _ in range(5))
    cid = secrets.token_urlsafe(16)
    await kv.set(f"cap:{cid}", _h(cid, text), ex=TTL)
    return {"captcha_id": cid, "image": "data:image/png;base64," + base64.b64encode(_render(text)).decode()}


async def verify_captcha(cid: str | None, answer: str | None) -> bool:
    if not cid or not answer:
        return False
    stored = await kv.get(f"cap:{cid}")
    await kv.delete(f"cap:{cid}")   # bir martalik
    return bool(stored) and stored == _h(cid, answer)


@router.get("/api/captcha", include_in_schema=False)
async def captcha(request: Request):
    if await kv.incr(f"capgen:{client_ip(request)}", 600) > 60:
        raise HTTPException(429, "Juda ko'p so'rov")
    return await new_captcha()
