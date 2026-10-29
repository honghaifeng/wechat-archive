"""微信 4.x 媒体文件解密（.dat 图片、视频、文件、语音）。

图片（V2 格式，4.1.x 主流）
--------------------------
    offset 0   6   魔数  07 08 56 32 08 07      (\x07\x08V2\x08\x07)
    offset 6   4   AES 段长度（LE u32，实测 1024）
    offset 10  4   XOR 段长度（LE u32）
    offset 14  1   标志位（实测 0x01）
    offset 15  N   AES-128-ECB 加密的图片头部
    offset 15+N 16 分隔尾（版本相关常量，跳过即可，不要硬编码）
    之后       M   单字节 XOR 混淆的剩余部分

    校验式：file_size == 15 + aes_size + 16 + xor_size

密钥是**账号级**的、可以离线派生，不需要微信进程在线：

    code    = kvcomm 文件名里 key_<code>_… 的第一个数字
    aes_key = MD5(f"{code}{wxid}").hexdigest()[:16]   # 16 个 ASCII 字符
    xor_key = code & 0xFF

注意 aes_key 取的是 **hex 字符串的前 16 个字符**，不是解码后的 8 字节——
这一点搞错会得到「第一块看着像图片头、整张图打不开」的假成功。

视频与文件
----------
实测 macOS 4.1.15：``msg/video/<YYYY-MM>/<md5>.mp4`` 是**明文**，封面 ``<md5>_thumb.jpg``
也是明文；``msg/file/<YYYY-MM>/<文件名>`` 同样是明文，只是文件名可能被重命名。
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from Crypto.Cipher import AES

MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF8": "gif",
    b"wxgf": "wxgf",
}
V2_SIG = b"\x07\x08V2\x08\x07"
V1_SIG = b"\x07\x08V1\x08\x07"
HEX32 = re.compile(r"[0-9a-f]{32}")


@dataclass
class MediaKey:
    aes: bytes          # 16 字节 ASCII
    xor: int            # 单字节异或 key
    code: int
    wxid: str

    def __repr__(self) -> str:  # 不要把 key 打进日志
        return "MediaKey(code=%d, aes=%s…, xor=0x%02x)" % (
            self.code, self.aes[:4].decode("ascii", "ignore"), self.xor)


# ---------------------------------------------------------------- 密钥派生

def _derive(code: int, wxid: str) -> MediaKey:
    aes = hashlib.md5(("%d%s" % (code, wxid)).encode()).hexdigest()[:16].encode()
    return MediaKey(aes=aes, xor=code & 0xFF, code=code, wxid=wxid)


def clean_wxid(wxid: str) -> str:
    """wxid_xxx_1234 -> wxid_xxx（多段后缀要剥掉）。"""
    parts = wxid.split("_")
    return "_".join(parts[:2]) if wxid.startswith("wxid_") and len(parts) >= 3 else wxid


def _v2_files(account, limit: int = 12) -> List[str]:
    out = []
    if not os.path.isdir(account.attach_dir):
        return out
    for base, _, files in os.walk(account.attach_dir):
        for f in files:
            if f.endswith(".dat"):
                p = os.path.join(base, f)
                try:
                    with open(p, "rb") as fh:
                        if fh.read(6) == V2_SIG:
                            out.append(p)
                            if len(out) >= limit:
                                return out
                except OSError:
                    continue
    return out


def _test_key(sample: str, key: MediaKey) -> bool:
    try:
        with open(sample, "rb") as f:
            head = f.read(15 + 1024)
    except OSError:
        return False
    if len(head) < 31 or head[:6] != V2_SIG:
        return False
    aes_size = struct.unpack("<I", head[6:10])[0]
    seg = head[15:15 + min(aes_size, 1024)]
    if len(seg) < 16:
        return False
    pt = AES.new(key.aes, AES.MODE_ECB).decrypt(seg[:16])
    return any(pt.startswith(m) for m in MAGIC)


def derive_media_key(account) -> Optional[MediaKey]:
    """从 kvcomm 文件名里的 code + wxid 派生，并用真实文件验证。"""
    codes = []
    code = account.media_code()
    if code:
        codes.append(code)
    # 兜底：账号目录名里也可能带数字段
    for m in re.finditer(r"\d{6,}", account.wxid):
        codes.append(int(m.group(0)))

    samples = _v2_files(account)
    for c in codes:
        for wid in {account.wxid, clean_wxid(account.wxid)}:
            key = _derive(c, wid)
            if not samples:
                return key          # 没有样本时只能先信它
            if any(_test_key(s, key) for s in samples[:8]):
                return key
    return None


# ---------------------------------------------------------------- .dat 解密

def is_v2(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(6) == V2_SIG
    except OSError:
        return False


def detect_ext(data: bytes) -> str:
    for magic, ext in MAGIC.items():
        if data.startswith(magic):
            return ext
    return "bin"


def decrypt_dat(path: str, key: MediaKey) -> Tuple[bytes, str]:
    """返回 (明文, 扩展名)。不支持的文件原样返回。"""
    with open(path, "rb") as f:
        data = f.read()

    if data[:6] == V2_SIG:
        aes_size, xor_size = struct.unpack("<II", data[6:14])
        aes_part = AES.new(key.aes, AES.MODE_ECB).decrypt(data[15:15 + aes_size])
        tail_start = 15 + aes_size + 16
        xor_part = bytes(b ^ key.xor for b in data[tail_start:tail_start + xor_size])
        pt = aes_part + xor_part
        return pt, detect_ext(pt)

    if data[:6] == V1_SIG:  # 老版本：V1 用固定 key，这里保留识别能力
        return data, "bin"

    # V0：整文件单字节 XOR，用已知图像头反推 key
    for magic in (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF8"):
        k = data[0] ^ magic[0]
        if bytes(b ^ k for b in data[:3]) == magic[:3]:
            pt = bytes(b ^ k for b in data)
            return pt, detect_ext(pt)
    return data, detect_ext(data)


def wxgf_to_image(data: bytes, out_path_noext: str) -> Optional[str]:
    """wxgf 是微信自研容器，里面是 HEVC。有 ffmpeg 就抽首帧。"""
    if shutil.which("ffmpeg") is None:
        return None
    idx = data.find(b"\x00\x00\x00\x01")
    if idx < 0:
        return None
    hevc = out_path_noext + ".hevc"
    with open(hevc, "wb") as f:
        f.write(data[idx:])
    png = out_path_noext + ".png"
    r = subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "hevc",
                        "-i", hevc, "-frames:v", "1", png], capture_output=True)
    os.remove(hevc)
    if r.returncode == 0 and os.path.exists(png):
        return png
    return None


def save_image(src: str, out_dir: str, key: Optional[MediaKey],
               name: Optional[str] = None) -> Optional[str]:
    """解密一张图并落到 out_dir，返回相对路径。"""
    os.makedirs(out_dir, exist_ok=True)
    stem = name or os.path.basename(src).split(".")[0]
    if key and is_v2(src):
        data, ext = decrypt_dat(src, key)
    else:
        with open(src, "rb") as f:
            data = f.read()
        ext = detect_ext(data)
    if ext == "wxgf":
        tmp = os.path.join(out_dir, stem)
        conv = wxgf_to_image(data, tmp)
        if conv:
            return conv
        # 没有 ffmpeg：退化为原始 wxgf（浏览器看不了，但数据保住了）
        path = tmp + ".wxgf"
        with open(path, "wb") as f:
            f.write(data)
        return path
    path = os.path.join(out_dir, "%s.%s" % (stem, ext))
    with open(path, "wb") as f:
        f.write(data)
    return path


# ---------------------------------------------------------------- 媒体定位

def _month_dir(ts: int) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m")


def find_image_variants(account, talker: str, ts: int,
                        packed_hex: List[str]) -> List[str]:
    """返回同一张图的候选文件（按质量从高到低：_h > 原图 > _t）。"""
    base = os.path.join(account.chat_attach_dir(talker), _month_dir(ts), "Img")
    cands: List[str] = []
    if not os.path.isdir(base):
        # 月份目录可能对不上，退到会话目录下全部搜索
        base = account.chat_attach_dir(talker)
        if not os.path.isdir(base):
            return cands
    names = set()
    for h in packed_hex:
        for suffix in ("_h", "", "_t"):
            names.add(h + suffix + ".dat")
    for name in names:
        for base2, _, files in os.walk(base):
            if name in files:
                cands.append(os.path.join(base2, name))
    # 打包信息里没有对应文件时，按修改时间找最近的（±180s）
    if not cands:
        best = []
        for base2, _, files in os.walk(base):
            for f in files:
                if not f.endswith(".dat"):
                    continue
                p = os.path.join(base2, f)
                try:
                    d = abs(os.path.getmtime(p) - ts)
                except OSError:
                    continue
                if d <= 180:
                    best.append((d, p))
        best.sort()
        cands = [p for _, p in best[:3]]
    order = {"_h.dat": 0, ".dat": 1, "_t.dat": 2}
    return sorted(set(cands), key=lambda p: next(
        (v for k, v in order.items() if os.path.basename(p).endswith(k)), 9))


def find_video(account, names, ts: int) -> Tuple[Optional[str], Optional[str]]:
    """names 可以是多个候选名：XML 里的 md5、packed_info_data 里的文件名。

    返回 (视频, 封面)。
    """
    if isinstance(names, str):
        names = [names]
    names = [n for n in names if n]
    for md5 in names:
        for base, _, files in os.walk(account.video_dir):
            for ext in (".mp4", ".mov"):
                if md5 + ext in files:
                    src = os.path.join(base, md5 + ext)
                    for t in ("%s_thumb.jpg" % md5, "%s.jpg" % md5):
                        tp = os.path.join(base, t)
                        if os.path.exists(tp):
                            return src, tp
                    return src, None
    return None, None


def find_file(account, title: str, ts: int) -> Optional[str]:
    if not title:
        return None
    months = [_month_dir(ts)]
    for m in months:
        p = os.path.join(account.file_dir, m, title)
        if os.path.exists(p):
            return p
    for base, _, files in os.walk(account.file_dir):
        if title in files:
            return os.path.join(base, title)
    return None


def copy_media(src: str, out_dir: str, name: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    dst = os.path.join(out_dir, name)
    if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
        shutil.copy2(src, dst)
    return dst


def guess_title_from_bytes(path: str) -> str:
    """语音/文件没有原始名时的兜底展示名。"""
    return os.path.basename(path)


def hex32_in(data: Optional[bytes]) -> List[str]:
    if not data:
        return []
    return HEX32.findall(data.decode("latin-1", "ignore"))
