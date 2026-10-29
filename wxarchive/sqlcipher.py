"""微信 4.x 本地库解密（SQLCipher 4，AES-256 + HMAC-SHA512）。

参数全部来自实测，不是猜的：

    PAGE      = 4096            每页大小
    SALT      = 16              文件头 16 字节是盐
    IV        = 16              每页末尾保留区的前 16 字节
    HMAC      = 64              每页末尾保留区的后 64 字节
    RESERVE   = 80 = IV + HMAC
    encKey    = PBKDF2-HMAC-SHA512(rawKey, salt, 256000, 32)
    第 1 页   = [salt 16][ciphertext 4000][IV 16][HMAC 64]
    第 N 页   = [ciphertext 4016][IV 16][HMAC 64]

一个容易踩的坑：SQLCipher 用 salt 覆盖了 SQLite 文件头的前 16 字节，
解密后必须手动补回 b"SQLite format 3\\x00"，否则 sqlite3 打不开。
"""
from __future__ import annotations

import os
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2

PAGE, SALT, IV, HMAC, RES = 4096, 16, 16, 64, 80
SQLITE_HDR = b"SQLite format 3\x00"
KDF_ROUNDS = 256000


def _derive(raw_key: bytes, salt: bytes, rounds: int = KDF_ROUNDS) -> bytes:
    return PBKDF2(raw_key, salt, 32, count=rounds, hmac_hash_module=SHA512)


def looks_like_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_HDR
    except OSError:
        return False


def test_key(db_path: str, raw_key: bytes, rounds: int = KDF_ROUNDS) -> bool:
    """只解第一页来判断密钥对不对，成本极低。"""
    try:
        with open(db_path, "rb") as f:
            head = f.read(PAGE)
    except OSError:
        return False
    if len(head) < PAGE or head[:16] == SQLITE_HDR[:16]:
        return False
    enc_key = _derive(raw_key, head[:SALT], rounds)
    iv = head[PAGE - RES: PAGE - RES + IV]
    pt = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(head[SALT: PAGE - RES])
    # 页头前 2 字节是页大小：0x1000 = 4096
    return pt[:2] == b"\x10\x00"


def decrypt_file(src: str, dst: str, raw_key: bytes,
                 rounds: int = KDF_ROUNDS) -> str:
    """解密单个库；返回 ok / skip（已经是明文）/ badkey / err:*。"""
    with open(src, "rb") as f:
        data = f.read()
    if len(data) < PAGE:
        return "skip"
    if data[:16] == SQLITE_HDR[:16]:
        return "skip"

    enc_key = _derive(raw_key, data[:SALT], rounds)
    out = bytearray()
    pages = len(data) // PAGE
    for p in range(pages):
        page = data[p * PAGE:(p + 1) * PAGE]
        iv = page[PAGE - RES: PAGE - RES + IV]
        aes = AES.new(enc_key, AES.MODE_CBC, iv)
        if p == 0:
            pt = aes.decrypt(page[SALT: PAGE - RES])
            if pt[:2] != b"\x10\x00":
                return "badkey"
            out += SQLITE_HDR + pt + page[PAGE - RES:]
        else:
            out += aes.decrypt(page[0: PAGE - RES]) + page[PAGE - RES:]

    tail = data[pages * PAGE:]
    if tail:
        out += tail
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "wb") as f:
        f.write(out)
    return "ok"


def decrypt_storage(db_storage: str, out_dir: str, raw_key: bytes,
                    rounds: int = KDF_ROUNDS, verbose: bool = True):
    """解密整个 db_storage 目录，返回 (成功数, 失败列表)。"""
    ok, failed = 0, []
    for base, _, files in os.walk(db_storage):
        for name in sorted(files):
            if not name.endswith(".db"):
                continue
            src = os.path.join(base, name)
            rel = os.path.relpath(src, db_storage)
            dst = os.path.join(out_dir, rel)
            try:
                r = decrypt_file(src, dst, raw_key, rounds)
            except Exception as exc:  # noqa: BLE001
                r = "err:%s" % exc
            if r == "ok":
                ok += 1
                if verbose:
                    print("  ok   %-42s %9d B" % (rel, os.path.getsize(dst)))
            elif r in ("badkey",) or r.startswith("err"):
                failed.append((rel, r))
                if verbose:
                    print("  FAIL %-42s %s" % (rel, r))
    return ok, failed


def best_rounds(db_path: str, raw_key: bytes,
                candidates=(256000, 64000, 4000)) -> Optional[int]:
    """微信不同版本 KDF 轮数可能不同，挨个试一遍。"""
    for r in candidates:
        if test_key(db_path, raw_key, r):
            return r
    return None
