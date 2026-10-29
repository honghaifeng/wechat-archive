"""命令行入口：``python3 -m wxarchive <命令>``。

一条命令跑通全流程：

    python3 -m wxarchive run

分步执行（排查问题时用）：

    python3 -m wxarchive doctor      # 先看环境对不对
    python3 -m wxarchive key         # 只取密钥
    python3 -m wxarchive decrypt     # 只解密数据库
    python3 -m wxarchive export      # 只做媒体解码 + 入库 + 生成界面
    python3 -m wxarchive search 关键词
    python3 -m wxarchive list
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import sqlite3
import sys
import time
from typing import Optional

from . import archive as archive_mod
from . import keycap, media as media_mod, paths, sqlcipher, viewer


# ------------------------------------------------------------------ 工作目录

def workdir(path: Optional[str]) -> str:
    base = os.path.abspath(path or os.environ.get("WXARCHIVE_DIR") or "wxarchive_data")
    for sub in ("decrypted", "media"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    return base


def keys_file(base: str) -> str:
    return os.path.join(base, "keys.json")


def load_keys(base: str) -> dict:
    p = keys_file(base)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}


def save_keys(base: str, data: dict) -> None:
    p = keys_file(base)
    with open(p, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(p, 0o600)


# ------------------------------------------------------------------ 各子命令

def cmd_doctor(args) -> int:
    base = workdir(args.workdir)
    print("== 环境 ==")
    print("  微信客户端        %s" % (paths.find_app() or "未找到（可继续，但取密钥需要它）"))
    print("  SIP               %s" % keycap.sip_status())
    print("  lldb              %s" % ("ok" if keycap.sip_disabled() else "需要关闭 SIP 才能附加进程"))
    try:
        import Crypto  # noqa: F401
        print("  pycryptodome      ok")
    except ImportError:
        print("  pycryptodome      缺失 → pip install -r requirements.txt")
    try:
        import zstandard  # noqa: F401
        print("  zstandard         ok")
    except ImportError:
        print("  zstandard         缺失 → pip install -r requirements.txt")
    print("  sqlite FTS5       %s" % _fts5_status())

    print("\n== 账号 ==")
    accts = paths.find_accounts()
    if not accts:
        print("  没有找到 4.x 数据目录")
        return 1
    for a in accts:
        dbs = a.db_files()
        print("  %s" % a.wxid)
        print("      数据目录   %s" % a.root)
        print("      数据库     %d 个" % len(dbs))
        print("      消息库     %s" % ("ok" if os.path.exists(a.message_db) else "缺失"))
        print("      媒体 code  %s" % a.media_code())

    acc = paths.pick_account(args.wxid)
    print("\n== 密钥 ==")
    keys = load_keys(base)
    rec = keys.get(acc.wxid)
    if rec and rec.get("db_key"):
        ok = sqlcipher.test_key(acc.message_db, bytes.fromhex(rec["db_key"]),
                                rec.get("kdf_rounds", 256000))
        print("  数据库密钥       %s（%s）" % ("有效" if ok else "已失效，需要重新抓", rec["db_key"][:8] + "…"))
    else:
        print("  数据库密钥       未抓取（运行 `cli.py key`）")

    mk = media_mod.derive_media_key(acc)
    if mk:
        print("  媒体密钥         code=%d xor=0x%02x（可从 kvcomm 离线派生）" % (mk.code, mk.xor))
    else:
        print("  媒体密钥         派生失败（没有 V2 样本文件？）")

    print("\n== 归档 ==")
    adb = os.path.join(base, "archive.db")
    if os.path.exists(adb):
        con = sqlite3.connect(adb)
        try:
            n = con.execute("select count(*) from messages").fetchone()[0]
            s = con.execute("select count(*) from sessions").fetchone()[0]
            print("  消息 / 会话      %d / %d" % (n, s))
            for kind, c in con.execute("select kind,count(*) from messages group by kind order by 2 desc"):
                print("      %-8s %d" % (kind, c))
        finally:
            con.close()
    else:
        print("  还没有归档（运行 `cli.py run`）")
    return 0


def _fts5_status() -> str:
    try:
        con = sqlite3.connect(":memory:")
        con.execute("create virtual table t using fts5(a, tokenize='trigram')")
        con.close()
        return "ok（含 trigram，可中文子串检索）"
    except Exception as exc:  # noqa: BLE001
        return "不可用：%s" % exc


def cmd_key(args) -> int:
    base = workdir(args.workdir)
    acc = paths.pick_account(args.wxid)
    print("账号：%s" % acc.wxid)
    key = keycap.capture(acc, seconds=args.seconds, restart=not args.no_restart)
    if not key:
        print("\n没抓到可用的密钥。常见原因：")
        print("  · SIP 没关（csrutil status 应为 disabled）")
        print("  · 断点挂上之前微信已经打开了库 → 换 --seconds 60 再试")
        print("  · 微信版本改了 KDF 实现 → 需要重新逆向（见 docs/TROUBLESHOOTING.md）")
        return 1
    rounds = sqlcipher.best_rounds(acc.message_db, key) or 256000
    keys = load_keys(base)
    keys[acc.wxid] = {
        "db_key": key.hex(),
        "kdf_rounds": rounds,
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_keys(base, keys)
    print("已保存到 %s（权限 600）" % keys_file(base))
    return 0


def cmd_decrypt(args) -> int:
    base = workdir(args.workdir)
    acc = paths.pick_account(args.wxid)
    rec = load_keys(base).get(acc.wxid, {})
    if not rec.get("db_key"):
        print("还没有密钥，先运行：python3 -m wxarchive key")
        return 1
    key = bytes.fromhex(rec["db_key"])
    rounds = rec.get("kdf_rounds", 256000)
    if not sqlcipher.test_key(acc.message_db, key, rounds):
        print("缓存的密钥失效了（微信可能改过库），请重新抓：python3 -m wxarchive key")
        return 1
    ok, failed = sqlcipher.decrypt_storage(acc.db_storage, os.path.join(base, "decrypted"), key, rounds)
    print("解密完成：%d 个成功，%d 个失败" % (ok, len(failed)))
    return 0 if ok else 1


def cmd_export(args) -> int:
    base = workdir(args.workdir)
    acc = paths.pick_account(args.wxid)
    dec = os.path.join(base, "decrypted")
    if not os.path.exists(os.path.join(dec, "message", "message_0.db")):
        print("还没有解密后的库，先运行：python3 -m wxarchive decrypt")
        return 1
    mk = media_mod.derive_media_key(acc)
    if mk:
        print("媒体密钥：code=%d（离线派生成功）" % mk.code)
    else:
        print("媒体密钥派生失败，图片只能保留 .dat 原文件")

    adb = os.path.join(base, "archive.db")
    b = archive_mod.Builder(acc, dec, base, adb, media_key=mk,
                            max_media_mb=args.max_media_mb)
    st = b.run()
    n = b.export_jsonl(os.path.join(base, "export.jsonl"))
    m = b.export_markdown(os.path.join(base, "chats.md"))
    b.close()
    html = viewer.build(adb, os.path.join(base, "index.html"))
    print("新增 %d 条，跳过重复 %d 条；媒体命中 %d，缺失 %d，超出体积上限未拷贝 %d"
          % (st["new"], st["dup"], st["media_ok"], st["media_miss"], st["media_skipped"]))
    print("导出：%s（%d 条）  %s（%d 个会话）  %s" % (
        os.path.join(base, "export.jsonl"), n, os.path.join(base, "chats.md"), m, html))
    return 0


def cmd_run(args) -> int:
    base = workdir(args.workdir)
    acc = paths.pick_account(args.wxid)
    print("账号：%s" % acc.wxid)

    rec = load_keys(base).get(acc.wxid, {})
    key = bytes.fromhex(rec["db_key"]) if rec.get("db_key") else None
    if not key or not sqlcipher.test_key(acc.message_db, key, rec.get("kdf_rounds", 256000)):
        if args.no_capture:
            print("没有可用密钥，且指定了 --no-capture")
            return 1
        print("需要抓取数据库密钥（微信会被自动重启一次）…")
        key = keycap.capture(acc, seconds=args.seconds)
        if not key:
            return 1
        rounds = sqlcipher.best_rounds(acc.message_db, key) or 256000
        keys = load_keys(base)
        keys[acc.wxid] = {"db_key": key.hex(), "kdf_rounds": rounds,
                          "captured_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_keys(base, keys)
    else:
        print("复用已保存的密钥（%s…）" % rec["db_key"][:8])

    rounds = load_keys(base)[acc.wxid].get("kdf_rounds", 256000)
    print("\n解密数据库…")
    ok, failed = sqlcipher.decrypt_storage(acc.db_storage, os.path.join(base, "decrypted"), key, rounds)
    print("  %d 个库解密成功，%d 个失败" % (ok, len(failed)))

    print("\n媒体与入库…")
    mk = media_mod.derive_media_key(acc)
    print("  媒体密钥：%s" % (("code=%d" % mk.code) if mk else "派生失败"))
    adb = os.path.join(base, "archive.db")
    b = archive_mod.Builder(acc, os.path.join(base, "decrypted"), base, adb,
                            media_key=mk, max_media_mb=args.max_media_mb)
    st = b.run()
    n = b.export_jsonl(os.path.join(base, "export.jsonl"))
    m = b.export_markdown(os.path.join(base, "chats.md"))
    b.close()
    html = viewer.build(adb, os.path.join(base, "index.html"))
    print("  新增 %d 条，重复 %d 条；媒体命中 %d，缺失 %d，超限未拷贝 %d"
          % (st["new"], st["dup"], st["media_ok"], st["media_miss"], st["media_skipped"]))
    print("\n完成：")
    print("  浏览界面  %s" % html)
    print("  JSONL     %s（%d 条）" % (os.path.join(base, "export.jsonl"), n))
    print("  Markdown  %s（%d 个会话）" % (os.path.join(base, "chats.md"), m))
    print("  数据库    %s" % adb)
    return 0


def cmd_search(args) -> int:
    base = workdir(args.workdir)
    adb = os.path.join(base, "archive.db")
    if not os.path.exists(adb):
        print("还没有归档，先运行 python3 -m wxarchive run")
        return 1
    con = sqlite3.connect(adb)
    con.row_factory = sqlite3.Row
    kw = args.keyword.replace('"', '""')
    sql = ("select m.time, m.talker_name, m.sender_name, m.is_self, m.kind, m.text, m.media_path"
           " from msg_fts f join (select uid, datetime(ts,'unixepoch','localtime') time,"
           " talker_name, sender_name, is_self, kind, text, media_path from messages) m"
           " on m.uid = f.uid where msg_fts match ? order by m.uid limit ?")
    try:
        rows = con.execute(sql, ('"%s"' % kw, args.limit)).fetchall()
    except sqlite3.OperationalError:
        rows = con.execute("select datetime(ts,'unixepoch','localtime') time, talker_name,"
                           " sender_name, is_self, kind, text, media_path from messages"
                           " where text like ? order by ts desc limit ?",
                           ("%%%s%%" % args.keyword, args.limit)).fetchall()
    for r in rows:
        who = "我" if r["is_self"] else (r["sender_name"] or "")
        print("[%s] %s · %s：%s" % (r["time"], r["talker_name"], who,
                                    (r["text"] or "").replace("\n", " ")[:160]))
        if r["media_path"]:
            print("        → %s" % r["media_path"])
    print("\n共 %d 条" % len(rows))
    return 0


def cmd_list(args) -> int:
    base = workdir(args.workdir)
    adb = os.path.join(base, "archive.db")
    if not os.path.exists(adb):
        print("还没有归档，先运行 python3 -m wxarchive run")
        return 1
    con = sqlite3.connect(adb)
    for talker, name, cnt, first, last in con.execute(
            "select talker,name,msg_count,first_ts,last_ts from sessions order by last_ts desc"):
        print("%-28s %-16s %5d 条  %s ~ %s" % (
            (name or talker)[:26], talker[:16], cnt,
            time.strftime("%Y-%m-%d", time.localtime(first)),
            time.strftime("%Y-%m-%d", time.localtime(last))))
    return 0


# ------------------------------------------------------------------ 参数

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wxarchive", description="微信聊天记录本地归档（macOS 4.x）")
    p.add_argument("--workdir", "-w", help="工作目录（默认 ./wxarchive_data）")
    p.add_argument("--wxid", help="指定账号（默认自动选择）")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, fn, help_text in [
        ("run", cmd_run, "全流程：取密钥 → 解密 → 媒体 → 入库 → 生成界面"),
        ("doctor", cmd_doctor, "环境与数据自检"),
        ("key", cmd_key, "只抓数据库密钥"),
        ("decrypt", cmd_decrypt, "只解密数据库"),
        ("export", cmd_export, "只做媒体解码 / 入库 / 生成界面"),
        ("list", cmd_list, "列出会话"),
    ]:
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=fn)

    sp = sub.add_parser("search", help="全文检索")
    sp.add_argument("keyword")
    sp.add_argument("--limit", type=int, default=30)
    sp.set_defaults(func=cmd_search)

    # run/key 的额外参数
    for name in ("run", "key"):
        sp = sub._name_parser_map[name]
        sp.add_argument("--seconds", type=int, default=45, help="断点等待秒数")
        sp.add_argument("--no-restart", action="store_true", help="不重启微信（微信已打开库时抓不到）")
    sub._name_parser_map["run"].add_argument("--no-capture", action="store_true",
                                            help="不用抓密钥，只用缓存里的")
    for name in ("run", "export"):
        sub._name_parser_map[name].add_argument(
            "--max-media-mb", type=int, default=50,
            help="单个文件/视频超过这个体积就只记路径不拷贝（默认 50MB）")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
