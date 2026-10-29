"""归一化入库：解密库 + 媒体 → 一个可检索的 archive.db。

为什么要多一层库
----------------
微信原始库是「一个会话一张 Msg_<md5> 表 + zstd 压缩 + XML 混杂」的形态，
直接拿去分析或喂给模型都是噪声。这里统一成一张 messages 表：

  * uid 幂等（重复跑不会重复入库，可增量）
  * 文字/链接/图片/视频/文件都有各自的 kind 与 media_path
  * 建 FTS5 trigram 索引，中文可以子串检索

每次跑完额外导出 JSONL —— SQLite 需要工具才能读，JSONL 十年后任何编辑器都能打开。
"""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import sqlite3
from typing import Dict, List, Optional, Tuple

import zstandard

from . import media as media_mod
from . import parser

ZSTD = zstandard.ZstdDecompressor()

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(
    uid         TEXT PRIMARY KEY,
    talker      TEXT,
    talker_name TEXT,
    sender      TEXT,
    sender_name TEXT,
    is_self     INTEGER DEFAULT 0,
    ts          INTEGER,
    local_type  INTEGER,
    kind        TEXT,
    text        TEXT,
    url         TEXT,
    quoted      TEXT,
    media_path  TEXT,
    media_kind  TEXT,
    src_table   TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts);
CREATE INDEX IF NOT EXISTS idx_msg_talker ON messages(talker, ts);

CREATE TABLE IF NOT EXISTS media(
    id     TEXT PRIMARY KEY,
    uid    TEXT,
    kind   TEXT,
    name   TEXT,
    src    TEXT,
    out    TEXT,
    size   INTEGER,
    status TEXT
);

CREATE TABLE IF NOT EXISTS sessions(
    talker    TEXT PRIMARY KEY,
    name      TEXT,
    msg_count INTEGER,
    first_ts  INTEGER,
    last_ts   INTEGER
);

CREATE TABLE IF NOT EXISTS contacts(
    username TEXT PRIMARY KEY,
    name     TEXT,
    remark   TEXT,
    nick     TEXT
);

CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);

CREATE VIRTUAL TABLE IF NOT EXISTS msg_fts USING fts5(
    text, talker_name, uid UNINDEXED, tokenize='trigram'
);
"""


def unzstd(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        return ZSTD.stream_reader(io.BytesIO(raw)).read().decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return raw.decode("utf-8", "ignore")


def _safe_name(s: str, limit: int = 40) -> str:
    s = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", s or "")
    return s[:limit] or "x"


class Builder:
    def __init__(self, account, decrypted_dir: str, out_dir: str,
                 archive_db: str, media_key=None, max_media_mb: int = 50):
        self.account = account
        self.dec = decrypted_dir
        self.out_dir = out_dir
        self.media_dir = os.path.join(out_dir, "media")
        self.db_path = archive_db
        self.key = media_key
        self.con = sqlite3.connect(archive_db)
        self.con.executescript(SCHEMA)
        self.cur = self.con.cursor()
        self.names: Dict[str, str] = {}
        self.name2id: Dict[int, str] = {}
        self.talker_by_md5: Dict[str, str] = {}
        self.max_media_bytes = max_media_mb * 1024 * 1024
        self.stats = {"new": 0, "dup": 0, "media_ok": 0, "media_miss": 0,
                      "media_skipped": 0}

    # ---------------------------------------------------------------- 元数据
    def load_contacts(self) -> None:
        p = os.path.join(self.dec, "contact", "contact.db")
        if not os.path.exists(p):
            return
        con = sqlite3.connect(p)
        try:
            for username, remark, nick in con.execute(
                    "select username, remark, nick_name from contact"):
                name = remark or nick or username
                self.names[username] = name
                self.cur.execute(
                    "insert or replace into contacts(username,name,remark,nick) values(?,?,?,?)",
                    (username, name, remark or "", nick or ""))
        finally:
            con.close()
        self.con.commit()

    def load_talkers(self) -> None:
        """Msg_<md5> 表名 → 会话 id：把已知 username 全部算一遍 md5 反查。"""
        cands = set(self.names)
        p = os.path.join(self.dec, "session", "session.db")
        if os.path.exists(p):
            con = sqlite3.connect(p)
            try:
                for (u,) in con.execute("select username from SessionTable"):
                    cands.add(u)
            finally:
                con.close()
        for u in cands:
            self.talker_by_md5[self.account.md5(u)] = u

    # ---------------------------------------------------------------- 媒体
    def _save_image(self, uid: str, talker: str, ts: int,
                    packed: bytes, xml_md5: str) -> Tuple[Optional[str], str]:
        variants = media_mod.find_image_variants(
            self.account, talker, ts, media_mod.hex32_in(packed) or ([xml_md5] if xml_md5 else []))
        for src in variants:
            out = media_mod.save_image(src, self.media_dir, self.key,
                                       name="%s_%s" % (_safe_name(uid, 24),
                                                       os.path.basename(src).split(".")[0][:12]))
            if out:
                return os.path.relpath(out, self.out_dir), os.path.basename(src)
        return None, ""

    def _save_video(self, uid: str, ts: int, md5: str,
                    packed: bytes = b"") -> Tuple[Optional[str], str]:
        names = ([md5] if md5 else []) + media_mod.hex32_in(packed)
        if not names:
            return None, ""
        src, _thumb = media_mod.find_video(self.account, names, ts)
        if not src:
            return None, ""
        if os.path.getsize(src) > self.max_media_bytes:
            self.stats["media_skipped"] += 1
            return None, src
        name = "%s_%s%s" % (_safe_name(uid, 24), os.path.basename(src)[:12],
                            os.path.splitext(src)[1])
        dst = media_mod.copy_media(src, self.media_dir, name)
        return os.path.relpath(dst, self.out_dir), src

    def _save_file(self, uid: str, ts: int, title: str) -> Tuple[Optional[str], str]:
        src = media_mod.find_file(self.account, title, ts)
        if not src:
            return None, ""
        if os.path.getsize(src) > self.max_media_bytes:
            self.stats["media_skipped"] += 1
            return None, src
        name = "%s_%s" % (_safe_name(uid, 24), _safe_name(title, 60))
        dst = media_mod.copy_media(src, self.media_dir, name)
        return os.path.relpath(dst, self.out_dir), src

    # ---------------------------------------------------------------- 主流程
    def run(self, verbose: bool = True) -> Dict:
        self.load_contacts()
        self.load_talkers()
        msg_db = os.path.join(self.dec, "message", "message_0.db")
        if not os.path.exists(msg_db):
            raise SystemExit("找不到解密后的 message_0.db：%s" % msg_db)
        src = sqlite3.connect(msg_db)
        s = src.cursor()

        try:
            for rowid, user_name in s.execute("select rowid, user_name from Name2Id"):
                self.name2id[rowid] = user_name
        except Exception:  # noqa: BLE001
            pass

        tables = [r[0] for r in s.execute(
            "select name from sqlite_master where type='table' and name like 'Msg_%'")]
        for table in tables:
            md5 = table[4:]
            talker = self.talker_by_md5.get(md5, md5)
            talker_name = self.names.get(talker, talker)
            try:
                rows = s.execute(
                    "select local_id, server_id, local_type, create_time, message_content,"
                    " packed_info_data, WCDB_CT_message_content, real_sender_id"
                    " from [%s] order by create_time" % table).fetchall()
            except Exception as exc:  # noqa: BLE001
                if verbose:
                    print("  跳过 %s：%s" % (table, exc))
                continue

            for lid, server_id, ltype, ts, content, packed, ct, sender_id in rows:
                text = unzstd(content) if ct == 4 else (
                    content.decode("utf-8", "ignore") if isinstance(content, bytes) else (content or ""))
                info = parser.parse(ltype, text, packed or b"")
                uid = "%s:%s" % (table, lid)
                sender = self.name2id.get(sender_id, "")
                is_self = 1 if self.account.is_me(sender) else 0
                sname = "我" if is_self else self.names.get(sender, sender or "")

                exists = self.cur.execute(
                    "select 1 from messages where uid=?", (uid,)).fetchone()
                if exists:
                    self.stats["dup"] += 1
                    continue

                media_path, media_src = "", ""
                if info["kind"] == "image":
                    media_path, media_src = self._save_image(uid, talker, ts, packed or b"", info["md5"])
                elif info["kind"] == "video":
                    media_path, media_src = self._save_video(uid, ts, info["md5"], packed or b"")
                elif info["kind"] == "file":
                    media_path, media_src = self._save_file(uid, ts, info["title"])
                if media_path:
                    self.stats["media_ok"] += 1
                elif info["kind"] in ("image", "video", "file"):
                    self.stats["media_miss"] += 1

                self.cur.execute(
                    "insert or replace into messages(uid,talker,talker_name,sender,sender_name,"
                    "is_self,ts,local_type,kind,text,url,quoted,media_path,media_kind,src_table)"
                    " values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (uid, talker, talker_name, sender, sname, is_self, ts, ltype,
                     info["kind"], info["text"], info["url"], info["quoted"],
                     media_path or "", info["kind"] if media_path else "", table))
                self.cur.execute("insert into msg_fts(text,talker_name,uid) values(?,?,?)",
                                 (info["text"], talker_name, uid))
                if media_path:
                    self.cur.execute(
                        "insert or replace into media(id,uid,kind,name,src,out,size,status)"
                        " values(?,?,?,?,?,?,?,?)",
                        (uid, uid, info["kind"], os.path.basename(media_path),
                         media_src, media_path,
                         os.path.getsize(os.path.join(self.out_dir, media_path))
                         if os.path.exists(os.path.join(self.out_dir, media_path)) else 0,
                         "ok"))
                self.stats["new"] += 1
        src.close()

        self.cur.execute("""
            insert or replace into sessions(talker,name,msg_count,first_ts,last_ts)
            select talker, max(talker_name), count(*), min(ts), max(ts)
            from messages group by talker""")
        self.cur.execute("insert or replace into meta(k,v) values('wxid',?)", (self.account.wxid,))
        self.cur.execute("insert or replace into meta(k,v) values('built_at',?)",
                         (datetime.datetime.now().isoformat(timespec="seconds"),))
        self.con.commit()
        return self.stats

    # ---------------------------------------------------------------- 导出
    def export_jsonl(self, path: str, limit: int = 0) -> int:
        q = ("select uid,talker,talker_name,sender,sender_name,is_self,ts,kind,text,url,"
             "quoted,media_path from messages order by ts")
        if limit:
            q += " limit %d" % limit
        n = 0
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for row in self.con.execute(q):
                rec = {
                    "uid": row[0], "talker": row[1], "talker_name": row[2],
                    "sender": row[3], "sender_name": row[4], "is_self": bool(row[5]),
                    "time": datetime.datetime.fromtimestamp(row[6]).isoformat(sep=" ", timespec="seconds"),
                    "ts": row[6], "kind": row[7], "text": row[8], "url": row[9],
                    "quoted": row[10], "media": row[11],
                }
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
        return n

    def export_markdown(self, path: str) -> int:
        """按会话导出可读的 markdown，方便直接归档或喂给别的工具。"""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        sessions = list(self.con.execute(
            "select talker,name,msg_count,first_ts,last_ts from sessions order by last_ts desc"))
        with open(path, "w", encoding="utf-8") as f:
            f.write("# 微信聊天归档\n\n")
            f.write("导出时间：%s\n\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            for talker, name, cnt, first, last in sessions:
                f.write("\n## %s（%d 条）\n\n" % (name or talker, cnt))
                f.write("时间范围：%s ~ %s\n\n" % (
                    datetime.datetime.fromtimestamp(first).strftime("%Y-%m-%d"),
                    datetime.datetime.fromtimestamp(last).strftime("%Y-%m-%d")))
                prev_day = None
                for ts, sender, is_self, kind, text, url, mpath in self.con.execute(
                        "select ts,sender_name,is_self,kind,text,url,media_path from messages"
                        " where talker=? order by ts", (talker,)):
                    day = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                    if day != prev_day:
                        f.write("\n### %s\n\n" % day)
                        prev_day = day
                    when = datetime.datetime.fromtimestamp(ts).strftime("%H:%M")
                    who = "我" if is_self else (sender or "对方")
                    line = "- `%s` **%s**：%s" % (when, who, text.replace("\n", " "))
                    if url and url not in text:
                        line += " <%s>" % url
                    if mpath:
                        line += " → `%s`" % mpath
                    f.write(line + "\n")
        return len(sessions)

    def close(self) -> None:
        self.con.commit()
        self.con.close()
