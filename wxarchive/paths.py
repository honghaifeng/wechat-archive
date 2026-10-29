"""路径与账号发现。

微信 4.x for macOS 把数据放在 App 容器里，结构如下：

    ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/
    ├── app_data/{net,ilink}/kvcomm/key_<code>_*.statistic   # 媒体密钥派生用
    └── xwechat_files/<wxid>/                                # 每个账号一个目录
        ├── db_storage/{message,contact,session,...}/*.db     # SQLCipher 加密库
        ├── msg/{attach,video,file}/…                         # 图片 / 视频 / 文件
        └── cache/…                                           # 朋友圈等缓存

本模块只做「找得到」这件事，不做解密，方便单独测试。
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

# 4.x 容器路径（第一个是最常见的）
CONTAINER_CANDIDATES = [
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents",
    # 部分早期 4.0 版本
    "~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat",
]

# 3.x 老版本（本工具不支持，仅用于给出明确提示）
LEGACY_CANDIDATES = [
    "~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/2.0b4.0.9",
]

WECHAT_APP_CANDIDATES = [
    "/Applications/WeChat.app",
    "/Applications/微信.app",
    "~/Applications/WeChat.app",
]


def _expand(p: str) -> str:
    return os.path.expanduser(p)


def find_container() -> Optional[str]:
    """返回微信容器 Documents 目录。"""
    for p in CONTAINER_CANDIDATES:
        p = _expand(p)
        if os.path.isdir(os.path.join(p, "xwechat_files")):
            return p
    return None


def find_legacy_container() -> Optional[str]:
    for p in LEGACY_CANDIDATES:
        p = _expand(p)
        if os.path.isdir(p):
            return p
    return None


def find_app() -> Optional[str]:
    for p in WECHAT_APP_CANDIDATES:
        p = _expand(p)
        if os.path.isdir(p):
            return p
    return None


@dataclass
class Account:
    """一个微信账号在磁盘上的全部入口。"""

    root: str                      # .../xwechat_files/<wxid>
    container: str                 # .../Data/Documents
    wxid: str                      # 目录名，可能带 _8a1e 这类设备后缀
    db_storage: str = ""
    msg_dir: str = ""
    attach_dir: str = ""
    video_dir: str = ""
    file_dir: str = ""
    cache_dir: str = ""
    kvcomm_files: List[str] = field(default_factory=list)
    wxid_clean: str = ""           # 去掉后缀的 wxid，库里的用户名与它一致

    def __post_init__(self):
        self.db_storage = os.path.join(self.root, "db_storage")
        self.msg_dir = os.path.join(self.root, "msg")
        self.attach_dir = os.path.join(self.msg_dir, "attach")
        self.video_dir = os.path.join(self.msg_dir, "video")
        self.file_dir = os.path.join(self.msg_dir, "file")
        self.cache_dir = os.path.join(self.root, "cache")
        parts = self.wxid.split("_")
        self.wxid_clean = ("_".join(parts[:2])
                           if self.wxid.startswith("wxid_") and len(parts) >= 3
                           else self.wxid)

    def is_me(self, username: str) -> bool:
        return username in (self.wxid, self.wxid_clean)

    # ---- 关键文件 ----
    @property
    def message_db(self) -> str:
        return os.path.join(self.db_storage, "message", "message_0.db")

    @property
    def contact_db(self) -> str:
        return os.path.join(self.db_storage, "contact", "contact.db")

    @property
    def session_db(self) -> str:
        return os.path.join(self.db_storage, "session", "session.db")

    def db_files(self) -> List[str]:
        out = []
        for base, _, files in os.walk(self.db_storage):
            for f in files:
                if f.endswith(".db"):
                    out.append(os.path.join(base, f))
        return sorted(out)

    # ---- 目录名即 md5(会话 id) ----
    @staticmethod
    def md5(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    def chat_attach_dir(self, talker: str) -> str:
        return os.path.join(self.attach_dir, self.md5(talker))

    # ---- 媒体密钥的 code（UIN） ----
    def media_code(self) -> Optional[int]:
        """从 kvcomm 统计文件名里取第一个数字段，例如
        key_2198118493_4066647863_1_1793258905_..._input.statistic -> 2198118493
        """
        for f in self.kvcomm_files:
            m = re.search(r"key_(\d+)_", os.path.basename(f))
            if m:
                return int(m.group(1))
        return None


def _find_kvcomm(container: str) -> List[str]:
    pats = [
        os.path.join(container, "app_data", "**", "key_*.statistic"),
        os.path.join(container, "**", "kvcomm", "key_*"),
    ]
    seen, out = set(), []
    for pat in pats:
        for f in glob.glob(pat, recursive=True):
            if f in seen:
                continue
            if os.path.isfile(f) and os.path.getsize(f) > 0:
                seen.add(f)
                out.append(f)
    return out


def find_accounts(container: Optional[str] = None) -> List[Account]:
    """列出所有本地登录过、且留有数据库的账号。"""
    container = container or find_container()
    if not container:
        return []
    base = os.path.join(container, "xwechat_files")
    kvcomm = _find_kvcomm(container)
    out = []
    for name in sorted(os.listdir(base)):
        root = os.path.join(base, name)
        if not os.path.isdir(root) or name == "all_users":
            continue
        if not os.path.isdir(os.path.join(root, "db_storage")):
            continue
        out.append(Account(root=root, container=container, wxid=name, kvcomm_files=kvcomm))
    return out


def pick_account(wxid: Optional[str] = None, container: Optional[str] = None) -> Account:
    accounts = find_accounts(container)
    if not accounts:
        legacy = find_legacy_container()
        if legacy:
            raise SystemExit(
                "只找到微信 3.x 的旧数据目录（%s）。\n"
                "本项目针对 4.x 磁盘格式，请先把微信升级到 4.x 并登录一次。" % legacy
            )
        raise SystemExit(
            "没有找到微信数据目录。请确认：\n"
            "  1) 已在「设置 → 通用 → 文件管理」里开启本地文件存储；\n"
            "  2) 当前用户至少登录过一次微信。"
        )
    if wxid:
        for a in accounts:
            if a.wxid == wxid:
                return a
        raise SystemExit("找不到 wxid=%s，可选：%s" % (wxid, [a.wxid for a in accounts]))
    if len(accounts) == 1:
        return accounts[0]
    # 多个账号时选消息库最大的那个
    return max(accounts, key=lambda a: os.path.getsize(a.message_db)
               if os.path.exists(a.message_db) else 0)
