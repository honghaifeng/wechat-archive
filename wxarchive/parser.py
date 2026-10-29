"""消息解析：把微信的 local_type + XML 正文，归一化成结构化字段。

微信 4.x 的 local_type 是高 32 位子类型 + 低 32 位主类型，例如
``25769803825 == 0x6_00000031``：主类型 49（appmsg 卡片），子类型 6。
卡片内部还有 <appmsg><type> 区分文件 / 链接 / 小程序 / 引用……

输出统一为 dict，交给 archive 入库；这样以后微信改字段，只需要改这一层。
"""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

URL_RE = re.compile(r"https?://[^\s\u4e00-\u9fff<>\"']+", re.I)
PLACEHOLDER_RE = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.S)

# 卡片子类型
APP_FILE = "6"
APP_LINK = "5"
APP_QUOTE = "57"
APP_MINIPROG = "33"
APP_CHANNEL = "51"
APP_MUSIC = "3"
APP_REDPACKET = "2001"

MAIN_TEXT = 1
MAIN_IMAGE = 3
MAIN_VOICE = 34
MAIN_CONTACT_CARD = 42
MAIN_VIDEO = 43
MAIN_EMOJI = 47
MAIN_LOCATION = 48
MAIN_APPMSG = 49
MAIN_VOIP = 50
MAIN_SYSTEM = 10000


def _text_of(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _find(root, tag: str) -> Optional[str]:
    if root is None:
        return None
    v = root.find(".//" + tag)
    if v is None:
        return None
    t = (v.text or "").strip()
    return html.unescape(t) if t else None


def strip_tags(s: str) -> str:
    if not s:
        return ""
    if "<" in s:
        s = re.sub(r"<br\s*/?>", "\n", s)
        s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = URL_RE.findall(text)
    # 句末标点别带进去
    return [u.rstrip(").,;，。；）】]") for u in urls]


def parse(local_type: int, content: str, packed: bytes = b"") -> Dict:
    """返回 {kind, text, url, title, md5, quoted}"""
    main = local_type & 0xFFFFFFFF
    out: Dict = {"kind": "other", "text": "", "url": "", "title": "",
                 "md5": "", "quoted": "", "appmsg_type": ""}
    content = content or ""

    if main == MAIN_TEXT:
        out["kind"] = "text"
        out["text"] = strip_tags(content)
        urls = extract_urls(out["text"])
        if urls:
            out["url"] = urls[0]
        quoted = _find_safe(content, "refermsg")
        if quoted:
            out["quoted"] = quoted
        if not out["text"] and quoted:
            out["kind"] = "quote"
            out["text"] = quoted
        return out

    if main == MAIN_IMAGE:
        out["kind"] = "image"
        out["md5"] = _xml_attr(content, "img", "md5") or ""
        out["text"] = "[图片]" + ("" if out["md5"] else "（无 md5）")
        return out

    if main == MAIN_VOICE:
        out["kind"] = "voice"
        secs = _xml_attr(content, "voicemsg", "voicelength") or "0"
        try:
            secs = str(round(int(secs) / 1000))
        except ValueError:
            secs = "0"
        out["text"] = "[语音 %s″]" % secs
        return out

    if main == MAIN_VIDEO:
        out["kind"] = "video"
        out["md5"] = _xml_attr(content, "videomsg", "md5") or ""
        out["text"] = "[视频]"
        return out

    if main == MAIN_EMOJI:
        out["kind"] = "emoji"
        out["md5"] = _xml_attr(content, "emoji", "md5") or ""
        out["text"] = "[表情]"
        return out

    if main == MAIN_LOCATION:
        out["kind"] = "location"
        out["text"] = "[位置] %s %s" % (_find_safe(content, "label") or "",
                                        _find_safe(content, "poiname") or "")
        return out

    if main == MAIN_CONTACT_CARD:
        out["kind"] = "card"
        out["text"] = "[名片] " + (_xml_attr(content, "msg", "nickname") or "")
        return out

    if main == MAIN_SYSTEM:
        out["kind"] = "system"
        out["text"] = strip_tags(content)[:500]
        return out

    if main == MAIN_APPMSG:
        return _parse_appmsg(content, out)

    out["kind"] = "other"
    out["text"] = strip_tags(content)[:300] or "[type=%d]" % main
    return out


def _parse_appmsg(content: str, out: Dict) -> Dict:
    title = _find_safe(content, "title") or ""
    des = _find_safe(content, "des") or ""
    url = _find_safe(content, "url") or ""
    app_type = _find_safe(content, "type") or ""
    out["appmsg_type"] = app_type
    out["title"] = title

    if app_type == APP_FILE:
        out["kind"] = "file"
        out["text"] = "[文件] " + title
        return out
    if app_type == APP_LINK:
        out["kind"] = "link"
        out["url"] = url
        out["text"] = "[链接] " + title + ("\n" + des if des else "")
        return out
    if app_type == APP_QUOTE:
        out["kind"] = "quote"
        quoted = _find_safe(content, "refermsg") or des
        out["quoted"] = quoted or ""
        out["text"] = "[引用] " + (quoted or title)
        return out
    if app_type in (APP_MINIPROG, "36", APP_CHANNEL, APP_MUSIC):
        out["kind"] = "app"
        out["url"] = url
        out["text"] = "[小程序/应用] " + title
        return out
    if app_type == APP_REDPACKET:
        out["kind"] = "app"
        out["text"] = "[红包] " + title
        return out

    out["kind"] = "app"
    out["text"] = "[卡片 type=%s] %s %s" % (app_type, title, des)
    out["url"] = url
    return out


# ------------------------------------------------------------------ 低层工具

def _xml_attr(content: str, tag: str, attr: str) -> Optional[str]:
    if not content or "<" not in content:
        return None
    m = re.search(r"<%s\b[^>]*\b%s=\"([^\"]*)\"" % (re.escape(tag), re.escape(attr)), content)
    return m.group(1) if m else None


def _find_safe(content: str, tag: str) -> Optional[str]:
    """容错取标签文本：XML 不合法（微信常见）时退化为正则。"""
    if not content or "<" not in content:
        return None
    try:
        root = ET.fromstring(content)
        v = root.find(".//" + tag)
        if v is not None and (v.text or "").strip():
            return html.unescape(v.text.strip())
        return None
    except Exception:  # noqa: BLE001
        m = re.search(r"<%s[^>]*>(.*?)</%s>" % (re.escape(tag), re.escape(tag)),
                      content, re.S)
        if not m:
            return None
        txt = PLACEHOLDER_RE.sub(r"\1", m.group(1))
        return strip_tags(txt)
