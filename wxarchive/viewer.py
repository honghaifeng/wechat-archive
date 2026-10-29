"""生成离线浏览界面（单个 HTML + media/ 目录，双击即可看）。

不依赖服务器：数据以内嵌 JSON 形式写进 HTML，图片/视频用相对路径引用 media/，
所以整个 out/ 目录拷到任何地方都能直接打开（包括发给别人）。
"""
from __future__ import annotations

import datetime
import html
import json
import os
import sqlite3
from typing import Dict, List

MAX_MESSAGES = 4000      # 超过这个量建议用 `cli.py search` 或分批导出


def _fmt_ts(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def collect(archive_db: str, limit: int = MAX_MESSAGES) -> Dict:
    con = sqlite3.connect(archive_db)
    con.row_factory = sqlite3.Row
    sessions = [dict(r) for r in con.execute(
        "select talker,name,msg_count,first_ts,last_ts from sessions order by last_ts desc")]
    rows = []
    for r in con.execute(
            "select uid,talker,talker_name,sender_name,is_self,ts,kind,text,url,media_path"
            " from messages order by ts desc limit ?", (limit,)):
        d = dict(r)
        d["time"] = _fmt_ts(d["ts"])
        rows.append(d)
    rows.reverse()
    media_kind = {}
    for r in con.execute("select uid,kind from media"):
        media_kind[r[0]] = r[1]
    for r in rows:
        r["media_kind"] = media_kind.get(r["uid"], "")
    con.close()
    return {"sessions": sessions, "messages": rows, "generated": _fmt_ts(int(datetime.datetime.now().timestamp()))}


HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>微信聊天归档</title>
<style>
  :root{
    --bg:#f7f7f8; --panel:#fff; --line:#e6e6e9; --text:#1c1c1e; --sub:#6b6b70;
    --accent:#1a7f5a; --bubble:#fff; --self:#d8f2e4; --hover:#f0f0f2;
    font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Helvetica Neue",Arial,sans-serif;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}
  header{padding:14px 20px;background:var(--panel);border-bottom:1px solid var(--line);
         display:flex;align-items:baseline;gap:14px;position:sticky;top:0;z-index:5}
  header h1{font-size:15px;margin:0;font-weight:600}
  header .meta{color:var(--sub);font-size:12px}
  header input{margin-left:auto;padding:6px 10px;border:1px solid var(--line);border-radius:6px;
               width:260px;font-size:13px;outline:none;background:#fafafa}
  header input:focus{border-color:var(--accent);background:#fff}
  .wrap{display:flex;height:calc(100vh - 53px)}
  aside{width:260px;flex:0 0 260px;background:var(--panel);border-right:1px solid var(--line);
        overflow:auto;padding:8px 0}
  aside .item{padding:9px 16px;cursor:pointer;border-left:3px solid transparent}
  aside .item:hover{background:var(--hover)}
  aside .item.active{background:#eef7f2;border-left-color:var(--accent)}
  aside .item .n{font-weight:500;font-size:13px;display:block;overflow:hidden;
                 text-overflow:ellipsis;white-space:nowrap}
  aside .item .c{color:var(--sub);font-size:11px}
  main{flex:1;overflow:auto;padding:18px 22px}
  .msg{display:flex;gap:10px;margin-bottom:14px;align-items:flex-start}
  .msg .who{width:70px;flex:0 0 70px;text-align:right;color:var(--sub);font-size:12px;
            padding-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .msg.self{flex-direction:row-reverse}
  .msg.self .who{text-align:left}
  .body{max-width:min(680px,72%);background:var(--bubble);border:1px solid var(--line);
        border-radius:10px;padding:8px 12px;white-space:pre-wrap;word-break:break-word}
  .msg.self .body{background:var(--self);border-color:#bfe6d3}
  .body img,.body video{max-width:100%;border-radius:8px;display:block;margin-top:4px}
  .body .chip{display:inline-block;font-size:11px;color:var(--sub);background:#f3f3f5;
              border-radius:4px;padding:1px 6px;margin-right:6px;vertical-align:1px}
  .body a{color:#0b6bcb;word-break:break-all}
  .day{text-align:center;color:var(--sub);font-size:12px;margin:18px 0 12px}
  .empty{color:var(--sub);text-align:center;margin-top:60px}
  .hit{background:#fff3c4}
  footer{padding:6px 20px;border-top:1px solid var(--line);background:var(--panel);
         color:var(--sub);font-size:11px}
  @media (max-width:820px){aside{display:none}.body{max-width:88%}}
</style>
</head>
<body>
<header>
  <h1>微信聊天归档</h1>
  <span class="meta" id="stat"></span>
  <input id="q" placeholder="搜索文字 / 链接（本地过滤）">
</header>
<div class="wrap">
  <aside id="sessions"></aside>
  <main id="stream"></main>
</div>
<footer id="foot"></footer>
<script id="payload" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('payload').textContent);
let cur = null, kw = '';

function fmtCount(n){ return n>=10000 ? (n/10000).toFixed(1)+'万' : n; }

function renderSessions(){
  const el = document.getElementById('sessions');
  el.innerHTML = '';
  const all = document.createElement('div');
  all.className = 'item' + (cur===null?' active':'');
  all.innerHTML = '<span class="n">全部会话</span><span class="c">'+DATA.messages.length+' 条</span>';
  all.onclick = ()=>{cur=null;renderSessions();renderStream();};
  el.appendChild(all);
  DATA.sessions.forEach(s=>{
    const d = document.createElement('div');
    d.className = 'item' + (cur===s.talker?' active':'');
    d.innerHTML = '<span class="n">'+esc(s.name||s.talker)+'</span><span class="c">'+s.msg_count+' 条</span>';
    d.onclick = ()=>{cur=s.talker;renderSessions();renderStream();};
    el.appendChild(d);
  });
}

function esc(s){ return (s||'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function linkify(text){
  const safe = esc(text);
  return safe.replace(/(https?:\/\/[^\s<>"']+)/g, '<a href="$1" target="_blank" rel="noreferrer">$1</a>');
}

function renderBody(m){
  const chips = {image:'图片', video:'视频', file:'文件', voice:'语音', link:'链接',
                 app:'卡片', quote:'引用', system:'系统', emoji:'表情', location:'位置'};
  let out = '';
  if (chips[m.kind]) out += '<span class="chip">'+chips[m.kind]+'</span>';
  out += linkify(m.text);
  if (m.media_path){
    const p = m.media_path;
    if (/\.(mp4|mov)$/i.test(p)) out += '<video src="'+p+'" controls preload="metadata"></video>';
    else if (/\\.(png|jpe?g|gif|webp)$/i.test(p)) out += '<img src="'+p+'" loading="lazy" alt="图片">';
    else out += '<div><a href="'+p+'" target="_blank">📎 '+esc(p.split('/').pop())+'</a></div>';
  } else if (m.media_kind){
    out += '<div style="color:#9a6b00;font-size:12px">（本地未找到原始文件）</div>';
  }
  return out;
}

function renderStream(){
  const el = document.getElementById('stream');
  let rows = DATA.messages.filter(m=>!cur || m.talker===cur);
  if (kw){ const k = kw.toLowerCase();
    rows = rows.filter(m => (m.text||'').toLowerCase().includes(k) || (m.url||'').toLowerCase().includes(k)); }
  if (!rows.length){ el.innerHTML = '<div class="empty">没有匹配的消息</div>'; return; }
  let html = '', day = '';
  rows.forEach(m=>{
    const d = m.time.slice(0,10);
    if (d!==day){ html += '<div class="day">'+d+'</div>'; day = d; }
    html += '<div class="msg'+(m.is_self?' self':'')+'">'
         +  '<div class="who">'+esc(m.is_self?'我':(m.sender_name||''))+'</div>'
         +  '<div class="body">'+renderBody(m)+'</div></div>';
  });
  el.innerHTML = html;
}

document.getElementById('q').addEventListener('input', e=>{ kw = e.target.value.trim(); renderStream(); });
document.getElementById('stat').textContent = DATA.messages.length + ' 条 · ' + DATA.sessions.length + ' 个会话';
document.getElementById('foot').textContent = '生成于 ' + DATA.generated + ' · 数据仅存在于本机，请勿上传到公开渠道';
renderSessions(); renderStream();
</script>
</body>
</html>
"""


def build(archive_db: str, out_html: str, limit: int = MAX_MESSAGES) -> str:
    data = collect(archive_db, limit)
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    page = HTML.replace("__DATA__", payload)
    os.makedirs(os.path.dirname(out_html) or ".", exist_ok=True)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(page)
    return out_html
