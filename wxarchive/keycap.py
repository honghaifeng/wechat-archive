"""从微信进程里取 SQLCipher 数据库密钥（macOS）。

原理
----
微信用 WCDB/SQLCipher 打开本地库时，一定会在 SQLCipher 里派生密钥，
而 SQLCipher 走的是系统 CommonCrypto 的 ``CCKeyDerivationPBKDF``。
我们在这个函数上下断点，命中时读它的入参（arm64 下 x1=password 指针、
x2=长度、x6=迭代轮数），就能拿到 32 字节原始密钥——不用猜它藏在内存哪个角落。

两个必须知道的前提
------------------
1. **时机**：密钥只在「库被打开」的那一瞬间出现在内存里，之后就被释放了。
   所以必须在微信启动的瞬间挂上断点——本脚本会自动退出再拉起微信来完成这件事。
2. **权限**：读别的进程内存需要调试权限。macOS 上要求 ``csrutil status`` 为
   disabled（SIP 关闭），否则 lldb 无法 attach。

抓到的候选密钥会用真实数据库逐个验证，验证不过的不算数。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

from . import paths, sqlcipher

# lldb 里跑的脚本：装断点、收密钥、到点自动 detach
_LLDB_SCRIPT = r'''
import lldb, os, threading

OUT = r"{out}"

class C:
    keys = []
    hits = 0

def _dump():
    with open(OUT, "w") as f:
        for k in C.keys:
            f.write(k + "\n")

def on_kdf(frame, bp_loc, internal_dict):
    try:
        C.hits += 1
        x1 = frame.FindRegister("x1").GetValueAsUnsigned()
        x2 = frame.FindRegister("x2").GetValueAsUnsigned()
        x6 = frame.FindRegister("x6").GetValueAsUnsigned()
        if not x1 or not (8 <= x2 <= 128):
            return False
        process = frame.GetThread().GetProcess()
        err = lldb.SBError()
        data = process.ReadMemory(x1, x2, err)
        if not err.Success() or not data:
            return False
        hx = data.hex()
        if hx not in C.keys:
            C.keys.append(hx)
            _dump()
            print("WXCAP rounds=%d len=%d key=%s" % (x6, x2, hx))
    except Exception as e:
        print("WXCAP err %s" % e)
    return False

@lldb.command("wxcap")
def setup(debugger, command, exe_ctx, result, internal_dict):
    target = exe_ctx.GetTarget()
    process = exe_ctx.GetProcess()
    bp = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
    bp.SetScriptCallbackFunction("__main__.on_kdf")
    print("WXCAP breakpoint id=%d locs=%d" % (bp.GetID(), bp.GetNumLocations()))
    try:
        secs = int(command.strip()) if command.strip() else 45
    except Exception:
        secs = 45
    def release():
        try:
            process.Detach()
            print("WXCAP detached hits=%d keys=%d" % (C.hits, len(C.keys)))
        except Exception:
            pass
    t = threading.Timer(secs, release)
    t.daemon = True
    t.start()
    _dump()
'''


def sip_status() -> str:
    try:
        out = subprocess.run(["csrutil", "status"], capture_output=True,
                             text=True, timeout=10).stdout
        return out.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def sip_disabled() -> bool:
    return "disabled" in sip_status().lower()


def wechat_pid() -> int | None:
    for pat in ("MacOS/WeChat$", "MacOS/Weixin$"):
        try:
            out = subprocess.run(["pgrep", "-f", pat], capture_output=True,
                                 text=True, timeout=10).stdout.split()
        except Exception:  # noqa: BLE001
            out = []
        if out:
            return int(out[0])
    return None


def _quit_wechat(pid: int) -> None:
    subprocess.run(["osascript", "-e", 'quit app "WeChat"'],
                   capture_output=True, timeout=30)
    for _ in range(100):
        if wechat_pid() is None:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, 15)
    except OSError:
        pass


def _launch_wechat() -> int | None:
    app = paths.find_app()
    if app:
        subprocess.run(["open", "-a", app], capture_output=True)
    else:
        subprocess.run(["open", "-a", "WeChat"], capture_output=True)
    for _ in range(600):          # 最多等 30s
        pid = wechat_pid()
        if pid:
            return pid
        time.sleep(0.05)
    return None


def _parse_keys(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [ln.strip() for ln in f if re.fullmatch(r"[0-9a-f]{16,128}", ln.strip())]


def capture(account, seconds: int = 45, restart: bool = True,
            keep_candidates: bool = True) -> bytes | None:
    """返回 32 字节的数据库密钥；失败返回 None。"""
    if shutil.which("lldb") is None:
        raise SystemExit("找不到 lldb。请先安装 Xcode Command Line Tools：xcode-select --install")

    if not sip_disabled():
        print("!" * 68)
        print("SIP 当前是开启的，lldb 无法附加微信进程。")
        print("请先在恢复模式执行: csrutil disable   （取到密钥后可以再打开）")
        print("!" * 68)

    pid = wechat_pid()
    if restart:
        if pid:
            print("[1/4] 退出微信（重新打开只为捕捉启动瞬间的密钥派生）…")
            _quit_wechat(pid)
        print("[2/4] 启动微信…")
        pid = _launch_wechat()
        if not pid:
            raise SystemExit("微信没能启动，请手动打开后重试。")
    elif not pid:
        raise SystemExit("微信没在运行，请先打开微信，或用 --restart 让脚本自动重启。")

    tmp = tempfile.mkdtemp(prefix="wxcap-")
    out_path = os.path.join(tmp, "keys.txt")
    script_path = os.path.join(tmp, "wxcap_lldb.py")
    with open(script_path, "w") as f:
        f.write(_LLDB_SCRIPT.replace("{out}", out_path))

    print("[3/4] 附加进程 %d 并在 CCKeyDerivationPBKDF 上等 %ds …" % (pid, seconds))
    time.sleep(0.3)
    cmd = ["lldb", "-p", str(pid), "-b",
           "-o", "command script import %s" % script_path,
           "-o", "wxcap %d" % seconds,
           "-o", "continue", "-o", "quit"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60)
    hits = [ln for ln in proc.stdout.splitlines() if "WXCAP" in ln]
    for ln in hits:
        print("      " + ln.strip())

    candidates = _parse_keys(out_path)
    print("[4/4] 收到 %d 个候选，验证中…" % len(candidates))

    # 用真实库验证，验证不过的不算数
    for hx in candidates:
        kb = bytes.fromhex(hx)
        if len(kb) != 32:
            continue
        rounds = sqlcipher.best_rounds(account.message_db, kb)
        if rounds:
            print("      命中：%s（KDF 轮数 %d）" % (hx, rounds))
            return kb
    if candidates and keep_candidates:
        print("      候选都不匹配当前库，可能是别的应用的 PBKDF2 调用。")
    return None
