# 微信聊天记录本地归档（macOS · 微信 4.x）

把 Mac 上加密的微信聊天记录，变成**可搜索、可浏览、可继续加工**的本地数据：
文字、链接、图片、视频、文件，全部解开并落成普通文件。

```bash
python3 -m wxarchive run
```

跑完你会得到一个目录：

```
wxarchive_data/
├── index.html        # 双击就能看的聊天浏览界面（含图片、视频、外链）
├── archive.db        # 归一化后的 SQLite 库，带中文全文索引
├── export.jsonl      # 每行一条消息，十年后任何编辑器都能打开
├── chats.md          # 按会话导出的 Markdown
├── media/            # 解密后的图片 / 视频 / 文件
├── decrypted/        # 解密后的原始微信库（19 个 .db）
└── keys.json         # 密钥缓存（权限 600，不要提交到任何仓库）
```

---

## 1. 它到底做了什么

微信 4.x 的本地数据有三道门，工具按顺序开：

| 关卡 | 微信的做法 | 本工具的做法 |
|---|---|---|
| 数据库 | SQLCipher 4（AES-256 + HMAC-SHA512）加密 `.db` | 从微信进程里取 32 字节密钥，按页解密 |
| 消息体 | 每条消息体 zstd 压缩，正文是 XML 混排 | 解压 + 按类型解析成结构化字段 |
| 媒体 | 图片 `.dat` 是 AES 头 + 单字节 XOR 尾的混合加密 | 复制一份并把 `.dat` 解成 jpg/png |

关键点是**第 1 关的密钥**：它只存在于微信进程的内存里，而且只在「数据库被打开的那一瞬间」出现。
所以工具会在微信启动的瞬间挂一个断点，捕捉这次调用（见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)）。

第 3 关的媒体密钥不一样——它是**账号级、可离线派生**的，不需要微信在线，
只用 `kvcomm` 文件名里的 code 和 wxid 算出来（见 [docs/MEDIA.md](docs/MEDIA.md)）。

## 2. 环境要求

> **⚠️ 仅支持 macOS。** Windows 版微信的数据库路径、加密参数、密钥获取方式
> 与 macOS 4.x 完全不同（Windows 取密钥靠读进程内存，图片 `.dat` 是单字节 XOR），
> 本工具的代码不能直接复用。Windows 用户请改用：
> [**PyWxDump**](https://github.com/xaoyaoo/PyWxDump)（Windows 微信 3.x，全功能）或
> [**chatlog**](https://github.com/sjzar/chatlog)（同时支持 Windows / macOS）。

- macOS（Apple Silicon / Intel 均可），微信 **4.x** 桌面版并已登录
- Python **3.9+**
- 两个 Python 包：`pycryptodome`、`zstandard`
- 抓密钥时需要：`lldb`（Xcode Command Line Tools 自带）且 **SIP 关闭**

```bash
xcode-select --install                 # 装 lldb
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 3. 快速开始

```bash
# 0) 先自检，确认环境、账号、密钥、媒体密钥都摸得到
python3 -m wxarchive doctor

# 1) 全流程（会自动重启一次微信去抓密钥）
python3 -m wxarchive run

# 2) 打开结果
open wxarchive_data/index.html
```

密钥抓到后会缓存在 `wxarchive_data/keys.json`，**以后不用再抓**，
`run` 发现密钥还有效就直接复用。只有微信大版本升级导致密钥失效时才需要重抓。

### 常用命令

| 命令 | 作用 |
|---|---|
| `python3 -m wxarchive doctor` | 环境 / 账号 / 密钥 / 归档状态自检 |
| `python3 -m wxarchive run` | 全流程：密钥 → 解密 → 媒体 → 入库 → 生成界面 |
| `python3 -m wxarchive run --no-capture` | 只复用缓存密钥（不重启微信） |
| `python3 -m wxarchive key` | 只抓密钥 |
| `python3 -m wxarchive decrypt` | 只解密数据库 |
| `python3 -m wxarchive export` | 只做媒体解码 / 入库 / 生成界面 |
| `python3 -m wxarchive search 飞利浦` | 命令行全文检索（中文子串） |
| `python3 -m wxarchive list` | 列出会话 |
| `--workdir DIR` | 指定输出目录（默认 `./wxarchive_data`） |
| `--max-media-mb N` | 单个文件/视频超过 N MB 只记路径不拷贝（默认 50） |

## 4. 能读到什么、读不到什么

| 内容 | 支持情况 | 说明 |
|---|---|---|
| 文字消息 | ✅ | 剥离 XML，保留原文与换行 |
| 外链 / 公众号文章 / 小程序卡片 | ✅ | 抽出 `url`，界面里可直接点开 |
| 图片 | ✅ | `.dat` → `_h` 高清 PNG / `_t` 缩略 JPG；`wxgf` 需要 ffmpeg 转码 |
| 视频 | ✅ | 微信本地保存的 `.mp4` 是**明文**，直接复制；封面 `_thumb.jpg` 一并带走 |
| 文件 | ✅ | docx / xlsx / pdf / zip… 按 `msg/file/<年-月>/` 原样复制 |
| 引用回复 | ✅ | `quoted` 字段保留被引用的原文 |
| 语音 | ⚠️ 只存元数据 | 时长保留；`.silk` 转码需要额外解码器，未内置 |
| 表情包 | ⚠️ 只记 `md5` | 未做 wxgf 转码 |
| **手机上但没迁到电脑的记录** | ❌ | 桌面版只保存「登录之后」产生的消息，手机历史需要手动迁移 |

> 关于最后一条：这是微信的产品设计——桌面版只保存登录之后产生的消息，不是工具的限制。
> 迁移路径：手机微信 →「我 → 设置 → 通用 → 聊天记录迁移与备份 → 迁移到电脑」。

## 5. 已知限制（都验证过，不是猜测）

- **SIP 必须关闭**才能读微信进程内存。这是全局安全降级：关闭期间，任何本地程序都能读任意进程内存。
  建议「用的时候关、用完打开」——密钥可复用，不需要每次抓。
- **首次运行会重启一次微信**。数据不会丢，但请避开正在传文件、开会的时刻。
- **媒体只解本地已有的**。对方发来但你从没点开过的原图，微信不会下载，本地也就没有。
  微信还会自动清理旧视频正文，只留封面——所以视频可能「有消息、无文件」。
- **`wxgf` 动图/图片**是微信自研容器（内部 HEVC），macOS 没有官方解码器；
  装了 `ffmpeg` 会自动抽首帧成 PNG，否则保留 `.wxgf` 原始文件。
- **中文全文检索**依赖 SQLite 的 `trigram` 分词器（SQLite ≥ 3.34）。
- 只支持 **macOS**。Windows 的取密钥路径不同（走 `Weixin.exe` 内存扫描），本项目未实现。

## 6. 隐私与合规

这个工具做的是**读取你自己的账号、在你自己的电脑上**产生的数据。

- 导出的数据只留在本机，工具不联网、不上传。
- `keys.json`、`decrypted/`、`archive.db` 都是敏感文件，**不要提交到 git**（`.gitignore` 已挡）。
- 群聊里是别人的发言。备份自用没问题，转给别人、公开发布、用于商业用途，
  可能违反《个人信息保护法》与微信用户协议，请自己判断边界。

更多见 [docs/PRIVACY.md](docs/PRIVACY.md)。

## 7. 给别人用 / 在 WorkBuddy 里用

朋友的电脑上不需要改代码，只要有 git、Python 和微信：

```bash
git clone <本仓库地址> && cd wechat-mac-archive
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m wxarchive doctor     # 先看环境
python3 -m wxarchive run
```

想直接让 WorkBuddy 代跑，把 [docs/WORKBUDDY.md](docs/WORKBUDDY.md) 里的那段话贴给它即可。

## 8. 文档索引

| 文档 | 内容 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 五层结构、密钥原理、数据流、库表设计 |
| [docs/MEDIA.md](docs/MEDIA.md) | `.dat` V2 格式逐字节说明、媒体密钥派生、wxgf |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | 抓不到密钥 / 解密失败 / 图片打不开 等 |
| [docs/PRIVACY.md](docs/PRIVACY.md) | 数据边界与法律提醒 |
| [docs/WORKBUDDY.md](docs/WORKBUDDY.md) | 让 AI 助手代跑的提示词 |

## 9. 免责声明

仅供个人备份与检索自用。请遵守当地法律与微信用户协议；因使用本工具造成的任何后果由使用者自负。

代码以 MIT 协议开源（见 [LICENSE](LICENSE)）。
