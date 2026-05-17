# KeyGate

[![PyPI version](https://img.shields.io/pypi/v/keygate.svg)](https://pypi.org/project/keygate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/keygate?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/keygate)

在 API 密钥和密码进入 git 历史之前将其拦截的 pre-commit 钩子。

```bash
pipx install keygate
keygate activate
```

就这两条命令。此后每次 `git commit` 都会自动检查。

---

## 演示

![KeyGate demo](https://raw.githubusercontent.com/kanekoyuichi/keygate/main/docs/keygate-demo.gif)

---

## 为什么需要它

开发过程中，很容易将 API 密钥或密码直接写入代码。一旦通过 `git commit` 提交，它们就会永久嵌入仓库历史记录中。

即使事后删除，过去的提交中仍然可以访问到这些信息——一旦在 GitHub 等平台上公开，几乎会立即被滥用。因 AWS 密钥泄露而产生巨额账单的案例不胜枚举。

KeyGate **在提交发生之前自动拦截**。无需任何配置即可开始使用。

---

## 检测范围

- AWS 访问密钥
- OpenAI API 密钥
- Anthropic API 密钥
- Google API 密钥
- GitHub Token
- GitLab 个人访问令牌
- Slack Token
- 私钥（PEM 格式）
- JWT Token
- Stripe 密钥
- SendGrid API 密钥
- npm 访问令牌
- PyPI API 令牌
- Django Secret Key
- Azure Storage 账户密钥
- Azure SAS Token
- Hugging Face、Docker Hub、Vercel、Datadog、Discord、Telegram、Twilio Token
- Sentry DSN
- URL 中嵌入的凭据（例如 `postgres://user:password@host`） <!-- # keygate: ignore reason="documentation example" -->
- `Authorization: Bearer ...` 以及可解码的 `Authorization: Basic ...` 请求头
- 疑似个人信息：电子邮件地址、日本电话号码（支持 `03-1234-5678` 和 `090-1234-5678` 等带分隔符格式、以 `090`/`080`/`070`/`050` 开头的无分隔符手机号、`(03)1234-5678` 和 `03(1234)5678` 等括号格式、`+81-...` 国际格式，以及 `ext. 123` 或 `内線 456` 等分机号后缀）、信用卡号（含 JCB）、美国 SSN、IBAN（紧凑格式和空格分组格式，不区分大小写）、英国 National Insurance Number（紧凑格式 `AB123456C` 和空格格式 `AB 12 34 56 C`）
- 看起来随机的长字符串（高熵检测）
- 变量名如 `api_key`、`password`、`secret` 与其对应值的组合

仅检测到个人信息时，KeyGate 会以 WARN 报告，不会阻止提交。若同一行还包含足够强的非 PII 密钥信号，并且这些信号本身已达到 block 阈值，则仍可能阻止提交。

---

## 快速开始

### 第一步：安装

`keygate` 是一个 Python CLI 工具，推荐使用 `pipx` 安装。

```bash
pipx install keygate
```

> 如果没有 `pipx`，可以通过 `pip install pipx` 安装。
> 使用 `pipx` 安装后，`keygate` 命令可在任意项目目录中使用。

### 第二步：激活

```bash
cd path/to/your-project
keygate activate
```

将 KeyGate 安装为 Git pre-commit 钩子。如果仓库配置了 `core.hooksPath`，KeyGate 会安装到该目录，而不是固定写入 `.git/hooks`。

> **Windows 用户**：需要安装 [Git for Windows](https://gitforwindows.org/)。钩子通过 Git for Windows 内置的 MSYS2 Shell 执行。如果你是通过 `pip install`（而非 `pipx`）安装的 `keygate`，请在你使用的 Shell 中激活 virtualenv 后再运行 `keygate activate`。使用 `pipx` 安装则无需此操作。WSL 同样支持。

生成的 hook 会优先使用当前 Python 环境执行 `python -m keygate.cli scan`，只有在该方式不可用时才回退到 `keygate scan`。这样在 hook 执行时 PATH 受限的环境里也更可靠。

配置完成。

### 第三步：使用

像往常一样执行 `git add` 和 `git commit`。如果没有发现危险内容，不会有任何提示。

如果检测到密钥，提交会被阻止，输出如下：

```
[BLOCK] High confidence secret detected

File: config.py:12
Rule: aws-access-key
Score: 100

Reason:
AWS Access Key detected; sensitive context detected

Remediation:
  - Remove the key from the code
  - Rotate the AWS credentials immediately
  - Use environment variables or AWS IAM roles instead

To ignore:
  Add comment: # keygate: ignore reason="..."
```

**输出说明：**
- `File: config.py:12` — 问题所在的文件和行号
- `Rule: aws-access-key` — 检测到的内容类型
- `Score: 100` — 危险程度（70 分及以上阻止提交；40~69 分仅发出警告）
- `Reason` — 触发检测的原因
- `Remediation` — 修复建议

### 第四步：升级

如果你是通过 `pipx` 安装的 `keygate`，可以这样升级：

```bash
pipx upgrade keygate
```

如果你是通过 `pip` 安装的，可以使用：

```bash
python -m pip install -U keygate
```

---

## 作为 Claude Code 插件使用

`keygate` 还可以作为 [Claude Code](https://docs.claude.com/en/docs/claude-code) 插件使用。安装后，Claude 会在你提交前自动扫描已暂存的变更，也可以在 Claude Code 中通过斜杠命令直接调用 keygate。

### 第一步：安装 keygate CLI

插件是 CLI 的封装，所以仍需先安装 CLI。任选其一：

```bash
pipx install keygate          # 使用 pipx
uv tool install keygate       # 使用 uv
pip install --user keygate    # 备选
```

### 第二步：添加 marketplace 并安装插件

在 Claude Code 中执行：

```
/plugin marketplace add kanekoyuichi/keygate
/plugin install keygate
```

### 提供的能力

- **Skill `keygate-secret-scan`** —— 当用户即将提交，或暂存变更中出现疑似凭据值时，Claude 会自动触发该技能。内部执行 `keygate scan --profile agent`，解析 JSON 输出，并使用已掩码的 snippet 报告检测结果。
- **斜杠命令**：
  - `/keygate:scan` —— 立即扫描已暂存的变更
  - `/keygate:install-hook` —— 安装 Git pre-commit hook
  - `/keygate:baseline-create` —— 将当前检测结果加入 baseline
  - `/keygate:baseline-update` —— 仅追加新检测结果到 baseline

插件内部使用 agent JSON profile（`schema_version: "1"`），检测逻辑与策略与 CLI 完全一致。

---

## 手动扫描

也可以不使用钩子，直接在当前目录执行扫描。

```bash
git add .
keygate scan
```

扫描对象为 `git diff --cached`（仅限已暂存的变更）。

### 面向 AI 智能体与自动化的 JSON 输出

`keygate scan` 默认输出为人类可读的 text。如果是 AI 智能体或脚本需要解析结果，可使用 JSON 输出：

```bash
keygate scan --format json    # stdout 仅输出 JSON
keygate scan --json           # --format json 的别名
keygate scan --profile agent  # 固定 JSON，不输出人类提示文本
```

默认 text 输出在首行也包含可被机器解析的摘要：

```
[KEYGATE] status=block findings=1
```

被 BLOCK 时，text 输出会附带 JSON 重新运行的命令提示，便于智能体改用 JSON 重新解析。JSON 负载遵循固定 schema（`schema_version: "1"`），包含 `status` / `summary` / `findings[]`（含 `rule_id`、`policy`、`score`、`verdict`、`file`、`line`、`message`，可生成时附 `snippet` 掩码）。

exit code 与原行为一致：`0` 表示 pass/warn，`1` 表示 block，`2` 表示选项冲突（如同时指定 `--format text` 与 `--json`）。

---

## 处理误报

`keygate` 倾向于保守检测，偶尔会误报非真实密钥。以下提供三种处理方式。

### 方式一：内联忽略注释

仅对该行生效，必须填写原因。

```python
api_key = "dummy-key-for-testing"  # keygate: ignore reason="test data"
```

### 方式二：路径或模式白名单

在项目根目录创建 `keygate.toml`，指定要排除的路径或模式。

```toml
[allowlist]
paths = ["vendor/*", "third_party/*"]  # 忽略非自有代码
patterns = ["dummy", "example"]         # 忽略包含这些词的行
```

> 注意：将 `tests/*` 整体加入白名单，会导致 KeyGate 忽略测试代码中混入的真实密钥。测试中的误报请使用方式一（内联忽略）或方式三（baseline）处理。

### 方式三：Baseline — 将现有检测结果注册为忽略

适用于只想检测新增密钥、不想处理历史问题的场景。

```bash
keygate baseline create
```

当前检测结果会保存到 `.keygate.baseline.json`，此后相同位置的检测结果将被忽略。文件内容示例：

```json
{
  "version": 1,
  "entries": [
    {
      "fingerprint": "e5282a7860678bc768d280eb3e77d2ca8a44286357c743dd024d74fe0605fe09",
      "file_path": "src/app/config.py",
      "line_number": 42,
      "rule_id": "url-credentials",
      "created_at": "2026-04-22T09:30:00+00:00"
    }
  ]
}
```

`fingerprint` 是 `file_path` + `line_number` + 匹配字符串的 SHA256 哈希值。不会存储实际密钥内容，因此将 baseline 文件提交到 Git 是安全的。

如果 `.keygate.baseline.json` 已经存在，重新执行 `keygate baseline create` 会保留已有 entries，并在其基础上追加新检测结果，不会悄悄覆盖掉现有 baseline。

如需将新发现的内容添加到 baseline：

```bash
keygate baseline update
```

#### 团队共享

推荐将 `.keygate.baseline.json` 提交到 Git 并共享，这样团队所有成员使用相同的忽略列表。

```bash
git add .keygate.baseline.json
git commit -m "Add keygate baseline"
```

新成员只需执行 `pipx install keygate` 和 `keygate activate`，即可自动使用共享的 baseline。

---

## 配置文件（可选）

默认配置开箱即用，如需自定义，可在项目根目录创建 `keygate.toml`。

```toml
[scan]
entropy_threshold = 4.2    # 随机字符串检测阈值（越低越严格）
block_score = 70           # 达到此分数及以上时阻止提交

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

未提供配置文件时使用默认值。

---

## 常见问题

**Q. 不小心提交了密钥怎么办？**

A. 立即撤销（rotate）该密钥。仅从 Git 历史中删除是不够的。应假设泄露的密钥已落入攻击者手中。

**Q. 如何临时禁用钩子？**

A. 使用 `git commit --no-verify` 可跳过单次提交的所有钩子。如需完全移除钩子，运行 `keygate deactivate`。

**Q. 如何在团队中共享配置？**

A. 将 `keygate.toml` 和 `.keygate.baseline.json` 提交到 Git 共享。每位成员需单独执行 `keygate activate`。

**Q. 如何升级 KeyGate？**

A. 如果是通过 `pipx` 安装的，运行 `pipx upgrade keygate`。如果是通过 `pip` 安装的，运行 `python -m pip install -U keygate`。

---

## 检测准确率

基于 100 个标注样本（50 个已知密钥、50 个无害字符串）的测量结果。

| 指标 | 值 |
|------|-----|
| 召回率（Recall: 未漏掉真实密钥的比例） | 100.0% |
| 精确率（Precision: 被检测项中真正危险的比例） | 80.6% |
| F1 分数（召回率与精确率的平衡指标） | 89.3% |
| True Positive（正确检测到的密钥） | 50 |
| False Negative（漏掉的密钥） | 0 |
| False Positive（并非真实密钥但被检测到的内容） | 12 |
| True Negative（正确放行的无害字符串） | 38 |

**召回率 100.0%** 意味着语料库中所有已知密钥均被检测到（BLOCK 或 WARN）。也就是说，在该基准测试中没有漏检密钥。

**精确率 80.6%** 反映了 12 个 False Positive。其中包括已遮蔽的 URL 凭据、占位符、Stripe publishable key，以及 `API_KEY=` 这样的空值。它们并不一定是真实密钥，但外观接近密钥，因此 `keygate` 会在提交前提示你检查。

语料库和阈值作为回归测试进行管理。如需重新测量：

```bash
python -m tests.benchmark.benchmark
```

---

## 免责声明

`keygate` 是一个尽力而为的检测工具，使用前请了解以下内容。

- **不保证完整检测**：未知密钥格式、混淆值或自定义格式可能无法被检测到（漏报）。
- **可能存在误报**：非密钥字符串可能被标记。请使用白名单 / baseline / 内联忽略处理。
- **不是密钥管理的替代方案**：本工具是提交时的额外防护层。密钥应通过环境变量、密钥管理器或 KMS 等方式管理，不应存储在仓库中。
- **钩子可被绕过**：`git commit --no-verify` 会跳过所有钩子。如需组织级管控，请结合服务端检查（pre-receive hook、CI 扫描等）使用。
- **因漏报导致的密钥泄露，责任由使用者承担**：因使用本工具造成的任何损失，作者及贡献者概不负责（详见 [LICENSE](LICENSE)）。
- **检测到密钥时请及时轮换**：即使提交被阻止，密钥值仍可能残留在本地文件、编辑器历史、剪贴板或其他设备中。

本工具定位为捕捉人为失误的最后一道防线，而非正确密钥管理实践的替代品。

---

## 许可证

以 [MIT License](LICENSE) 发布。包括商业用途在内，可自由使用、修改和再分发。详见 [LICENSE](LICENSE)。
