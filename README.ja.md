# KeyGate

[![PyPI version](https://img.shields.io/pypi/v/keygate.svg)](https://pypi.org/project/keygate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/keygate?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/keygate)

うっかり API キーやパスワードを Git にコミットしてしまう事故を、自動で防ぐツールです。

```bash
pipx install keygate
keygate activate
```

これだけで、以降は `git commit` のたびに自動でチェックが走ります。

---

## デモ

![KeyGate demo](docs/keygate-demo.gif)

---

## なぜ必要か

開発中、コードに API キーを直接書いてしまうことは誰にでもあります。

```python
# こういうのを git commit してしまうと…
OPENAI_API_KEY = "sk-..."  # 実際のキー
```

`git commit` した瞬間、その値はリポジトリの**履歴に永久に残ります**。後で削除しても、過去のコミットを辿れば取り出せます。GitHub に push した場合、数秒以内に bot にスキャンされて悪用されることもあります。

KeyGate はこの「うっかりコミット」を、コミットが確定する前の瞬間に止めます。

---

## インストール

### ① KeyGate 本体を入れる

```bash
pipx install keygate
```

> **`pipx` とは？**  
> Python 製コマンドラインツールを、プロジェクトの環境を汚さずにインストールできる仕組みです。`pipx` がない場合は先に `pip install pipx` で入れてください。

### ② リポジトリで有効化する

```bash
cd /path/to/your-project  # プロジェクトのフォルダに移動
keygate activate
```

> **何が起きるの？**  
> Git の「コミット直前に自動で走るスクリプト」（pre-commit フック）として KeyGate を登録します。以降の `git commit` で自動的に動くようになります。

**以上で完了です。** あとは普段通りに開発するだけです。

---

## 使い方（普段は何もしなくていい）

インストール後は、普段通り `git add` → `git commit` するだけです。

**問題がなければ、何も表示されません。**

シークレットが見つかった場合だけ、コミットが止まります：

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

**出力の読み方：**

| 項目 | 意味 |
|------|------|
| `File: config.py:12` | 問題のあるファイルと行番号 |
| `Rule: aws-access-key` | 何を検知したか |
| `Score: 100` | 危険度（70以上でブロック、40〜69は警告のみ） |
| `Reason` | なぜ検知されたか |
| `Remediation` | 直し方の提案 |

---

## 検知できるもの

- AWS アクセスキー（`AKIA...`）
- OpenAI API キー（`sk-...`）
- GitHub トークン（`ghp_...`）
- Slack トークン（`xoxb-...`）
- 秘密鍵（PEM 形式）
- JWT トークン
- Stripe キー
- URL に埋め込まれた認証情報（`postgres://user:***@host` など）
- ランダムに見える長い文字列（高エントロピー検知）
- `api_key`, `password`, `secret` などの変数名 + 値の組み合わせ

---

## 誤検知が出たときは

KeyGate は安全側に倒す設計のため、まれに本物でない文字列を検知することがあります。その場合の対処法です。

### 方法1：その行だけ無視する（一番手軽）

```python
api_key = "dummy-key-for-testing"  # keygate: ignore reason="テストデータ"
```

コメントを追加するだけです。`reason="..."` は省略できません（なぜ無視したかを記録するためです）。

### 方法2：特定のファイルやパターンを除外する

プロジェクトのルートに `keygate.toml` を作ります：

```toml
[allowlist]
paths = ["vendor/*", "third_party/*"]  # 自分のコードではない箇所
patterns = ["dummy", "example"]         # この文字列を含む行は無視
keywords = ["fixture"]
```

> **注意：** `tests/*` を丸ごと除外すると、テストコードに混入した本物のシークレットを見逃します。テスト内の誤検知は方法1で対処するのをおすすめします。

### 方法3：既存の検知をまとめて登録して無視する（baseline）

すでに存在する検知結果をまとめて「無視リスト」に登録できます。**新しく追加したものだけを検知したい**場合に便利です。

```bash
keygate baseline create
```

現時点の検知結果が `.keygate.baseline.json` に保存され、以降は同じ場所の検知が無視されます。値そのものは保存されないので、このファイルを Git にコミットしても安全です。

新しい検知を追加で登録したいときは：

```bash
keygate baseline update
```

---

## よくある質問

**Q. うっかりコミットしてしまった場合は？**

すぐにそのキーを無効化（rotate）してください。Git の履歴から消すだけでは不十分です。漏れた可能性があるキーは、すでに誰かの手に渡っていると考えてください。

**Q. 一時的にチェックをスキップしたい**

```bash
git commit --no-verify
```

で1回だけスキップできます。ただし多用は禁物です。フックを完全に取り除く場合は `keygate deactivate`、再度有効化するには `keygate activate` を使ってください。

**Q. チームで共有するには？**

`keygate.toml` と `.keygate.baseline.json` を Git にコミットして共有してください。各メンバーが `keygate activate` を実行すれば、共有設定がそのまま使われます。

**Q. KeyGate 自体を更新するには？**

```bash
pipx upgrade keygate
```

`pip` で入れた場合は `python -m pip install -U keygate`。

---

## Claude Code プラグインとして使う

`keygate` は [Claude Code](https://docs.claude.com/ja/docs/claude-code) のプラグインとしても使えます。Claude がコミット前に自動でスキャンし、問題を指摘してくれるようになります。

```
/plugin marketplace add kanekoyuichi/keygate
/plugin install keygate
```

スラッシュコマンド：
- `/keygate:scan` — 手動でスキャン
- `/keygate:install-hook` — hook を導入
- `/keygate:baseline-create` — baseline を作成
- `/keygate:baseline-update` — baseline を更新

---

## 設定ファイル（必要な人だけ）

デフォルトのまま使えますが、`keygate.toml` をプロジェクトのルートに置くことでカスタマイズできます。

```toml
[scan]
entropy_threshold = 4.2    # ランダム文字列の検知感度（下げると厳しくなる）
block_score = 70           # この点数以上でコミットをブロック

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

設定ファイルがなければデフォルトで動作します。

---

## AI エージェント・自動化向け

`keygate scan` のデフォルト出力は人間向けですが、AI エージェントやスクリプトには JSON 出力が便利です。

```bash
keygate scan --profile agent  # JSON のみを出力
keygate scan --format json    # 同上
```

JSON は固定スキーマ（`schema_version: "1"`）で、`status` / `summary` / `findings[]` を返します。

---

## 検知精度

100件のラベル付きコーパス（既知シークレット50件 + 無害な文字列50件）での計測結果です。

| 指標 | 値 |
|------|-----|
| 再現率（本物のシークレットを見逃さなかった割合） | 100.0% |
| 適合率（検知したもののうち本当に危険だった割合） | 80.6% |
| F1 スコア | 89.3% |
| 見逃したシークレット（False Negative） | 0件 |
| 誤検知（False Positive） | 12件 |

**見逃しゼロ**を最優先にしています。誤検知の12件は、マスク済み URL credentials・プレースホルダー・`API_KEY=` のような空値などです。

---

## 免責事項

- **完全な検知は保証しません**：未知のフォーマットや難読化された値は検知できない場合があります
- **誤検知はゼロではありません**：allowlist / baseline / inline ignore で対処してください
- **フックはバイパスできます**：`git commit --no-verify` で回避可能です
- **シークレット管理の代替ではありません**：本来は環境変数やシークレットマネージャーで管理するのが鉄則です

---

## ライセンス

[MIT License](LICENSE) で配布しています。商用利用を含めて自由に利用・改変・再配布できます。
