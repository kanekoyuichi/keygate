# keygate

[![PyPI version](https://img.shields.io/pypi/v/keygate.svg)](https://pypi.org/project/keygate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/keygate?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/keygate)

APIキーやパスワードが git 履歴に入る前に止める、pre-commit フックです。

```bash
pipx install keygate
keygate activate
```

これだけ。以降は `git commit` のたびに自動でチェックが走ります。

---

## なぜ必要か

開発中、コードに API キーやパスワードを直接書いてしまうことがあります。それをそのまま `git commit` すると、リポジトリの履歴に永久に残ってしまいます。

たとえ後で削除しても、過去のコミットからは取り出せるため、GitHub などに公開されるとすぐに悪用されます。AWS のキーが漏れて高額請求された事例も多くあります。

keygate は **コミット前に自動でブロック** します。設定不要で使い始められます。

---

## 検知できるもの

- AWS アクセスキー
- OpenAI API キー
- GitHub トークン
- Slack トークン
- 秘密鍵（PEM 形式）
- JWT トークン
- ランダムに見える長い文字列（高エントロピー検知）
- `api_key`, `password`, `secret` などの変数名 + 値

---

## はじめかた

### ステップ1: インストール

`keygate` は Python 製のコマンドラインツールです。`pipx` でインストールするのが一番簡単です。

```bash
pipx install keygate
```

> `pipx` がない場合は `pip install pipx` でインストールできます。
> `pipx` を使うと、どのプロジェクトのフォルダからでも `keygate` コマンドが使えるようになります。

### ステップ2: 有効化する

```bash
cd path/to/your-project   # 自分のプロジェクトに移動
keygate activate
```

Git の pre-commit フックとしてインストールします。`core.hooksPath` を設定しているリポジトリでも、`.git/hooks` に固定せず正しい配置先を使います。

生成される hook は、まず現在の Python 実行環境で `python -m keygate.cli scan` を実行し、それが使えない場合だけ `keygate scan` にフォールバックします。hook 実行時の `PATH` が制限されている環境でも壊れにくくするためです。

これで準備完了です。

### ステップ3: 実際に使ってみる

普段通り `git add` と `git commit` をするだけです。危険なものが含まれていなければ、何も起きません。

危険なものが含まれていると、こんなふうにコミットが止まります：

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

**読み方：**
- `File: config.py:12` — 問題のあるファイルと行番号
- `Rule: aws-access-key` — 何を検知したか
- `Score: 100` — 危険度（70以上で自動ブロック、40〜69は警告のみ）
- `Reason` — 検知の理由
- `Remediation` — 直し方の提案

### ステップ4: アップデートする

`pipx` で `keygate` をインストールした場合は、次で更新できます。

```bash
pipx upgrade keygate
```

`pip` でインストールした場合は、次を使います。

```bash
python -m pip install -U keygate
```

---

## Claude Code プラグインとして使う

`keygate` は [Claude Code](https://docs.claude.com/ja/docs/claude-code) のプラグインとしても利用できます。プラグインを導入すると、Claude がコミット前のステージ変更を自動でスキャンし、Claude Code 内からスラッシュコマンドで keygate を直接操作できます。

### ステップ 1: keygate CLI をインストール

プラグインは CLI のラッパーなので、本体は別途必要です。いずれか1つを実行してください。

```bash
pipx install keygate          # pipx を使う場合
uv tool install keygate       # uv を使う場合
pip install --user keygate    # フォールバック
```

### ステップ 2: マーケットプレイスを追加してプラグインを導入

Claude Code 内で以下を実行します。

```
/plugin marketplace add kanekoyuichi/keygate
/plugin install keygate
```

### 提供される機能

- **Skill `keygate-secret-scan`** — Claude がコミット直前やシークレットらしき値を含む変更を検知したときに自律起動します。内部で `keygate scan --profile agent` を実行し、JSON 結果を解釈してマスク済み snippet と共に報告します。
- **スラッシュコマンド**:
  - `/keygate:scan` — ステージ変更をその場でスキャン
  - `/keygate:install-hook` — Git pre-commit hook を導入
  - `/keygate:baseline-create` — 現在の検知を baseline に記録
  - `/keygate:baseline-update` — 新規検知のみを baseline に追加

プラグインは内部で agent JSON プロファイル（`schema_version: "1"`）を使うため、検知ロジック・ポリシーは CLI と完全に同じです。

---

## 手動でスキャンする

フックを使わず、その場でチェックすることもできます。

```bash
git add .
keygate scan
```

`git diff --cached`（ステージ済みの変更）に対してスキャンを実行します。

### AI エージェント・自動化向けの JSON 出力

`keygate scan` のデフォルト出力は人間向けの text ですが、AI エージェントやスクリプトで結果を解析したい場合は JSON を使えます。

```bash
keygate scan --format json    # stdout に JSON のみを出力
keygate scan --json           # --format json のエイリアス
keygate scan --profile agent  # JSON 固定。人間向け説明は出さない
```

デフォルトの text 出力にも、機械的に読めるサマリ行が先頭に出ます。

```
[KEYGATE] status=block findings=1
```

BLOCK 時の text 出力には JSON 再実行用のコマンドも案内されるため、エージェントは text を見て JSON で再実行できます。JSON ペイロードは固定スキーマ（`schema_version: "1"`）で、`status` / `summary` / `findings[]`（`rule_id` / `policy` / `score` / `verdict` / `file` / `line` / `message`、マスク済み `snippet`（生成可能な場合のみ）を含む）を返します。

exit code は従来通りで、`0` が pass/warn、`1` が block、`2` がオプション誤指定（例：`--format text` と `--json` を併用）になります。

---

## 誤検知が出たときの対処

`keygate` は安全に倒すため、まれに本物ではないものも検知します。そのときの対処法を3つ用意しています。

### 方法1: コメントで「これは無視していい」と伝える

その行限定で無視できます。理由を書くのが必須です。

```python
api_key = "dummy-key-for-testing"  # keygate: ignore reason="テストデータ"
```

### 方法2: ファイルやキーワードを丸ごと除外する

プロジェクトのルートに `keygate.toml` というファイルを作って、除外したいファイルパスやキーワードを書きます。

```toml
[allowlist]
paths = ["vendor/*", "third_party/*"]  # 自分のコードではない箇所は無視
patterns = ["dummy", "example"]         # この単語を含む行は無視
```

> 注意: `tests/*` のようにテスト全体を allowlist に入れると、テストコードに混入した本物のシークレットを見逃します。テスト側の誤検知は方法1（inline ignore）か方法3（baseline）で対処してください。

### 方法3: 既存の検知をすべて見逃しリストに登録する（baseline）

これから新しく加わるものだけチェックしたい場合に便利です。

```bash
keygate baseline create
```

現時点の検知結果が `.keygate.baseline.json` というファイルに保存され、それ以降は同じ場所を検知しても無視されます。中身はこのような JSON です：

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

`fingerprint` は `file_path` + `line_number` + 検知文字列 の SHA256 ハッシュです。値そのものは保存されないため、baseline を Git にコミットしても機密情報は漏れません。

すでに `.keygate.baseline.json` がある状態で `keygate baseline create` を再実行しても、既存 entries は保持されます。再作成で baseline が勝手に縮むことはありません。

新しく見逃しリストに追加したいものが出てきたら、こうします：

```bash
keygate baseline update
```

#### チームで共有する

`.keygate.baseline.json` は Git にコミットして共有することをおすすめします。共有しておけば、チーム全員が同じ「見逃してよい検知」リストを使えます。

```bash
git add .keygate.baseline.json
git commit -m "Add keygate baseline"
```

新しくプロジェクトに参加した人は、`pipx install keygate` と `keygate activate` を実行するだけで、共有された baseline がそのまま使われます。

---

## 設定ファイル（必要な人だけ）

デフォルト設定で十分動きますが、好みに合わせて変更できます。`keygate.toml` をプロジェクトのルートに作ります。

```toml
[scan]
entropy_threshold = 4.2    # ランダムに見える文字列を検知する基準（厳しくしたいなら下げる）
block_score = 70           # この点数以上でコミットを止める

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

設定ファイルがなければデフォルトで動作します。

---

## よくある質問

**Q. うっかり機密情報をコミットしてしまったらどうすれば？**

A. すぐにそのキーを無効化（rotate）してください。Git の履歴から消すだけでは不十分です。漏れた可能性のあるキーは攻撃者の手に渡っていると考えるべきです。

**Q. フックを一時的に無効化したい**

A. `git commit --no-verify` で1回だけスキップできます。フックを完全に取り除く場合は `keygate deactivate` を実行してください。

**Q. チームで共有するには？**

A. `keygate.toml` と `.keygate.baseline.json` を Git にコミットして共有してください。各メンバーは `keygate activate` をそれぞれ実行する必要があります。

**Q. keygate 自体を更新するには？**

A. `pipx` で入れた場合は `pipx upgrade keygate`、`pip` で入れた場合は `python -m pip install -U keygate` を使ってください。

---

## 検知精度

100件のラベル付きコーパス（既知シークレット50件、無害な文字列50件）で計測した結果です。

| 指標 | 値 |
|------|-----|
| 再現率（Recall: 本物のシークレットを見逃さず検知できた割合） | 100.0% |
| 適合率（Precision: 検知したもののうち本当に危険だった割合） | 80.6% |
| F1 スコア（再現率と適合率のバランス指標） | 89.3% |
| True Positive（正しく検知できたシークレット） | 50 |
| False Negative（見逃したシークレット） | 0 |
| False Positive（本物のシークレットではないが検知したもの） | 12 |
| True Negative（正しく通過させた無害な文字列） | 38 |

**再現率 100.0%** は、コーパス内のすべての既知シークレットを検知（BLOCK または WARN）できたことを意味します。つまり、このベンチマークではシークレットの見逃しは 0 件でした。

**適合率 80.6%** は12件の False Positive を反映しています。内訳には、マスク済み URL credentials、プレースホルダー、Stripe publishable key、`API_KEY=` のような空値などが含まれます。これらは本物のシークレットではない場合もありますが、見た目がシークレットに近いため、コミット前に確認できるよう検知対象にしています。

コーパスと閾値はリグレッションテストとして管理されています。再計測するには：

```bash
python -m tests.benchmark.benchmark
```

---

## 免責事項

`keygate` はベストエフォートで動作する検知ツールです。利用にあたっては以下を理解してください。

- **完全な検知は保証しません**：未知のシークレット形式、難読化された値、独自フォーマットなどは検知できない場合があります（false negative）。
- **誤検知が発生する可能性があります**：本物ではない文字列が検知されることがあります（false positive）。allowlist / baseline / inline ignore で対処してください。
- **シークレット管理の代替ではありません**：本ツールはコミット時の追加防壁です。秘密情報は本来、環境変数・シークレットマネージャー・KMS 等で管理し、リポジトリに含めない設計を優先してください。
- **フックの無効化を防ぐものではありません**：`git commit --no-verify` でバイパスされる可能性があります。組織的な統制が必要な場合はサーバ側のチェック（pre-receive hook、CI スキャン等）と併用してください。
- **検知漏れによって機密情報が漏洩した場合の責任は利用者にあります**：本ツールの使用によって生じたいかなる損害についても、作者および貢献者は責任を負いません（詳細は [LICENSE](LICENSE) 記載のとおり）。
- **検知された場合は速やかに鍵をローテーションしてください**：コミット前に止められた場合でも、ローカルファイル・エディタ履歴・クリップボード・他端末等に値が残っている可能性があります。

本ツールは「シークレット管理を正しく行う」ことの代わりではなく、「人間のうっかりミスを最後に拾う網」として設計されています。

---

## ライセンス

[MIT License](LICENSE) で配布しています。商用利用を含めて自由に利用・改変・再配布できます。詳細は [LICENSE](LICENSE) を参照してください。
