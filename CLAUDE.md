# CLAUDE.md

## 1. プロジェクト概要

本プロジェクトは、Git の pre-commit フックとして動作する **シークレット漏洩防止ツール** を実装する。

目的は以下に限定する：

- コミット前に **秘密情報の混入を検知しブロックする**
- 誤検知による開発体験の悪化を防ぐ
- 例外運用（allowlist / baseline）を破綻させない

本ツールは gitleaks の代替ではなく、**ローカル開発体験に最適化されたツール** とする。

---

## 2. 非目標（重要）

以下は **実装禁止** とする：

- フルリポジトリスキャン（初期バージョン）
- LLMによる判定
- 外部APIを使ったシークレット検証（トークンの有効性確認など）
- IDEプラグイン
- SaaS連携
- 自動ローテーション機能

理由：

- Git Hook での実行時間と信頼性を優先するため
- オフライン・高速・安全性を維持するため

---

## 3. 成功条件

以下を満たさない実装は不採用とする：

- 実行時間が **1秒以内（目標 200〜500ms）**
- 誤検知率が低い（allowlistなしでも使えるレベル）
- フックが無効化されない設計（UX重視）
- エラーメッセージが修正可能な情報を持つ

---

## 4. スキャン対象

対象は必ず以下に限定する：

- `git diff --cached` の **追加行のみ**

禁止：

- 全ファイルスキャン
- 削除行のスキャン
- 未ステージファイルのスキャン（デフォルト）

---

## 5. 検知ロジック

検知は単一手法に依存してはいけない。必ず以下を組み合わせる：

### 5.1 ルールベース検知（必須）

- AWS Access Key
- OpenAI API Key
- GitHub Token
- Slack Token
- Private Key (PEM)
- JWT
- Stripe Secret Key (`sk_live_*` / `rk_live_*`) / Publishable Key (`pk_live_*`)
- SendGrid API Key (`SG.*.*`)
- URL credentials（`scheme://user:password@host` 形式、任意スキーム対応）

形式：

- regexで実装
- rule_id を必ず持つ
- `policy` フィールドで分類する：
  - `must_block`：秘匿必須。単独 BLOCK に届くスコアを持つ（既定）
  - `public_exposable`：公開前提（例：Stripe publishable key、URL のマスク済み credential）。WARN レベル（40）に降格する

URL credentials は context からルール層へ昇格している。理由は（1）任意スキーム（`postgres://`, `mongodb://`, `redis://` 等）への対応、（2）BLOCK 閾値（70）到達の確保。マスク済みの値（`***`、`REDACTED`、`<password>` 等）は `public_exposable` として WARN に降格する。

---

### 5.2 エントロピー検知（必須）

- Shannon entropy を使用
- 閾値：4.0〜4.5（設定可能）
- 最低文字長：20文字以上

---

### 5.3 コンテキスト検知（必須）

context.py は以下の独立シグナルを検知し、`ContextSignals` として返す。加点は scoring.py がコンボも含めて集約する。

#### キーワード（tier 分け）

- HIGH（+25）：`secret`、`password`、`passwd`、`api_key`、`access_key`、`access_token`、`private_key`、`auth_token`、`session_secret`、`client_secret`、`jwt_secret`、`database_password`、`db_password`
- MID（+15）：`token`、`credential`、`auth`

境界条件は `_` を含む変数名（`access_token`、`SECRET_KEY` 等）を正しく捕捉するため `(?:^|[^A-Za-z])…(?:[^A-Za-z]|$)` を用いる。

#### パス（tier 分け）

- very_sensitive（+20）：`.env`、`.env.production`、`.env.local` 等
- sensitive（+15）：`settings`、`credentials?`、`secrets?`、`config` を含むパス名
- ext（+10）：`.yaml` / `.yml` / `.toml` / `.ini` / `.properties` 拡張子

複数該当時は加算せず、より大きい値を採用する。

#### 代入構文（+15）

以下を強シグナルとして扱う：

- `NAME = "..."` / `NAME: "..."`（Python / YAML / JSON）
- `export NAME=...`（shell）
- `NAME=...`（.env 形式）

URL credentials は 5.1 のルール層で検知する（context からは扱わない）。

---

### 5.4 スコアリング（必須）

rules / entropy / context の全結果を集約し、最終スコアを算出して判定する。

基本配点：

- regex一致: +50〜100
- 高エントロピー: +20
- キーワード: HIGH +25 / MID +15
- パス: +10〜+20
- 代入構文: +15
- テストファイル: -10
- `example`, `dummy`: -20

コンボボーナス（rule 未マッチ時のみ適用。複数シグナル同時成立を強く評価する）：

- keyword（HIGH または MID） + entropy: **+15**
- keyword（HIGH） + entropy + 代入構文: **さらに +15**

rule マッチがある場合はコンボ加点を行わない（既にスコアが高いため重複加点を避ける）。

最終スコアにより判定：

- 70以上: block（コミット停止）
- 40以上: warn（警告を出力してコミット続行）
- 未満: 無視

---

## 6. 誤検知対策

以下を必ず実装する：

### 6.1 allowlist

- パスベース
- パターンベース（regex）
- キーワードベース

### 6.2 baseline

- JSON形式
- fingerprintで管理（値そのものではなくハッシュ）
- fingerprint は SHA256 で生成（ファイルパス + 行番号 + マッチ文字列 のハッシュ）
- 既存の問題はブロックしない

### 6.3 inline ignore

例：

```python
# keygate: ignore reason="test data"
```

制約：

- reason必須
- reasonなしはエラー

---

## 7. CLI仕様

### コマンド

```bash
keygate scan               # staged diff をスキャン（デフォルト動作）
keygate install-hook
keygate baseline create
keygate baseline update
```

---

## 8. 出力仕様

### 表示例

```text
[BLOCK] High confidence secret detected

File: config.py:12
Rule: aws-access-key
Score: 92

Reason:
AWS access key pattern detected with high entropy

Remediation:
- Remove the key
- Rotate credentials
- Use environment variables instead

To ignore:
Add comment: # keygate: ignore reason="..."
```

---

## 9. 設定ファイル

ファイル名：`keygate.toml`（リポジトリルートに配置）

```toml
[scan]
entropy_threshold = 4.2
block_score = 70

[allowlist]
paths = ["tests/*"]
patterns = ["dummy", "example"]

[baseline]
path = ".keygate.baseline.json"
```

---

## 10. アーキテクチャ

ソースコードは `src/` 配下に配置する。テストは `tests/` 配下に配置し、pytest を使用する。パッケージ管理は pip + pyproject.toml を使用する。`keygate` コマンドは pyproject.toml の `[project.scripts]` で登録する。

```text
src/
  keygate/
    cli.py            # エントリポイント（コマンド定義）
    config.py         # 設定ファイル読み込み（TOML）
    scanner/          # 検知ロジック
      rules.py        # ルールベース検知（regex + rule_id）
      entropy.py      # Shannon エントロピー検知
      context.py      # コンテキストスコアリング
      scoring.py      # スコア集計・判定（block/warn/ignore）
    diff/             # git diff 取得・パース
      parser.py       # --cached diff のパースと追加行抽出
    hook/             # pre-commit フック管理
      installer.py    # install-hook コマンド実装
    policy/           # 誤検知対策
      allowlist.py    # パス・パターン・キーワード allowlist
      baseline.py     # fingerprint ベースの baseline 管理
      inline.py       # インラインコメント ignore（reason 必須）
tests/
  test_scanner/
  test_diff/
  test_hook/
  test_policy/
```