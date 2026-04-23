# 設計決定記録

## メモリ保存方針

プロジェクトに関するメモリ（設計決定、事実）はすべて本ファイル（`.claude/memory/decisions.md`）に集約する。user-global の auto-memory には保存しない。Git で版管理してチームに共有可能にするため（2026-04-23 ユーザー指示）。

## CLI

- `keygate scan` が staged diff をデフォルトでスキャン（`--staged` フラグは不要）
- コマンド一覧：
  - `keygate scan`
  - `keygate install-hook`
  - `keygate baseline create`
  - `keygate baseline update`

## スコアリング・判定

- 70以上: block（コミット停止）
- 40以上: warn（警告を出力してコミット続行）
- 未満: 無視

### 配点

- regex一致: +50〜100
- 高エントロピー: +20
- キーワード: HIGH +25 / MID +15
- パス: very_sensitive +20 / sensitive +15 / config拡張子 +10
- 代入構文: +15
- テストファイル: -10、`example`/`dummy`: -20

### コンボボーナス（rule 未マッチ時のみ）

- keyword（HIGH/MID） + entropy: +15
- keyword（HIGH） + entropy + 代入構文: さらに +15

rule マッチがある場合はコンボ加点しない（重複加点回避）。

## 責務分担

- `context.py`：文脈検知を行い、`ContextSignals`（keyword_score / keyword_tier / path_score / assignment_score）を返す
- `scoring.py`：rules / entropy / context の全シグナルを集約し、コンボボーナスを評価して最終スコアを算出・判定する

## キーワード分類（context.py）

- HIGH（+25）：`secret`、`password`、`passwd`、`api_key`、`access_key`、`access_token`、`private_key`、`auth_token`、`session_secret`、`client_secret`、`jwt_secret`、`database_password`、`db_password`
- MID（+15）：`token`、`credential`、`auth`
- 境界条件：`(?:^|[^A-Za-z])…(?:[^A-Za-z]|$)` を使用（`_` を含む変数名に対応）

## パス分類（context.py）

- very_sensitive（+20）：`.env`、`.env.production` 等
- sensitive（+15）：`settings`/`credentials?`/`secrets?`/`config` を含むパス
- ext（+10）：`.yaml`/`.yml`/`.toml`/`.ini`/`.properties`
- 複数該当時は加算せず最大値を採用

## 代入構文（context.py）

`NAME = "..."` / `NAME: "..."` / `export NAME=...` / `.env` 形式の `NAME=...` を強シグナルとして +15 加点。

## ルール分類（rules.py）

`Rule.policy` フィールドで方針を明示：

- `must_block`：秘匿必須。BLOCK スコアを持つ（既定）
- `public_exposable`：公開前提。WARN レベル40に降格
  - 現状：Stripe publishable key、URL credentials のマスク済み値（`***`/`xxx`/`REDACTED`/`<password>`/`changeme`/`placeholder`/`your_password`）

## URL credentials の扱い

context ではなく rule 層で検知する。理由：

- 任意スキーム対応（`postgres://`、`mongodb://`、`redis://` 等）
- BLOCK 閾値（70）への到達を確保
- マスク済み値は `public_exposable` として WARN に降格

## 設定ファイル

- ファイル名：`keygate.toml`（リポジトリルートに配置）
- ドットファイルにしない（チームに設定の存在を認識させるため）

## baseline

- fingerprint は SHA256 で生成（ファイルパス + 行番号 + マッチ文字列 のハッシュ）

## パッケージ管理

- pip + pyproject.toml
- `keygate` コマンドは `[project.scripts]` で登録

## 実装状況（2026-04-22）

全モジュール実装完了。163 テスト全通過、検証ハーネス 53/53 全パス（検知率 100%、誤検知 0%）。

- pyproject.toml: `setuptools.build_meta`（Raspberry Pi の setuptools が古く `setuptools.backends.legacy` は使用不可）
- `pip install -e ".[dev]" --break-system-packages` でインストール済み

## 既知ルール（rules.py）

`aws-access-key`、`openai-api-key`、`github-token`、`slack-token`、`private-key-pem`、`jwt`、`stripe-secret-key`、`stripe-publishable-key`、`sendgrid-api-key`、`url-credentials`

## パッケージ公開（PyPI）

- パッケージ名：`keygate`（`secretgate` は既に他者が PyPI で取得済み）
- PyPI: https://pypi.org/project/keygate/
- GitHub: https://github.com/kanekoyuichi/keygate
- 認証方式：**PyPI Trusted Publisher（GitHub Actions OIDC）**。API トークンは使わない
- リリースフロー：`pyproject.toml` の version と `CHANGELOG.md` を更新 → `git tag vX.Y.Z && git push origin vX.Y.Z` → `.github/workflows/publish.yml` が自動で sdist/wheel を PyPI に公開
- 初回公開：v0.1.0（2026-04-23）
- バージョン再利用不可：PyPI の仕様上、同一バージョンは削除後も再アップロード不可
- ローカル pre-commit フックの副作用：keygate 自身のテストフィクスチャは BLOCK されるため、`tests/test_scanner/test_scoring.py` の 3 行に inline ignore を付与している

## 将来タスク（本リリース対象外）

- strict / 保守モード分離（`keygate.toml` の `[scan.mode]` 設定化）
- `.claude/report/validate.py` の Precision/Recall/F1/BLOCK率/WARN率 自動集計
- TN 負例の大幅追加（Base64 長文、ダミー JWT、`.env.example`、fixture、コメント化された秘密風文字列）
- 汎用シークレット補助ルール（`generic-high-entropy-secret` 命名パターン特化、現状フェーズ1で BLOCK 到達済みのため不要）
- context-only 検知の baseline fingerprint 化（現状は RuleMatch のみ fingerprint 対象）
- publish workflow のアクションを Node.js 24 対応版に更新（2026-09-16 までに `actions/checkout`、`actions/setup-python` を更新）

## ディレクトリ構成

```
src/
  keygate/
    cli.py
    config.py
    scanner/
      rules.py
      entropy.py
      context.py
      scoring.py
    diff/
      parser.py
    hook/
      installer.py
    policy/
      allowlist.py
      baseline.py
      inline.py
tests/
  test_scanner/
  test_diff/
  test_hook/
  test_policy/
```
