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

形式：

- regexで実装
- rule_id を必ず持つ

---

### 5.2 エントロピー検知（必須）

- Shannon entropy を使用
- 閾値：4.0〜4.5（設定可能）
- 最低文字長：20文字以上

---

### 5.3 コンテキスト検知（必須）

以下の文脈を検知し、スコア加算値を返す（集約は scoring.py が行う）：

- `api_key`, `token`, `secret`, `password`：+20
- `.env`, `config`, `settings`：+10
- URL内の認証情報：+20

---

### 5.4 スコアリング（必須）

rules / entropy / context の全結果を集約し、最終スコアを算出して判定する。

スコアの例：

- regex一致: +50〜100
- 高エントロピー: +20
- 危険なキーワード: +20
- URL内認証情報: +20
- テストファイル: -10
- `example`, `dummy`: -20

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
# secretgate: ignore reason="test data"
```

制約：

- reason必須
- reasonなしはエラー

---

## 7. CLI仕様

### コマンド

```bash
secretgate scan               # staged diff をスキャン（デフォルト動作）
secretgate install-hook
secretgate baseline create
secretgate baseline update
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
Add comment: # secretgate: ignore reason="..."
```

---

## 9. 設定ファイル

ファイル名：`secretgate.toml`（リポジトリルートに配置）

```toml
[scan]
entropy_threshold = 4.2
block_score = 70

[allowlist]
paths = ["tests/*"]
patterns = ["dummy", "example"]

[baseline]
path = ".secretgate.baseline.json"
```

---

## 10. アーキテクチャ

ソースコードは `src/` 配下に配置する。テストは `tests/` 配下に配置し、pytest を使用する。パッケージ管理は pip + pyproject.toml を使用する。`secretgate` コマンドは pyproject.toml の `[project.scripts]` で登録する。

```text
src/
  secretgate/
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