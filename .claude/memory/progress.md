# 進捗記録

最終更新: 2026-04-22

---

## 完了済み

### CLAUDE.md の仕様策定
- プロジェクト概要・非目標・成功条件を定義
- 検知ロジック（ルールベース・エントロピー・コンテキスト・スコアリング）を仕様化
- 誤検知対策（allowlist / baseline / inline ignore）を仕様化
- CLI仕様・出力仕様・設定ファイル仕様を確定
- アーキテクチャ（src/secretgate/ + tests/）を確定

### 設計決定（decisions.md に詳細あり）
- `secretgate scan` が staged diff をデフォルトスキャン（--staged フラグなし）
- warn はコミット続行、block のみ停止
- 設定ファイルは `secretgate.toml`（リポジトリルート）
- baseline fingerprint は SHA256（ファイルパス + 行番号 + マッチ文字列）
- pip + pyproject.toml、`[project.scripts]` でコマンド登録
- context.py はスコア加算値を返すのみ、集約は scoring.py が担う

### README.md
- ユーザー向けドキュメント作成済み
- pipx 推奨（どのプロジェクトからでも使える）、pip も対応

### 実装（全モジュール完了）

| ファイル | 内容 |
|---|---|
| `pyproject.toml` | パッケージ定義、エントリポイント |
| `src/secretgate/models.py` | DiffLine, RuleMatch, ScanResult, PolicyResult, Verdict |
| `src/secretgate/config.py` | secretgate.toml 読み込み（tomllib） |
| `src/secretgate/diff/parser.py` | git diff --cached パース、追加行抽出 |
| `src/secretgate/scanner/rules.py` | regex ルール検知（AWS/OpenAI/GitHub/Slack/PEM/JWT） |
| `src/secretgate/scanner/entropy.py` | Shannon エントロピー検知 |
| `src/secretgate/scanner/context.py` | コンテキストスコアリング |
| `src/secretgate/scanner/scoring.py` | スコア集約・BLOCK/WARN/IGNORE 判定 |
| `src/secretgate/hook/installer.py` | .git/hooks/pre-commit への書き込み |
| `src/secretgate/policy/inline.py` | inline ignore コメント解析 |
| `src/secretgate/policy/allowlist.py` | パス・パターン allowlist |
| `src/secretgate/policy/baseline.py` | SHA256 fingerprint ベースの baseline 管理 |
| `src/secretgate/cli.py` | scan / install-hook / baseline create / baseline update |

### テスト
- 52テスト全通過（実行時間 0.10秒）
- test_scanner/, test_diff/, test_hook/, test_policy/ を網羅

### 環境メモ
- Raspberry Pi 環境のため `setuptools.backends.legacy` が使用不可
- `setuptools.build_meta` を使用
- インストール: `pip install -e ".[dev]" --break-system-packages`

---

## README 整合性修正（2026-04-22 追加）

実装の実出力と README の出力例にズレがあったため修正済み。

- Reason 文言を実装に合わせる（"AWS Access Key detected; sensitive context detected"）
- Remediation 文言を実装に合わせる（"Remove the key from the code" など）
- インデントを実装に合わせる（`  - ` の2スペース）
- Score 値を実 90+context10 = 100 に修正
- allowlist パターン例の `placeholder` を削除（仕様の dummy/example のみに統一）

---

## 自己レビューと修正（2026-04-22 追加）

実装後の自己レビューで以下のバグ・仕様乖離・スタイル違反を発見し、すべて修正済み。詳細は `review_2026-04-22.md` 参照。

- B1: `cli.py` の `baseline` コマンド重複登録
- B2: `get_staged_diff` のエラーハンドリング欠落
- S1: `_DUMMY_PATTERN` が仕様外（fake/mock/sample/placeholder を含んでいた）
- C1: WHAT コメントの削除（3ファイル）
- U1: 未使用 fixture の削除

修正後の動作確認（実 git リポジトリで AWS キーをステージ → BLOCK 出力 → exit 1）も完了。

---

## ドッグフーディング（2026-04-22 追加）

secretgate を自プロジェクトに適用：
- `git init`、`.gitignore` で Python 成果物・`.claude/` を除外
- `secretgate install-hook` で自身のフックをインストール
- baseline に 10 件の既存検知（テストの fake secret）を登録 → クリーンスキャン

### ドッグフーディング中に発見した制約

**inline ignore パーサは文字列リテラルを区別できない**

`tests/test_policy/test_inline.py:26` にあった `'key = "secret"  # secretgate: ignore'` という文字列リテラルを、実コメントと誤認してエラーを出す。

**暫定対処**: 同じ行末に `# secretgate: ignore reason="..."` を追加（with-reason が先にマッチするため抑制される）

**根本解決案（未実装）**: AST/トークン解析で実際のコメントのみをパースする。ただし対象が Python/JS/Go 等多様なので難しい。現実的には inline 誤検知は baseline で吸収する運用が正解。

---

## baseline 共有方針（2026-04-22 追加）

このリポジトリ（secretgate 自身）では `.secretgate.baseline.json` は **コミットしない**。
- 理由: 本リポはツール本体で、外部ユーザーは pipx でインストールする。baseline はコントリビューター（このリポのフックを動かす人）のみが必要なファイルで、外部ユーザーには不要。
- `.gitignore` に `.secretgate.baseline.json` を追加済み。
- コントリビューターは clone 後に `secretgate baseline create` を実行して自分用の baseline を作る。

ただし README では **ユーザーが自分のプロジェクトで secretgate を使うケース** 向けに「baseline は Git にコミットしてチーム共有する」ことを推奨している（方法3 と FAQ の両方）。本リポの方針はあくまで「ツール本体リポ特有の判断」。

---

## 未着手・次のステップ候補

- 初期コミット作成（ユーザー未承認）
- PyPI へのパッケージ公開
