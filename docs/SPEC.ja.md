# KeyGate 技術ガイド

このドキュメントは、以前の `SPEC.md`、`DETECTION_RULES.md`、`ARCHITECTURE.md` を 1 つに統合した技術リファレンスです。

## プロダクトのスコープ

`keygate` は、リポジトリ履歴に残る前に、新しく追加されたシークレットをローカルの Git pre-commit で検知することに特化したスキャナです。

コミット時に動作し、ステージ済みの追加差分だけを対象にする、高速でオフラインなチェックが必要な場面で使います。

`keygate` の目的は次の通りです。

- コミット前にシークレットらしい値をブロックする
- 日常開発で扱える範囲に誤検知を抑える
- inline ignore、allowlist、baseline による現実的な例外運用を支える

## 非目標

`keygate` は意図的にスコープを絞っています。デフォルトでは次を行いません。

- リポジトリ全体の履歴スキャン
- 未ステージファイルのスキャン
- 外部 API を使った資格情報の有効性確認
- 値がシークレットかどうかを LLM に判定させること
- IDE プラグインとしての提供（VS Code 拡張など）

> 補足：`.claude-plugin/` 配下の Claude Code プラグイン（0.1.8 で追加）は、既存 CLI を Skill と Slash Command として薄くラップしたものです。内部では `keygate scan --profile agent` を呼ぶだけで、LLM ベースの検知や新たな IDE 統合を導入しません。検知ロジック・ポリシー・終了コードは CLI と完全に同一です。

## スキャン対象

デフォルトのスキャン対象は次の通りです。

- `git diff --cached` の追加行

つまり `keygate` は、リポジトリ内にすでに存在する全内容ではなく、これからコミットされる差分に集中します。

## コマンド

```bash
keygate scan
keygate scan --format json
keygate scan --json
keygate scan --profile agent
keygate activate
keygate deactivate
keygate install-hook
keygate uninstall-hook
keygate baseline create
keygate baseline update
```

## 終了コード

- `0`: pass または warn
- `1`: block
- `2`: usage error

## 出力モード

デフォルト出力は人間向けの text です。先頭にサマリ行が付きます。

```text
[KEYGATE] status=block findings=1
```

自動化用途では JSON 出力を使います。

```bash
keygate scan --format json
```

JSON ペイロードには、固定の schema version、全体 status、summary オブジェクト、構造化された findings が含まれます。

## 設定ファイル

任意の設定ファイルは、リポジトリルートの `keygate.toml` に置きます。

```toml
[scan]
entropy_threshold = 4.2
block_score = 70

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]
keywords = ["fixture"]

[baseline]
path = ".keygate.baseline.json"
```

## 検知ルール

`keygate` は単一の regex に依存せず、複数のシグナルを組み合わせます。これにより、デフォルト hook の速度を保ちながら、典型的な誤検知の一部を避けています。

### ルールベース検知

`keygate` には、一般的な資格情報フォーマット向けの専用ルールがあります。

- AWS access key
- OpenAI API key
- GitHub token
- Slack token
- PEM 形式の private key
- JWT
- Stripe live secret key
- Stripe live publishable key
- SendGrid API key
- `postgres://user:password@host` のような埋め込み credentials を含む URL <!-- keygate: ignore reason="documentation example" -->

各ルールは次を持ちます。

- 安定した `rule_id`
- score
- `policy`

### ポリシー

ユーザーから見える policy は 2 種類あります。

| Policy | 意味 |
| --- | --- |
| `must_block` | デフォルトで機密扱い。強い一致なら単独で block に届きやすい。 |
| `public_exposable` | 公開前提、またはマスク済みサンプルでよく現れる値。block ではなく warn 相当で扱う。 |

`public_exposable` の例:

- Stripe publishable key
- `postgres://user:***@host/db` のようなマスク済み URL credentials <!-- keygate: ignore reason="documentation example" -->

### エントロピー検知

既知ルールに一致しない値に対しては、Shannon entropy を使ってランダムらしい文字列も見ます。

高エントロピーだけでは不十分なことが多いため、次のような文脈と組み合わせて使います。

- `api_key` や `password` のような変数名
- `NAME=...` のような代入構文
- `.env` のような機微なファイルパス

### コンテキストシグナル

高レベルなコンテキストシグナルには次があります。

- シークレット関連キーワード
- 機微なファイルパス
- 代入構文

これらのシグナルにより、通常の文字列と、コードや設定に代入されているシークレットらしい値を区別しやすくしています。

### スコアリングと判定

すべてのシグナルを組み合わせて最終スコアを作ります。

- `70+`: `block`
- `40-69`: `warn`
- `<40`: ignore

`README.md`、`docs/*`、`*.env.example`、`tests/fixtures/*` のようなプレースホルダーやドキュメント寄りの文脈では、サンプルが過剰に block されないよう一部の検知を意図的に降格します。

### 誤検知対策

`keygate` には、想定された検知を抑制するための主な手段が 3 つあります。

- reason 必須の inline ignore コメント
- `keygate.toml` による allowlist path / pattern 設定
- 既存検知を登録する baseline ファイル

### プライバシーモデル

`keygate` はローカル・オフライン利用を前提にしています。

- ステージ済みの行はローカルでスキャンする
- 資格情報の検証に外部 API は使わない
- baseline には生のシークレットではなく fingerprint を保存する

## アーキテクチャとフロー

ここでは、ユーザーから見えるスキャンフローを高レベルで説明します。

### スキャンフロー

`keygate scan` を実行したとき、またはインストール済み Git hook が `git commit` 中に動いたときの流れは次の通りです。

1. `git diff --cached` からステージ済み差分を読む
2. 追加行だけを抽出する
3. inline-ignore と allowlist を適用する
4. rule、entropy、context の検知を走らせる
5. 各 finding を `block`、`warn`、ignore にスコアリングする
6. baseline 済みの finding を除外する
7. 結果を text または JSON に整形する

### Git hook の挙動

`keygate activate` は、Git が実際に使う hooks ディレクトリへ pre-commit hook をインストールします。`keygate install-hook` は互換コマンドとして残します。

`keygate deactivate` は keygate が導入した hook を削除します。既存 hook が keygate によるものではない場合は、削除前に確認します。`keygate uninstall-hook` は互換コマンドとして残します。

hook はローカルで動き、次を満たすことを意図しています。

- 通常の commit ワークフローで十分高速であること
- オフラインでも使えること
- 同じ staged diff に対して決定的に再現できること

生成される hook は、現在の Python 実行環境を優先し、必要に応じて `keygate scan` にフォールバックします。

### データファイル

主なユーザー向けファイルは次の通りです。

- `keygate.toml`: 任意設定
- `.keygate.baseline.json`: 許容済み既存検知の fingerprint 保存先

### 出力設計

text 出力は人間向けに最適化されています。

- 先頭に summary line
- finding の詳細
- remediation guidance
- block 時の JSON 再実行ヒント

JSON 出力はツール向けに最適化されています。

- stdout に JSON のみ
- 固定 schema version
- 構造化された summary と findings

### コード配置

リポジトリをたどる場合、実装本体は `src/keygate/`、テストは `tests/` 配下にあります。

主な領域は次の通りです。

- CLI entry points
- diff parsing
- rules、entropy、context、scoring の scanner modules
- allowlist、baseline、inline ignore の policy modules
- text と JSON の output formatters

## 公開向けドキュメント

- [`README.md`](../README.md): インストール、使用例、日常運用向けガイド
