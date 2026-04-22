# secretgate

**APIキーやパスワードを誤って Git にコミットしてしまう事故を防ぐツール**です。

---

## なぜ必要なのか

開発中、コードに API キーやパスワードを直接書いてしまうことがあります。それをそのまま `git commit` すると、リポジトリの履歴に永久に残ってしまいます。

たとえ後で削除しても、過去のコミットからは取り出せるため、GitHub などに公開されるとすぐに悪用されます。AWS のキーが漏れて高額請求された事例も多くあります。

`secretgate` は **コミット直前に自動でチェック** し、危険なものが含まれていれば止めてくれます。

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

`secretgate` は Python 製のコマンドラインツールです。`pipx` というツールでインストールするのが一番簡単です。

```bash
pipx install secretgate
```

> `pipx` がない場合は `pip install pipx` でインストールできます。
> `pipx` を使うと、どのプロジェクトのフォルダからでも `secretgate` コマンドが使えるようになります。

### ステップ2: フックを有効化する

「フック」とは、Git が特定のタイミングで自動的に実行してくれる仕組みのことです。`secretgate install-hook` を実行すると、`git commit` のたびに `secretgate` が自動で動くようになります。

```bash
cd path/to/your-project   # 自分のプロジェクトに移動
secretgate install-hook
```

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
  Add comment: # secretgate: ignore reason="..."
```

**読み方：**
- `File: config.py:12` — 問題のあるファイルと行番号
- `Rule: aws-access-key` — 何を検知したか
- `Score: 100` — 危険度（70以上で自動ブロック、40〜69は警告のみ）
- `Reason` — 検知の理由
- `Remediation` — 直し方の提案

---

## 手動でスキャンする

フックを使わず、その場でチェックすることもできます。

```bash
git add .
secretgate scan
```

`git diff --cached`（ステージ済みの変更）に対してスキャンを実行します。

---

## 誤検知が出たときの対処

`secretgate` は安全に倒すため、まれに本物ではないものも検知します。そのときの対処法を3つ用意しています。

### 方法1: コメントで「これは無視していい」と伝える

その行限定で無視できます。理由を書くのが必須です。

```python
api_key = "dummy-key-for-testing"  # secretgate: ignore reason="テストデータ"
```

### 方法2: ファイルやキーワードを丸ごと除外する

プロジェクトのルートに `secretgate.toml` というファイルを作って、除外したいファイルパスやキーワードを書きます。

```toml
[allowlist]
paths = ["vendor/*", "third_party/*"]  # 自分のコードではない箇所は無視
patterns = ["dummy", "example"]         # この単語を含む行は無視
```

> 注意: `tests/*` のようにテスト全体を allowlist に入れると、テストコードに混入した本物のシークレットを見逃します。テスト側の誤検知は方法1（inline ignore）か方法3（baseline）で対処してください。

### 方法3: 既存の検知をすべて見逃しリストに登録する（baseline）

これから新しく加わるものだけチェックしたい場合に便利です。

```bash
secretgate baseline create
```

現時点の検知結果が `.secretgate.baseline.json` というファイルに保存され、それ以降は同じ場所を検知しても無視されます。

新しく見逃しリストに追加したいものが出てきたら、こうします：

```bash
secretgate baseline update
```

#### チームで共有する

`.secretgate.baseline.json` は Git にコミットして共有することをおすすめします。共有しておけば、チーム全員が同じ「見逃してよい検知」リストを使えます。

```bash
git add .secretgate.baseline.json
git commit -m "Add secretgate baseline"
```

新しくプロジェクトに参加した人は、`pipx install secretgate` と `secretgate install-hook` を実行するだけで、共有された baseline がそのまま使われます。

---

## 設定ファイル（必要な人だけ）

デフォルト設定で十分動きますが、好みに合わせて変更できます。`secretgate.toml` をプロジェクトのルートに作ります。

```toml
[scan]
entropy_threshold = 4.2    # ランダムに見える文字列を検知する基準（厳しくしたいなら下げる）
block_score = 70           # この点数以上でコミットを止める

[allowlist]
paths = ["vendor/*"]
patterns = ["dummy", "example"]

[baseline]
path = ".secretgate.baseline.json"
```

設定ファイルがなければデフォルトで動作します。

---

## よくある質問

**Q. うっかり機密情報をコミットしてしまったらどうすれば？**

A. すぐにそのキーを無効化（rotate）してください。Git の履歴から消すだけでは不十分です。漏れた可能性のあるキーは攻撃者の手に渡っていると考えるべきです。

**Q. フックを一時的に無効化したい**

A. `git commit --no-verify` で `secretgate` を含むすべてのフックをスキップできます（ただし非推奨です）。

**Q. チームで共有するには？**

A. `secretgate.toml` と `.secretgate.baseline.json` を Git にコミットして共有してください。各メンバーは `secretgate install-hook` をそれぞれ実行する必要があります。
