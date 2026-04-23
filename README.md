# keygate

**APIキーやパスワードを誤って Git にコミットしてしまう事故を防ぐツール**です。

---

## なぜ必要なのか

開発中、コードに API キーやパスワードを直接書いてしまうことがあります。それをそのまま `git commit` すると、リポジトリの履歴に永久に残ってしまいます。

たとえ後で削除しても、過去のコミットからは取り出せるため、GitHub などに公開されるとすぐに悪用されます。AWS のキーが漏れて高額請求された事例も多くあります。

`keygate` は **コミット直前に自動でチェック** し、危険なものが含まれていれば止めてくれます。

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

`keygate` は Python 製のコマンドラインツールです。`pipx` というツールでインストールするのが一番簡単です。

```bash
pipx install keygate
```

> `pipx` がない場合は `pip install pipx` でインストールできます。
> `pipx` を使うと、どのプロジェクトのフォルダからでも `keygate` コマンドが使えるようになります。

### ステップ2: フックを有効化する

「フック」とは、Git が特定のタイミングで自動的に実行してくれる仕組みのことです。`keygate install-hook` を実行すると、`git commit` のたびに `keygate` が自動で動くようになります。

```bash
cd path/to/your-project   # 自分のプロジェクトに移動
keygate install-hook
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
  Add comment: # keygate: ignore reason="..."
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
keygate scan
```

`git diff --cached`（ステージ済みの変更）に対してスキャンを実行します。

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

新しくプロジェクトに参加した人は、`pipx install keygate` と `keygate install-hook` を実行するだけで、共有された baseline がそのまま使われます。

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

[baseline]
path = ".keygate.baseline.json"
```

設定ファイルがなければデフォルトで動作します。

---

## よくある質問

**Q. うっかり機密情報をコミットしてしまったらどうすれば？**

A. すぐにそのキーを無効化（rotate）してください。Git の履歴から消すだけでは不十分です。漏れた可能性のあるキーは攻撃者の手に渡っていると考えるべきです。

**Q. フックを一時的に無効化したい**

A. `git commit --no-verify` で `keygate` を含むすべてのフックをスキップできます（ただし非推奨です）。

**Q. チームで共有するには？**

A. `keygate.toml` と `.keygate.baseline.json` を Git にコミットして共有してください。各メンバーは `keygate install-hook` をそれぞれ実行する必要があります。

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
