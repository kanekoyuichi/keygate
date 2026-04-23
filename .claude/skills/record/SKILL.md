---
name: record
description: 会話で決定した設計・仕様をプロジェクトの記録ファイルに追記する。「記録して」「決定を記録」などのフレーズで起動する。
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Edit
---

# /record — 設計決定を記録する

Arguments: `$ARGUMENTS`

## 記録先（必須）

**プロジェクトルート配下の `.claude/memory/decisions.md` のみに記録する。**

- 対象パス：現在の Git リポジトリルート（`git rev-parse --show-toplevel` の出力）＋ `/.claude/memory/decisions.md`
- `.claude/memory/` が存在しない場合は作成してから書き込む

## 書いてはいけない場所

以下には **絶対に書き込まない**：

- user-global の auto-memory（`~/.claude/projects/*/memory/`）
- ホームディレクトリ配下のその他の場所
- `.claude/report/` などプロジェクト内の他ディレクトリ

理由：プロジェクトの決定事項は Git で版管理してチームに共有するため、リポジトリ内に閉じる必要がある。

---

## 手順

1. `git rev-parse --show-toplevel` でプロジェクトルートを特定する
2. 現在の会話コンテキストから、今回決定した事項を抽出する
3. `<project_root>/.claude/memory/decisions.md` を Read で読み込む（なければ作成）
4. 既存の内容と重複しないよう確認する
5. 新しい決定事項を適切なセクションに追記、または既存セクションを更新する

## 記録ルール

- 決定した「結論」のみを記録する（議論の経緯は不要）
- 既存項目と同じカテゴリなら上書き更新（重複を作らない）
- 新しいカテゴリなら `##` セクションを追加する
- 箇条書きで簡潔に書く
- 日付は記載しない（git 履歴で追える）

## 出力

完了後、書き込んだファイルの絶対パスと、追記・更新した内容を 1〜3 行で要約して報告する。
