# CLAUDE.md

このリポジトリで作業するAIエージェントは、実装前に以下の仕様を確認すること。

- プロジェクト仕様: `.claude/specs/SPEC.md`
- 検知ルール詳細: `.claude/specs/DETECTION_RULES.md`
- アーキテクチャ: `.claude/specs/ARCHITECTURE.md`
- 運用ルール: `.claude/rules/`
- 公開向け説明: `README.md` / `README.ja.md` / `README.zh.md`
- ユーザー向け仕様書: `docs/SPEC.md` / `docs/SPEC.ja.md`

## 作業ルール

- `git diff --cached` の追加行のみをデフォルトのスキャン対象にする。
- フルリポジトリスキャンを初期バージョンへ追加しない。
- LLMや外部APIによるシークレット判定・有効性検証を追加しない。
- Git Hookでの実行速度とオフライン動作を優先する。
- バージョン変更やPyPI公開などの運用作業では `.claude/rules/` 配下の該当ルールを確認する。
- 仕様変更を伴う実装では `.claude/specs/` 配下も更新する。
- CLIやユーザー向け挙動を変更する場合は該当する`README.md` / `README.ja.md` / `README.zh.md`も更新する。
- ファイルの削除を行う場合は、必ずユーザーに事前に確認すること。
