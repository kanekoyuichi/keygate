# Versioning Rules

このリポジトリでバージョンを変更する場合は、以下のルールに従う。

## 基本方針

- バージョン番号は SemVer 形式 `MAJOR.MINOR.PATCH` を使う。
- `1.0.0` 未満でも、ユーザー影響が分かるように SemVer の意味を保つ。
- バージョンの単一の公開元は `pyproject.toml` の `[project].version` とする。
- リリース履歴は `CHANGELOG.md` に記録する。
- Git タグは `vX.Y.Z` 形式にする。

## バージョンを上げる基準

- `PATCH`: バグ修正、誤検知・検知漏れの調整、ドキュメント修正、テスト追加、内部実装の改善。
- `MINOR`: 新しい CLI オプション、検知ルール、出力フィールド、設定項目、Claude Code plugin 機能など、既存ユーザーを壊さない機能追加。
- `MAJOR`: 既存 CLI、設定ファイル、JSON schema、終了コード、baseline 互換性、hook の期待動作を壊す変更。

`0.x` 系では破壊的変更を `MINOR` に含めてもよいが、その場合でも `CHANGELOG.md` に `Breaking` セクションを明記する。

## 更新必須ファイル

バージョンを上げるコミットでは、原則として次を同じ変更に含める。

- `pyproject.toml`: `[project].version`
- `CHANGELOG.md`: 新バージョンの見出しと変更内容

CLI やユーザー向け挙動が変わる場合は、該当する公開ドキュメントも更新する。

- `README.md`
- `README.ja.md`
- `README.zh.md`
- `docs/SPEC.md`
- `docs/SPEC.ja.md`

仕様変更を伴う場合は `.claude/specs/` 配下も更新する。

## CHANGELOG の書き方

- 見出しは `## [X.Y.Z] - YYYY-MM-DD` とする。
- 日付はリリース予定日または実際のリリース日を使う。
- 変更内容は以下の区分を必要に応じて使う。
  - `Features`
  - `Fixes`
  - `Improvements`
  - `Docs`
  - `Breaking`
- ユーザーから見える影響を優先して書き、内部事情だけの説明にしない。
- セキュリティやシークレット検知に関わる変更では、誤検知・検知漏れ・速度・オフライン動作への影響を明記する。

## リリース前チェック

リリース前に最低限確認する。

- `pyproject.toml` の version と `CHANGELOG.md` の最新見出しが一致している。
- `CHANGELOG.md` の日付が正しい。
- `keygate --version` が新しいバージョンを返す。
- `keygate scan` のデフォルト対象が `git diff --cached` の追加行のみである。
- フルリポジトリスキャン、LLM 判定、外部 API 検証を追加していない。
- CLI / JSON / hook / baseline の挙動を変えた場合は、対応するテストと README を更新している。

## タグと公開

- タグは `vX.Y.Z` 形式で作成する。
- タグ対象のコミットには、対応する `pyproject.toml` と `CHANGELOG.md` の更新を含める。
- タグ公開後に同じバージョン番号を再利用しない。
- 公開に失敗した場合も、同じ成果物を再公開できない状態なら次の `PATCH` を切る。

## 禁止事項

- `pyproject.toml` 以外に独立したバージョン定義を増やさない。
- `CHANGELOG.md` を更新せずにリリースしない。
- タグ済みバージョンの内容を書き換えない。
- バージョン変更と無関係なリファクタリングを同じリリース準備コミットに混ぜない。
- リリース準備のためにフルリポジトリスキャン、LLM 判定、外部 API 検証を追加しない。
