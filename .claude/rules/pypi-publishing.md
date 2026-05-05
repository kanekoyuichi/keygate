# PyPI Publishing Rules

このリポジトリで PyPI に公開する場合は、以下のルールに従う。

## 公開方式

- PyPI 公開は `.github/workflows/publish.yml` を使う。
- 公開トリガーは GitHub Release の `published` イベントとする。
- Git タグ push だけでは PyPI 公開しない。
- GitHub Release は `vX.Y.Z` 形式のタグに紐付ける。
- パッケージのビルドは `python -m build` で行う。
- PyPI へのアップロードは `pypa/gh-action-pypi-publish` を使う。
- 認証は GitHub Actions OIDC / PyPI trusted publishing を前提にする。
- PyPI API token や password をリポジトリ、workflow、ローカル設定ファイルに追加しない。
- workflow は Release のタグを checkout し、そのタグ名と `pyproject.toml` の version が一致しない場合は公開前に失敗させる。

## 公開前チェック

Release を publish する前に最低限確認する。

- `.claude/rules/versioning.md` のルールに従っている。
- `pyproject.toml` の `[project].version` が公開するバージョンと一致している。
- `CHANGELOG.md` の最新見出しが公開するバージョンと一致している。
- `CHANGELOG.md` の日付が公開日として正しい。
- `README.md` が PyPI の long description として破綻していない。
- CLI / JSON / hook / baseline / plugin のユーザー向け挙動を変えた場合、README と docs を更新している。
- `keygate --version` が公開するバージョンを返す。
- CI と同等の検証をローカルまたは GitHub Actions で通している。

推奨するローカル確認:

```bash
python -m pip install -e ".[dev]"
ruff check src tests
mypy src
pytest --cov=keygate --cov-report=term-missing
python -m build
```

## タグ作成

- タグ名は `vX.Y.Z` とする。
- タグ名の `X.Y.Z` は `pyproject.toml` の version と完全一致させる。
- タグは、対応する version / changelog / docs 更新を含むコミットに付ける。
- GitHub Release はこのタグを指定して作成する。
- Release のタイトルも原則としてタグ名 `vX.Y.Z` と一致させる。
- Release publish 前に `git status` が意図した状態であることを確認する。
- タグ公開後に同じバージョン番号を再利用しない。

## 公開後チェック

Release publish 後に確認する。

- `Publish to PyPI` workflow が成功している。
- PyPI の `keygate` ページに新バージョンが表示されている。
- GitHub Release と Git タグが同じ `vX.Y.Z` を指している。
- 公開された wheel / sdist から `keygate --version` が期待値を返す。
- README の表示崩れやリンク切れが目立たない。

## 失敗時の扱い

- PyPI へ一度公開された version は削除・再アップロード前提にしない。
- 壊れた成果物を公開した場合は、原則として次の `PATCH` バージョンで修正して再公開する。
- workflow 失敗が PyPI アップロード前なら、原因を修正して同じタグを使えるか確認する。
- タグや Release の付け間違いが PyPI 公開前に分かった場合のみ、Release の修正やタグ再作成を検討する。
- タグ済みかつ公開済みの履歴を書き換えない。

## セキュリティ制約

- 公開作業のためにシークレット検知の外部 API 検証を追加しない。
- 公開作業のために LLM 判定を検知ロジックへ追加しない。
- PyPI credential、token、`.pypirc` の中身をコミットしない。
- workflow の permission は必要最小限に保つ。PyPI 公開には `id-token: write`、Release タグの checkout には `contents: read` を使う。
- 公開前後の確認で実シークレット値をログに出さない。

## 禁止事項

- `pyproject.toml` と異なるバージョン名のタグで公開しない。
- `CHANGELOG.md` 未更新のまま公開しない。
- GitHub Actions を迂回して手元の認証情報で PyPI に直接公開しない。
- タグ push だけで PyPI 公開する workflow に戻さない。
- 公開済み version の wheel / sdist を差し替えようとしない。
- 公開準備コミットに無関係なリファクタリングを混ぜない。
