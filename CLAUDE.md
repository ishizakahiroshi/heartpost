<!-- このファイルはプロジェクト固有ルールのみを書く。個人/グローバル AI ルール
（言語・確認スタイル・出力フォーマット等）は各 AI ツールのグローバル設定へ。
fresh public clone でも有効な内容に保つこと。 -->

# heartpost 開発ガイド

> **このファイルは索引であって本文ではない。** 全 AI セッションで全文がロードされるので、
> ルールの本文はここへ書かず、破る人が必ず開く場所（コード・検査スクリプト・skill・guide・台帳）へ置き、
> ここには索引の 1 行だけを残す。新しいルールを足す前に既存の CLAUDE.md・skill・guide・台帳を検索し、
> 正本が既にあれば参照だけにする。詳細は下記「設計原則の索引」。

## プロジェクト概要

heartpost は、レンタルサーバー（共有ホスティング）と小規模な VPS の**死活監視**だけを担う道具。
各サーバーで cron から one-shot の agent が動き、基本的な指標を集めて、HMAC 署名付きの heartbeat を
自前でホストする monitor へ POST する。monitor はそれを保存し、**レポートが来なくなったら知らせる**。
最後の 1 点が本体で、指標の数を競う道具ではない。

想定利用者は、さくらのレンタルサーバー等の共有ホスティングと VPS を数台〜十数台持っていて、
「落ちたことに気づけない」を解消したいだけの管理者。root 権限もパッケージ導入も要らないことを前提にする。

## やらないこと（スコープ外）

- APM・分散トレーシング
- ログ集約基盤・全文検索
- 時系列 DB とクエリ言語つきダッシュボード
- SaaS としての提供（monitor は利用者が自分で建てる）
- 通知ルーティングの分岐条件を組み立てる仕組み（webhook を 1 本出すところまで）
- agent 側からのサーバー操作（再起動・デプロイ・設定変更）。**収集と送信だけを行い、書き込みはしない**

## 技術スタック

| 項目 | 内容 |
|---|---|
| 言語 | Go 1.25 |
| module | `github.com/ishizakahiroshi/heartpost` |
| 外部依存 | 最小限に保つ（TOML パーサ程度） |
| 対象 OS | agent: FreeBSD（共有ホスティング）/ Linux、monitor: Linux |
| 配布 | GitHub Releases（linux/amd64・linux/arm64・freebsd/amd64） |

## ディレクトリ構成

<!-- TODO: 実装が入ったら埋める。予定は以下。
- collector/ — collector インターフェースと共有基盤
- collector/rental/ — 共有ホスティング向け collector
- collector/vps/ — Linux VPS 向け collector
- agentsig/ — レポート署名（HMAC）
- report/ — レポートのスキーマ型・ヘッダ定数
- cmd/heartpost-agent/ — agent 本体
- cmd/heartpost-monitor/ — 受信 monitor
-->

## 主要コマンド

- テスト: `go test ./...`
- ビルド: `go build ./...`
- FreeBSD 向けクロスビルド: `GOOS=freebsd GOARCH=amd64 go build ./cmd/heartpost-agent`
- secrets-scan（手動）: `node scripts/secrets-scan.mjs --staged --block`
- CLAUDE.md 構造検査: `node scripts/check-claude-md.mjs`

## 設計原則の索引（本文は正本にある）

事故から生まれた設計ルールを追記する表。**本文はここに書かず、破る人が必ず開く場所に置く。**

| ルール | 正本（本文はここ） | 機械検査 |
|---|---|---|
| レポートのワイヤ仕様（パス・ヘッダ 3 種・payload の 5 キー・署名形式）は破壊的に変えない。変えると稼働中の全 agent が受信側から拒否される | `report/report.go` の定数とコメント | `report/report_golden_test.go`・`agentsig/agentsig_golden_test.go` |
| 署名の計算は 1 箇所にしか置かない（送信側と検証側で別実装にしない） | `agentsig/agentsig.go` | `hmac.New` の出現箇所が `agentsig` だけであること |
| collector は読むだけ。サーバーへ書き込む処理を持たせない | `collector/collector.go` のインターフェース定義 | なし（レビュー時に見る） |
| 鍵ファイルは 600 でなければ agent を起動しない（共有ホスティングは他人と同居する） | `cmd/heartpost-agent/config.go` | なし（起動時にエラーで落ちる） |

**新しいルールを足す前に、まずこの表に 1 行足せる形にできないかを考える。**

## AI 作業共通ルール

ビルド・コミット禁止、secrets-scan 責務、plan/bugfix/pending md の作成ルール等の AI 作業共通ルールは、各利用者のグローバル AI 設定に従う（作者環境の例: `~/.claude/CLAUDE.md` および `~/.claude/guides/`）。

このリポジトリ固有:

- **上流と下流の向きを守る。** 収集ロジックと署名とレポートのスキーマはこのリポジトリが正本で、利用側（作者の非公開リポを含む）は module として import する。利用側で直して後からこちらへ写す運用はしない
- 実サーバーのホスト名・IP・顧客名をコード・テスト・ドキュメントへ書かない。テストのフィクスチャは RFC 5737 のドキュメント用アドレス（`203.0.113.0/24` 等）と架空のホスト名を使う

## Obsidian artifacts

If `docs/obsidian/README.md` exists, use it as an index for related knowledge artifacts.
Use the repository-relative `docs/obsidian` entry. Do not write to a central absolute
path and do not silently fall back to `docs/local` when the entry is missing.

## secrets-scan（このリポジトリの配線）

書く瞬間の責務（固有名詞の一般化・fixture は合成データ等）は上記「AI 作業共通ルール」の参照先に従う。このリポジトリ固有の配線は以下:

- scanner: `scripts/secrets-scan.mjs`（手動実行: `node scripts/secrets-scan.mjs --staged --block`）
- layer 2: `.githooks/pre-commit`（`git config core.hooksPath .githooks` で有効化。clone 後は `scripts/install-hooks.sh` または `scripts/install-hooks.ps1`）
- layer 3: `.github/workflows/secrets-scan.yml`
- env (full coverage に必要・未設定なら構造 regex のみで継続): `KB_ROOT` / `FAMILY_ROOT`。設定詳細は `scripts/secrets-scan.mjs` の冒頭コメント

## 関連ドキュメント

| 項目 | パス |
|---|---|
| ユーザー向け README | `README.md` |
| Codex/他 AI 用入口 | `AGENTS.md` |
| ローカル作業ノート（非公開） | `docs/local/`（存在する場合） |
| Obsidian knowledge artifacts | `docs/obsidian/`（存在する場合。作業キューではない） |
