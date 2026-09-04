---
schemaVersion: 1
color: "#d4553f"
initials: "hp"
cat:
  ja: "監視ツール / Go"
  en: "Monitoring / Go"
tagline:
  ja: "サーバーが黙ったことに、人より先に気づく。"
  en: "Notice a server has gone quiet before anyone tells you."
short:
  ja: "レンタルサーバーと小規模 VPS の死活監視だけを担う OSS。cron で動く agent が署名付き heartbeat を送り、届かなくなったら知らせる。"
  en: "Liveness monitoring for shared hosting and small VPS fleets. A cron-driven agent posts signed heartbeats; the monitor tells you when they stop arriving."
tech: ["Go", "CLI", "FreeBSD", "systemd", "HMAC", "Self-hosted"]
store: null
live: "https://ishizakahiroshi.github.io/heartpost/"
guide: null
featured: false
features:
  - icon: "◷"
    title: { ja: "来ないことを検知する", en: "Detects the absence" }
    desc:  { ja: "値の異常ではなく、レポートが届かなくなったことを見る。完全に止まったサーバーは異常値すら送ってこない。", en: "Watches for reports that stop arriving, not for bad values. A server that is fully down cannot even send a bad value." }
  - icon: "△"
    title: { ja: "root もパッケージも要らない", en: "No root, no packages" }
    desc:  { ja: "共有ホスティングの制約（root なし・常駐プロセス不可）を前提に、cron から 1 回動いて終わる形にした。", en: "Built for shared hosting from the start: no root, no daemon, one shot from cron." }
  - icon: "◇"
    title: { ja: "1 回鳴って、直ったらもう 1 回", en: "One alert, then one recovery" }
    desc:  { ja: "状態が変わったときだけ通知する。鳴りっぱなしの監視は、結局みんな通知を切る。", en: "Notifies only on state change. Monitors that keep shouting get muted." }
shots:
  - path: portfolio/dashboard-alive.jpg
    caption: { ja: "一覧は 1 枚。サーバー名・状態・最終受信・経過・ディスク・load だけ。", en: "One page: name, state, last seen, elapsed, disk, load." }
  - path: portfolio/dashboard-down.jpg
    caption: { ja: "欠報は赤地で最上段へ。同時に webhook が 1 通だけ飛ぶ。", en: "A missing server moves to the top in red, and one webhook goes out." }
---

## ja

サーバーが落ちたことに、人はたいてい自分では気づかない。気づくのは「サイトが見られない」と誰かに言われたときで、そこまでの間ずっと止まっている。監視を入れていない理由も毎回同じで、入れるほうが面倒だからだ。

とくにレンタルサーバー（共有ホスティング）は条件が厳しい。root 権限が無い。パッケージを入れられない。常駐プロセスを置けない。監視エージェントを入れる前提の道具は、この時点でほぼ全部使えなくなる。

heartpost は「cron から 1 回だけ動いて終わる 1 個のファイル」という形にして、この制約を最初から前提にした。各サーバーの agent が基本的な状態を集め、HMAC 署名を付けて、自分で建てた受信サーバーへ POST する。受信側はそれを保存し、**届かなくなったら知らせる**。

設計の中心にあるのは「来なかったこと」の検知にある。値が異常になったことを知らせる仕組みは山ほどあるが、サーバーが完全に止まると異常値すら送られてこない。何も届かない状態は「すべて健康で静か」と見た目が区別できない。そこを分けるのがこの道具の役目である。

### 集めるもの

共有ホスティング向けに 9 項目（ホスト情報・負荷平均・メモリ・ディスク・cron・プロセス・CPU・ネットワーク・アクセスログ）、Linux VPS 向けに 8 項目（システム・プロセス・cron・systemd サービス・証明書の残日数・SSH ログ・nginx ログ・適用可能な更新）。どれも読むだけで、サーバーへ書き込む処理は持たない。項目は 1 つずつ設定で切れる。

### 決めたこと

外部サービスに預けない。受信側も自分のサーバーに建てる。データベースは要らず、受け取ったものは 1 行 1 レポートのテキストとして追記し、指定した日数で消す。

1 回の取りこぼしで騒がない。既定では実行間隔の 3 倍だまってから欠報と判断する。ホストが一時的に重かった、cron がバックアップと重なった、程度で起こされない。

画面は 1 枚に留める。ダッシュボードを設計する作業そのものを発生させない。

そして、この monitor 自身が落ちていれば欠報に気づけない。落ちた monitor の見た目は「全台が健康で静か」と同じである。これは後で直せる穴ではなく、1 点にまとめる監視が構造的に持つ穴なので、認証なしの `/healthz` を用意したうえで「外から別の手段で見てください」と README に明記している。

### やらないこと

APM・分散トレーシング、ログ集約基盤、時系列 DB とグラフ、通知の振り分けルール、SaaS としての提供。グラフとクエリ言語が要るなら Prometheus や Zabbix のほうが合う。heartpost が答えるのは 1 つだけで、「まだ報告してきているか」である。

## en

People rarely notice their own server going down. They find out when someone says the site is unreachable — and it has been down the whole time until then. The reason monitoring never got set up is always the same: setting it up was more work than living without it.

Shared hosting makes that worse. No root. No package installation. No resident processes. Most monitoring tools assume an agent you can install as a service, and stop being an option right there.

heartpost is shaped around those constraints: a single file that cron runs once and that exits. The agent on each server collects a handful of basics, signs the payload with HMAC, and POSTs it to a monitor you host yourself. The monitor stores the reports and **tells you when they stop arriving**.

Detecting absence is the whole point. Plenty of tools alert on a bad value, but a server that is fully down cannot send a bad value either. "Nothing arrived" looks exactly like "everything is healthy and quiet" unless something separates the two.

### What it collects

Nine items for shared hosting (host info, load average, memory, disk, cron, processes, CPU, network, access log) and eight for a Linux VPS (system, processes, cron, systemd services, certificate expiry, SSH log, nginx log, available updates). All read-only — the agent never writes to the server it watches. Each item can be turned off individually.

### Decisions

Nothing is handed to a third-party service; you run the receiver too. No database: reports are appended as one line each and deleted after a retention window you choose.

It does not shout about a single miss. By default a server is called down only after three intervals of silence, so a slow host or a cron tick that overlapped a backup does not wake anyone.

The dashboard stays at one page, so that designing a dashboard never becomes a task of its own.

And a monitor that is itself down cannot report absence — it looks identical to a world where every server is healthy and quiet. That is not a gap to fix later; every single-point liveness checker has it. heartpost exposes an unauthenticated `/healthz` and the README says plainly to watch it from outside this system.

### Not in scope

APM and tracing, log aggregation, a time-series database with graphs and a query language, alert routing trees, a hosted service. If you want graphs and a query language, Prometheus or Zabbix fits better. heartpost answers one question: *is it still reporting?*
