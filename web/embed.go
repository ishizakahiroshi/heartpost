// Package web は monitor の一覧画面のテンプレートと静的ファイルを埋め込む。
//
// 外部 CDN を参照しないのは、この monitor が「外へ出られない、あるいは外が落ちている」
// 状況でこそ開かれる画面だから。画面の描画をネットワークに依存させない。
package web

import "embed"

// FS は画面 1 枚分のテンプレートと静的ファイル。
//
//go:embed dashboard.html static
var FS embed.FS
