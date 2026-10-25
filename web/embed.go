// Package webassets 内嵌 Web 控制台前端静态资源。
//
// 资源随二进制一同打包（go:embed），镜像无需额外拷贝前端文件，离线可用；
// ECharts 图表库位于 vendor/echarts.min.js，由 /api/vendor/echarts.js 对外提供。
package webassets

import "embed"

// FS 前端资源集合，根目录对应本包目录（index.html / login.html / css / js / img / vendor）。
//
//go:embed favicon.ico index.html login.html css js img vendor
var FS embed.FS
