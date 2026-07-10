// Package migrations exposes the embedded SQL migrations as an io/fs.FS.
package migrations

import "embed"

//go:embed all:sql
var FS embed.FS
