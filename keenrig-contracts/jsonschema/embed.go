// Package jsonschema embed các file JSON Schema của contracts
// (go:embed không vượt được thư mục cha nên file này phải nằm tại đây).
package jsonschema

import "embed"

//go:embed *.json
var FS embed.FS
