package db

import v1 "github.com/noqcks/xeol/xeol/db/v1"

// Closer lets receiver close the db connection and free any allocated db resources.
// It's especially useful if vulnerability DB loaded repeatedly during some periodic SBOM scanning process.
type Closer struct {
	v1.DBCloser
}
