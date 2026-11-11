//go:build !unix

package sys

import "io/fs"

func platformOwner(fs.FileInfo) (uint32, uint32, bool) { return 0, 0, false }
