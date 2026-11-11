package sys

import "io/fs"

// FileOwner is what a fake FileInfo's Sys() returns.
type FileOwner struct{ UID, GID uint32 }

// Owner returns the owning uid and gid of fi, if the platform knows them.
func Owner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	if o, isFake := fi.Sys().(*FileOwner); isFake {
		return o.UID, o.GID, true
	}
	return platformOwner(fi)
}
