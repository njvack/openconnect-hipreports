package sys

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Fake is a System that answers from recorded data. A fixture file holds
// one; see LoadFixture and Recorder.
type Fake struct {
	Host     string        `toml:"hostname"`
	UID      int           `toml:"uid"`
	Time     time.Time     `toml:"now"`
	Commands []FakeCommand `toml:"command"`
	Files    []FakeFile    `toml:"file"`
}

type FakeCommand struct {
	Argv   []string `toml:"argv"`
	Stdout string   `toml:"stdout"`
	Exit   int      `toml:"exit"`
}

type FakeFile struct {
	Path    string    `toml:"path"`
	Dir     bool      `toml:"dir,omitempty"`
	Missing bool      `toml:"missing,omitempty"`
	Content string    `toml:"content,omitempty"`
	Mode    uint32    `toml:"mode,omitempty"` // permission bits; default 0644 or 0755
	UID     uint32    `toml:"owner_uid"`
	GID     uint32    `toml:"owner_gid"`
	ModTime time.Time `toml:"mtime"`
	Symlink string    `toml:"symlink,omitempty"`
}

// LoadFixture reads a Fake from a TOML fixture file.
func LoadFixture(file string) (*Fake, error) {
	f := &Fake{}
	if _, err := toml.DecodeFile(file, f); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", file, err)
	}
	return f, nil
}

// ExitError is the error a Fake returns for a non-zero exit.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

func (f *Fake) Run(_ context.Context, _ time.Duration, argv ...string) (string, error) {
	for _, c := range f.Commands {
		if equal(c.Argv, argv) {
			if c.Exit != 0 {
				return c.Stdout, &ExitError{c.Exit}
			}
			return c.Stdout, nil
		}
	}
	return "", fmt.Errorf("%s: %w", strings.Join(argv, " "), fs.ErrNotExist)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (f *Fake) file(p string) *FakeFile {
	p = path.Clean(p)
	for i := range f.Files {
		if path.Clean(f.Files[i].Path) == p {
			if f.Files[i].Missing {
				return nil
			}
			return &f.Files[i]
		}
	}
	// A directory exists implicitly if any file lives under it.
	for i := range f.Files {
		if !f.Files[i].Missing && strings.HasPrefix(path.Clean(f.Files[i].Path), p+"/") {
			return &FakeFile{Path: p, Dir: true}
		}
	}
	return nil
}

func (f *Fake) ReadFile(p string) ([]byte, error) {
	ff, err := f.resolve(p)
	if err != nil {
		return nil, err
	}
	if ff.Dir {
		return nil, &fs.PathError{Op: "read", Path: p, Err: fmt.Errorf("is a directory")}
	}
	return []byte(ff.Content), nil
}

func (f *Fake) resolve(p string) (*FakeFile, error) {
	for range 10 {
		ff := f.file(p)
		if ff == nil {
			return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
		}
		if ff.Symlink == "" {
			return ff, nil
		}
		p = ff.Symlink
	}
	return nil, &fs.PathError{Op: "stat", Path: p, Err: fmt.Errorf("too many links")}
}

func (f *Fake) Stat(p string) (fs.FileInfo, error) {
	ff, err := f.resolve(p)
	if err != nil {
		return nil, err
	}
	return fakeInfo{ff}, nil
}

func (f *Fake) Lstat(p string) (fs.FileInfo, error) {
	ff := f.file(p)
	if ff == nil {
		return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	return fakeInfo{ff}, nil
}

func (f *Fake) Readlink(p string) (string, error) {
	ff := f.file(p)
	if ff == nil || ff.Symlink == "" {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: fmt.Errorf("not a symlink")}
	}
	return ff.Symlink, nil
}

func (f *Fake) Hostname() (string, error) { return f.Host, nil }
func (f *Fake) Getuid() int               { return f.UID }
func (f *Fake) Now() time.Time            { return f.Time }

type fakeInfo struct{ f *FakeFile }

func (i fakeInfo) Name() string { return path.Base(i.f.Path) }
func (i fakeInfo) Size() int64  { return int64(len(i.f.Content)) }
func (i fakeInfo) Mode() fs.FileMode {
	m := fs.FileMode(i.f.Mode) & fs.ModePerm
	if i.f.Mode == 0 {
		m = 0o644
		if i.f.Dir {
			m = 0o755
		}
	}
	switch {
	case i.f.Symlink != "":
		m |= fs.ModeSymlink
	case i.f.Dir:
		m |= fs.ModeDir
	}
	return m
}
func (i fakeInfo) ModTime() time.Time { return i.f.ModTime }
func (i fakeInfo) IsDir() bool        { return i.f.Dir && i.f.Symlink == "" }
func (i fakeInfo) Sys() any           { return &FileOwner{UID: i.f.UID, GID: i.f.GID} }

var _ System = (*Fake)(nil)
var _ System = Real{}
