package sys

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// Recorder wraps a System and remembers every answer it gives, so a run on
// a real Mac can be replayed in tests as a Fake.
type Recorder struct {
	System
	mu   sync.Mutex
	fake Fake
	seen map[string]bool
}

func NewRecorder(s System) *Recorder {
	r := &Recorder{System: s, seen: map[string]bool{}}
	r.fake.Host, _ = s.Hostname()
	r.fake.UID = s.Getuid()
	r.fake.Time = s.Now().Truncate(time.Second)
	return r
}

func (r *Recorder) Now() time.Time { return r.fake.Time }

func (r *Recorder) Run(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
	out, err := r.System.Run(ctx, timeout, argv...)
	code := 0
	if err != nil {
		code = 1
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() > 0 {
			code = ee.ExitCode()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := "run\x00" + join(argv)
	if !r.seen[key] {
		r.seen[key] = true
		r.fake.Commands = append(r.fake.Commands, FakeCommand{Argv: argv, Stdout: out, Exit: code})
	}
	return out, err
}

func join(a []string) string {
	s := ""
	for _, x := range a {
		s += x + "\x00"
	}
	return s
}

func (r *Recorder) note(p string, fi fs.FileInfo, content []byte, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.fake.Files {
		if r.fake.Files[i].Path == p {
			if content != nil {
				r.fake.Files[i].Content = string(content)
			}
			return
		}
	}
	ff := FakeFile{Path: p}
	if err != nil {
		ff.Missing = true
	} else if fi != nil {
		ff.Dir = fi.IsDir()
		ff.Mode = uint32(fi.Mode() & fs.ModePerm)
		ff.ModTime = fi.ModTime()
		ff.UID, ff.GID, _ = Owner(fi)
	}
	if content != nil {
		ff.Content = string(content)
	}
	r.fake.Files = append(r.fake.Files, ff)
}

func (r *Recorder) ReadFile(p string) ([]byte, error) {
	b, err := r.System.ReadFile(p)
	fi, _ := r.System.Stat(p)
	r.note(p, fi, b, err)
	return b, err
}

func (r *Recorder) Stat(p string) (fs.FileInfo, error) {
	fi, err := r.System.Stat(p)
	r.note(p, fi, nil, err)
	return fi, err
}

// Write writes everything recorded so far as a fixture file.
func (r *Recorder) Write(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return toml.NewEncoder(w).Encode(r.fake)
}
