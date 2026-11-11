// Package sys is the boundary between hipreport and the machine it runs on.
// Every probe reads the system through a System, so tests can substitute
// recorded output for real commands and files.
package sys

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"time"
)

// SafePath is the only PATH commands ever see.
const SafePath = "/usr/bin:/bin:/usr/sbin:/sbin"

// DefaultTimeout bounds every command unless a check sets its own.
const DefaultTimeout = 10 * time.Second

// System is what probes may ask of the machine.
type System interface {
	// Run runs argv[0] (an absolute path) with a fixed environment and
	// returns its stdout. err is non-nil if it could not start, timed
	// out, or exited non-zero; stdout is still returned in that case.
	Run(ctx context.Context, timeout time.Duration, argv ...string) (stdout string, err error)
	ReadFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	Lstat(path string) (fs.FileInfo, error)
	Readlink(path string) (string, error)
	Hostname() (string, error)
	Getuid() int
	Now() time.Time
}

// Real is the System for the machine we are running on.
type Real struct{}

func (Real) Run(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("empty command")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + SafePath, "LC_ALL=C", "HOME=/var/empty"}
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return out.String(), err
}

func (Real) ReadFile(path string) ([]byte, error)   { return os.ReadFile(path) }
func (Real) Stat(path string) (fs.FileInfo, error)  { return os.Stat(path) }
func (Real) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (Real) Readlink(path string) (string, error)   { return os.Readlink(path) }
func (Real) Hostname() (string, error)              { return os.Hostname() }
func (Real) Getuid() int                            { return os.Getuid() }
func (Real) Now() time.Time                         { return time.Now() }
