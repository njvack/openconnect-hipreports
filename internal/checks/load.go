package checks

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/njvack/openconnect-hipreports/internal/sys"
)

// Library is the default check library, compiled into the binary so the
// binary's code signature covers it.
//
//go:embed library
var Library embed.FS

// Source is a place checks come from.
type Source struct {
	Dir string // a directory on disk; "" means the built-in library
	Dev bool   // load without trust checks, and mark results untrusted
}

// Set is the checks that will run, in report order.
type Set struct {
	Checks  []*Check
	Trusted bool // false if any check came from a dev source
}

// Load reads every source in order. A file in a later source replaces one
// with the same relative path in an earlier source, so a local file can
// fix or (with disabled = true) remove a built-in one. Missing directories
// are skipped; files that fail trust checks or validation are skipped and
// returned as errors.
func Load(s sys.System, sources []Source) (*Set, []error) {
	byID := map[string]*Check{}
	var errs []error
	set := &Set{Trusted: true}
	for _, src := range sources {
		checks, e := loadSource(s, src)
		errs = append(errs, e...)
		for _, c := range checks {
			byID[c.ID] = c
			if src.Dev {
				set.Trusted = false
			}
		}
	}
	for _, c := range byID {
		if !c.Disabled {
			set.Checks = append(set.Checks, c)
		}
	}
	sort.Slice(set.Checks, func(i, j int) bool {
		a, b := set.Checks[i], set.Checks[j]
		if ra, rb := categoryRank(a.Category), categoryRank(b.Category); ra != rb {
			return ra < rb
		}
		if ba, bb := path.Base(a.ID), path.Base(b.ID); ba != bb {
			return ba < bb
		}
		return a.ID < b.ID
	})
	return set, errs
}

func loadSource(s sys.System, src Source) ([]*Check, []error) {
	var fsys fs.FS
	var root string
	if src.Dir == "" {
		sub, _ := fs.Sub(Library, "library")
		fsys, root = sub, "built-in:"
	} else {
		abs, err := filepath.Abs(src.Dir)
		if err != nil {
			return nil, []error{err}
		}
		if _, err := os.Stat(abs); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, []error{err}
		}
		if !src.Dev {
			if err := CheckTrusted(s, abs); err != nil {
				return nil, []error{err}
			}
		}
		fsys, root = os.DirFS(abs), abs+"/"
	}

	var checks []*Check
	var errs []error
	walkErr := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s%s: %w", root, p, err))
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".toml") {
			return nil
		}
		where := root + p
		if src.Dir != "" && !src.Dev {
			if err := CheckTrusted(s, where); err != nil {
				errs = append(errs, err)
				return nil
			}
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		c, err := Parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
			return nil
		}
		c.ID, c.Source, c.Trusted = p, where, !src.Dev
		if c.Disabled {
			checks = append(checks, c)
			return nil
		}
		if ve := c.Validate(); len(ve) > 0 {
			for _, e := range ve {
				errs = append(errs, fmt.Errorf("%s: %w", where, e))
			}
			return nil
		}
		checks = append(checks, c)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return checks, errs
}

// Parse decodes one check file, rejecting unknown keys.
func Parse(b []byte) (*Check, error) {
	c := &Check{}
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(c)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	return c, nil
}

// CheckTrusted refuses a path unless it and every directory above it are
// owned by root and writable by nobody else, the way sudo treats sudoers.
// A group-writable directory is allowed only if its group is wheel (0).
// Symlinks are followed, and the target is held to the same rule.
func CheckTrusted(s sys.System, p string) error {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s: not an absolute path", p)
	}
	seen := 0
	var check func(string) error
	check = func(p string) error {
		if seen++; seen > 64 {
			return fmt.Errorf("%s: too many symlinks", p)
		}
		for cur := p; ; cur = filepath.Dir(cur) {
			fi, err := s.Lstat(cur)
			if err != nil {
				return err
			}
			uid, gid, ok := sys.Owner(fi)
			if !ok {
				return fmt.Errorf("%s: cannot tell who owns it", cur)
			}
			mode := fi.Mode()
			switch {
			case uid != 0:
				return fmt.Errorf("%s: untrusted, owned by uid %d, not root", cur, uid)
			case mode.Perm()&0o002 != 0 && mode&fs.ModeSymlink == 0:
				return fmt.Errorf("%s: untrusted, writable by anyone", cur)
			case mode.Perm()&0o020 != 0 && gid != 0 && mode&fs.ModeSymlink == 0:
				return fmt.Errorf("%s: untrusted, writable by group %d", cur, gid)
			}
			if mode&fs.ModeSymlink != 0 {
				target, err := s.Readlink(cur)
				if err != nil {
					return err
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(cur), target)
				}
				if err := check(target); err != nil {
					return err
				}
			}
			if cur == "/" || cur == filepath.Dir(cur) {
				return nil
			}
		}
	}
	return check(p)
}
