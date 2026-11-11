package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"

	"github.com/njvack/openconnect-hipreports/internal/sys"
)

// NA is what a field reports when its state cannot be determined.
const NA = "n/a"

// Drive is one volume's encryption state.
type Drive struct {
	Name  string `json:"name"`
	State string `json:"state"` // encrypted, unencrypted or unknown
}

// Value is one field's result, with how it was found.
type Value struct {
	Str    string  `json:"value"`
	Drives []Drive `json:"drives,omitempty"`
	How    string  `json:"how"`             // the probe and what it read
	Err    string  `json:"error,omitempty"` // why a probe fell back, if it did
}

// Env carries the system and per-run caches into probes.
type Env struct {
	Sys sys.System
	Ctx context.Context
	// Debug, if set, receives every command and its output.
	Debug func(format string, a ...any)

	mu    sync.Mutex
	cache map[string]runResult
}

type runResult struct {
	out string
	err error
}

func NewEnv(ctx context.Context, s sys.System) *Env {
	return &Env{Sys: s, Ctx: ctx, cache: map[string]runResult{}}
}

// Run runs a command once per Env and caches the result. Commands always
// go through here so their stderr never reaches the report.
func (e *Env) Run(timeout time.Duration, argv ...string) (string, error) {
	key := strings.Join(argv, "\x00")
	e.mu.Lock()
	if r, ok := e.cache[key]; ok {
		e.mu.Unlock()
		return r.out, r.err
	}
	e.mu.Unlock()
	out, err := e.Sys.Run(e.Ctx, timeout, argv...)
	if e.Debug != nil {
		e.Debug("$ %s (err=%v)\n%s", strings.Join(argv, " "), err, out)
	}
	e.mu.Lock()
	e.cache[key] = runResult{out, err}
	e.mu.Unlock()
	return out, err
}

// Exists reports whether a path exists.
func (e *Env) Exists(p string) bool {
	_, err := e.Sys.Stat(p)
	return err == nil
}

// ReadPlist decodes a plist file (XML or binary) into a dictionary.
func (e *Env) ReadPlist(p string) (map[string]any, error) {
	b, err := e.Sys.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return DecodePlist(b)
}

// DecodePlist decodes plist data (XML or binary) whose root is a dictionary.
func DecodePlist(b []byte) (map[string]any, error) {
	var m map[string]any
	if _, err := plist.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// PlistString renders a plist value the way `plutil -extract KEY raw` does.
func PlistString(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case time.Time:
		return v.UTC().Format(time.RFC3339), true
	}
	return "", false
}

// lookup finds a dotted key path in a plist dictionary.
func lookup(m map[string]any, key string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(key, ".") {
		d, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = d[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// BundleVersion is CFBundleShortVersionString of an app or bundle, or "".
func (e *Env) BundleVersion(bundle string) (string, error) {
	m, err := e.ReadPlist(bundle + "/Contents/Info.plist")
	if err != nil {
		return "", err
	}
	v, ok := m["CFBundleShortVersionString"].(string)
	if !ok {
		return "", errors.New("no CFBundleShortVersionString")
	}
	return v, nil
}

// OSVersion is the macOS product version, such as 27.1.
func (e *Env) OSVersion() string {
	out, _ := e.Run(0, "/usr/bin/sw_vers", "-productVersion")
	return strings.TrimSpace(out)
}

func (e *Env) processes() map[string]bool {
	out, _ := e.Run(0, "/bin/ps", "-axo", "comm=")
	running := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			running[l] = true
		}
	}
	return running
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// Eval runs a probe.
func (e *Env) Eval(p Probe) Value {
	if p.Value != nil {
		return Value{Str: *p.Value, How: "value"}
	}
	how := p.Probe
	fail := func(v string, err error) Value {
		val := Value{Str: v, How: how}
		if err != nil {
			val.Err = err.Error()
		}
		return val
	}
	switch p.Probe {
	case "bundle_version":
		how += " " + p.Path
		v, err := e.BundleVersion(p.Path)
		return fail(v, err)
	case "plist":
		how += " " + p.Path + " " + p.Key
		m, err := e.ReadPlist(p.Path)
		if err != nil {
			return fail("", err)
		}
		raw, ok := lookup(m, p.Key)
		if !ok {
			return fail("", fmt.Errorf("no key %s", p.Key))
		}
		s, ok := PlistString(raw)
		if !ok {
			return fail("", fmt.Errorf("key %s is not a scalar", p.Key))
		}
		return fail(s, nil)
	case "mtime":
		how += " " + p.Path
		fi, err := e.Sys.Stat(p.Path)
		if err != nil {
			return fail("", err)
		}
		return fail(strconv.FormatInt(fi.ModTime().Unix(), 10), nil)
	case "exists":
		how += " " + p.Path
		return fail(yesNo(e.Exists(p.Path)), nil)
	case "process":
		how += " " + p.Path
		return fail(yesNo(e.processes()[p.Path]), nil)
	case "launchd":
		target := p.Label
		if rest, ok := strings.CutPrefix(target, "gui/"); ok {
			target = fmt.Sprintf("gui/%d/%s", e.Sys.Getuid(), rest)
		}
		how += " " + target
		_, err := e.Run(0, "/bin/launchctl", "print", target)
		return fail(yesNo(err == nil), nil)
	case "command":
		how += " " + strings.Join(p.Argv, " ")
		out, err := e.Run(time.Duration(p.Timeout)*time.Second, p.Argv...)
		for _, m := range p.Map {
			if re, rerr := regexp.Compile(m.Match); rerr == nil && re.MatchString(out) {
				return Value{Str: m.Value, How: how}
			}
		}
		def := NA
		if p.Default != nil {
			def = *p.Default
		}
		if err == nil {
			err = errors.New("output matched nothing")
		}
		return fail(def, err)
	case "os_version":
		return fail(e.OSVersion(), nil)
	case "volumes":
		drives, err := e.Volumes()
		v := fail("", err)
		v.Drives = drives
		return v
	case "privileged":
		how += " " + p.Fact
		f, ok := privilegedFacts[p.Fact]
		if !ok {
			return fail(NA, fmt.Errorf("unknown fact %s", p.Fact))
		}
		if e.Sys.Getuid() != 0 {
			return fail(NA, errors.New("needs root (the HIP helper)"))
		}
		v, err := f(e)
		return fail(v, err)
	case "all":
		// yes if every part is yes; no if any is no; otherwise n/a.
		state := "yes"
		var parts []string
		for _, sub := range p.All {
			v := e.Eval(sub)
			parts = append(parts, v.How+"="+v.Str)
			switch {
			case v.Str == "no":
				state = "no"
			case v.Str != "yes" && state == "yes":
				state = NA
			}
		}
		how += " [" + strings.Join(parts, "; ") + "]"
		return fail(state, nil)
	}
	return fail(NA, fmt.Errorf("unknown probe %q", p.Probe))
}

// Product is one check's evaluated result.
type Product struct {
	Check  *Check           `json:"-"`
	ID     string           `json:"id"`
	Source string           `json:"source"`
	Trust  bool             `json:"trusted"`
	Cat    string           `json:"category"`
	Vendor string           `json:"vendor,omitempty"`
	Name   string           `json:"name,omitempty"`
	Fields map[string]Value `json:"fields,omitempty"`

	// custom-plist results
	Plist *PlistResult `json:"plist,omitempty"`
}

type PlistResult struct {
	Path   string     `json:"path"`
	Exists bool       `json:"exists"`
	Keys   []KeyValue `json:"keys"`
}

type KeyValue struct {
	Key    string `json:"key"`
	Exists bool   `json:"exists"`
	Value  string `json:"value"`
}

// Evaluate runs a check. ok is false if its when condition says the
// product is not installed.
func (e *Env) Evaluate(c *Check) (p Product, ok bool) {
	p = Product{Check: c, ID: c.ID, Source: c.Source, Trust: c.Trusted, Cat: c.Category, Vendor: c.Vendor, Name: c.Name}
	for _, path := range c.When.Exists {
		if !e.Exists(path) {
			return p, false
		}
	}
	if c.Category == CustomPlist {
		p.Plist = e.customPlist(c)
		return p, true
	}
	def, _ := Category(c.Category)
	p.Fields = map[string]Value{}
	for _, f := range def.Fields {
		probe, have := c.Fields[f.Name]
		if !have {
			p.Fields[f.Name] = Value{Str: f.Default, How: "default"}
			continue
		}
		p.Fields[f.Name] = e.Eval(probe)
	}
	return p, true
}

func (e *Env) customPlist(c *Check) *PlistResult {
	r := &PlistResult{Path: c.Path}
	m, err := e.ReadPlist(c.Path)
	_, statErr := e.Sys.Stat(c.Path)
	r.Exists = statErr == nil
	for _, k := range c.Keys {
		kv := KeyValue{Key: k}
		if err == nil {
			if raw, ok := lookup(m, k); ok {
				kv.Value, kv.Exists = PlistString(raw)
			}
		}
		r.Keys = append(r.Keys, kv)
	}
	return r
}
