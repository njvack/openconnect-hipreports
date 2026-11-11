// Command hipreport writes a GlobalProtect HIP report for openconnect.
//
// As a --csd-wrapper, openconnect runs it with --cookie, --client-ip,
// --client-ipv6, --md5 and --client-os, and submits whatever it prints:
//
//	openconnect --protocol=gp --csd-wrapper=/path/to/hipreport vpn.example.edu
//
// The report is built from check files: TOML descriptions of one product
// each. The built-in library is compiled in; local additions go in
// /Library/Application Support/hipreport/checks.d, which must be owned by
// root and writable by nobody else.
//
// Other commands:
//
//	hipreport facts [--json]        what each check found, and how
//	hipreport check --policy FILE   pass or fail per expected condition
//	hipreport lint [PATH...]        validate check files
//	hipreport record [-o FILE]      record this machine's answers as a test fixture
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"
	"strings"

	"github.com/njvack/openconnect-hipreports/internal/checks"
	"github.com/njvack/openconnect-hipreports/internal/policy"
	"github.com/njvack/openconnect-hipreports/internal/report"
	"github.com/njvack/openconnect-hipreports/internal/sys"
)

// DefaultChecksDir holds local check files.
const DefaultChecksDir = "/Library/Application Support/hipreport/checks.d"

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], sys.Real{}, os.Stdout, os.Stderr))
}

type options struct {
	report.Request
	checksDirs []string
	devDirs    []string
	noBuiltin  bool
	debug      bool
	json       bool
	policy     string
	output     string
	fixture    string // replay a recorded fixture instead of the real system
	rest       []string
}

// flags that take a value, and where it goes.
func (o *options) valueFlags() map[string]func(string) {
	return map[string]func(string){
		"--cookie":            func(v string) { o.Cookie = v },
		"--client-ip":         func(v string) { o.ClientIP = v },
		"--client-ipv6":       func(v string) { o.ClientIPv6 = v },
		"--md5":               func(v string) { o.MD5 = v },
		"--client-os":         func(v string) { o.ClientOS = v },
		"--client-version":    func(v string) { o.ClientVersion = v },
		"--host-id-interface": func(v string) { o.HostIDDevice = v },
		"--checks-dir":        func(v string) { o.checksDirs = append(o.checksDirs, v) },
		"--dev-checks":        func(v string) { o.devDirs = append(o.devDirs, v) },
		"--policy":            func(v string) { o.policy = v },
		"-o":                  func(v string) { o.output = v },
		"--fixture":           func(v string) { o.fixture = v },
	}
}

func (o *options) boolFlags() map[string]*bool {
	return map[string]*bool{"--debug": &o.debug, "--json": &o.json, "--no-builtin": &o.noBuiltin}
}

// parse is lenient: openconnect may grow new options, and a HIP report
// should still go out, so unknown options are warned about and skipped.
func parse(args []string, stderr io.Writer) (*options, error) {
	o := &options{}
	vf, bf := o.valueFlags(), o.boolFlags()
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(a, "=")
		if set, ok := vf[name]; ok {
			if !hasVal {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("%s needs a value", name)
				}
				i++
				val = args[i]
			}
			set(val)
			continue
		}
		if b, ok := bf[a]; ok {
			*b = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(stderr, "hipreport: ignoring unknown option %s\n", a)
			if !hasVal && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}
		o.rest = append(o.rest, a)
	}
	if os.Getenv("HIPREPORT_DEBUG") == "1" {
		o.debug = true
	}
	if o.ClientVersion == "" {
		// openconnect passes its --version-string here.
		o.ClientVersion = os.Getenv("APP_VERSION")
	}
	if o.checksDirs == nil {
		o.checksDirs = []string{DefaultChecksDir}
	}
	return o, nil
}

func run(args []string, real sys.System, stdout, stderr io.Writer) int {
	cmd := "report"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	o, err := parse(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "hipreport:", err)
		return 2
	}
	s := real
	if o.fixture != "" {
		if s, err = sys.LoadFixture(o.fixture); err != nil {
			fmt.Fprintln(stderr, "hipreport:", err)
			return 2
		}
	}
	switch cmd {
	case "report":
		return cmdReport(o, s, stdout, stderr)
	case "facts":
		return cmdFacts(o, s, stdout, stderr)
	case "check":
		return cmdCheck(o, s, stdout, stderr)
	case "lint":
		return cmdLint(o, s, stdout, stderr)
	case "record":
		return cmdRecord(o, s, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "hipreport", version)
		return 0
	case "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "hipreport: unknown command %q\n%s", cmd, usage)
	return 2
}

const usage = `usage:
  hipreport [--md5 X --cookie X ...]   write a HIP report (openconnect --csd-wrapper)
  hipreport facts [--json]             show what each check found
  hipreport check --policy FILE        compare facts with an expected policy
  hipreport lint [PATH...]             validate check files
  hipreport record [-o FILE]           record this machine as a test fixture
  hipreport version

options:
  --checks-dir DIR         trusted check directory (repeatable; default ` + DefaultChecksDir + `)
  --dev-checks DIR         load checks without trust checks; output is marked untrusted
  --no-builtin             skip the built-in check library
  --host-id-interface DEV  interface whose MAC is the host-id (default en0)
  --debug                  log commands and their output to stderr (or HIPREPORT_DEBUG=1)
`

func sources(o *options) []checks.Source {
	var src []checks.Source
	if !o.noBuiltin {
		src = append(src, checks.Source{})
	}
	for _, d := range o.checksDirs {
		src = append(src, checks.Source{Dir: d})
	}
	for _, d := range o.devDirs {
		src = append(src, checks.Source{Dir: d, Dev: true})
	}
	return src
}

func collect(o *options, s sys.System, stderr io.Writer) (*report.Facts, *checks.Set) {
	set, errs := checks.Load(s, sources(o))
	for _, e := range errs {
		fmt.Fprintln(stderr, "hipreport: skipping:", e)
	}
	if !set.Trusted {
		fmt.Fprintln(stderr, "hipreport: warning: using --dev-checks; this report is untrusted")
	}
	env := checks.NewEnv(context.Background(), s)
	if o.debug {
		env.Debug = func(format string, a ...any) { fmt.Fprintf(stderr, "hipreport: "+format+"\n", a...) }
	}
	req := o.Request
	if req.UserName == "" {
		req.UserName = currentUser()
	}
	return report.Collect(env, set, req), set
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func cmdReport(o *options, s sys.System, stdout, stderr io.Writer) int {
	if o.MD5 == "" {
		fmt.Fprintln(stderr, "hipreport: warning: no --md5 given; the gateway will reject this")
	}
	f, _ := collect(o, s, stderr)
	if _, err := io.WriteString(stdout, f.XML().String()); err != nil {
		fmt.Fprintln(stderr, "hipreport:", err)
		return 1
	}
	return 0
}

func cmdFacts(o *options, s sys.System, stdout, stderr io.Writer) int {
	f, _ := collect(o, s, stderr)
	if o.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(f); err != nil {
			fmt.Fprintln(stderr, "hipreport:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "host %s (%s), macOS %s, host-id %s, trusted=%v\n", f.HostName, f.Computer, f.OSVersion, f.HostID, f.Trusted)
	for _, p := range f.Products {
		if p.Plist != nil {
			fmt.Fprintf(stdout, "\ncustom plist %s exists=%v  [%s]\n", p.Plist.Path, p.Plist.Exists, p.Source)
			for _, k := range p.Plist.Keys {
				fmt.Fprintf(stdout, "  %-24s exists=%v %q\n", k.Key, k.Exists, k.Value)
			}
			continue
		}
		fmt.Fprintf(stdout, "\n%s: %s %s  [%s]\n", p.Cat, p.Vendor, p.Name, p.Source)
		names := make([]string, 0, len(p.Fields))
		for n := range p.Fields {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := p.Fields[n]
			val := fmt.Sprintf("%q", v.Str)
			if v.Drives != nil {
				parts := []string{}
				for _, d := range v.Drives {
					parts = append(parts, d.Name+"="+d.State)
				}
				val = strings.Join(parts, " ")
			}
			line := fmt.Sprintf("  %-22s %s  via %s", n, val, v.How)
			if v.Err != "" {
				line += "  (" + v.Err + ")"
			}
			fmt.Fprintln(stdout, line)
		}
	}
	return 0
}

func cmdCheck(o *options, s sys.System, stdout, stderr io.Writer) int {
	if o.policy == "" {
		fmt.Fprintln(stderr, "hipreport: check needs --policy FILE")
		return 2
	}
	b, err := os.ReadFile(o.policy)
	if err != nil {
		fmt.Fprintln(stderr, "hipreport:", err)
		return 2
	}
	pol, err := policy.Parse(b)
	if err != nil {
		fmt.Fprintf(stderr, "hipreport: %s: %v\n", o.policy, err)
		return 2
	}
	f, _ := collect(o, s, stderr)
	failed := 0
	for _, r := range pol.Check(f.Products) {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(stdout, "%s  %s\n", mark, r.Req)
		for _, d := range r.Detail {
			fmt.Fprintf(stdout, "      %s\n", d)
		}
	}
	if failed > 0 {
		fmt.Fprintf(stdout, "%d of %d requirements failed\n", failed, len(pol.Require))
		return 1
	}
	return 0
}

// lint validates the built-in library and configured directories (with
// trust checks), plus any paths given, which are checked as dev sources.
func cmdLint(o *options, s sys.System, stdout, stderr io.Writer) int {
	o.devDirs = append(o.devDirs, o.rest...)
	src := sources(o)
	var errs []error
	n := 0
	for _, one := range src {
		if fi, err := os.Stat(one.Dir); one.Dir != "" && err == nil && !fi.IsDir() {
			c, e := lintFile(one.Dir)
			errs = append(errs, e...)
			n += c
			continue
		}
		set, e := checks.Load(s, []checks.Source{one})
		errs = append(errs, e...)
		n += len(set.Checks)
	}
	for _, e := range errs {
		fmt.Fprintln(stderr, e)
	}
	fmt.Fprintf(stdout, "%d check files ok, %d problems\n", n, len(errs))
	if len(errs) > 0 {
		return 1
	}
	return 0
}

func lintFile(p string) (int, []error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, []error{err}
	}
	c, err := checks.Parse(b)
	if err != nil {
		return 0, []error{fmt.Errorf("%s: %w", p, err)}
	}
	var errs []error
	for _, e := range c.Validate() {
		errs = append(errs, fmt.Errorf("%s: %w", p, e))
	}
	if len(errs) > 0 {
		return 0, errs
	}
	return 1, nil
}

// record runs every check against the real system and writes the answers
// as a fixture. The fixture holds this machine's host name, MACs and
// addresses; scrub them before committing one.
func cmdRecord(o *options, s sys.System, stdout, stderr io.Writer) int {
	rec := sys.NewRecorder(s)
	collect(o, rec, io.Discard)
	w := stdout
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			fmt.Fprintln(stderr, "hipreport:", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if err := rec.Write(w); err != nil {
		fmt.Fprintln(stderr, "hipreport:", err)
		return 1
	}
	return 0
}
