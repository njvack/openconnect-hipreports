package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/njvack/openconnect-hipreports/internal/sys"
)

func TestLibraryIsValid(t *testing.T) {
	set, errs := Load(&sys.Fake{}, []Source{{}})
	for _, e := range errs {
		t.Error(e)
	}
	if len(set.Checks) < 10 {
		t.Fatalf("only %d built-in checks", len(set.Checks))
	}
	// Report order: categories in definition order, then file name.
	var got []string
	for _, c := range set.Checks {
		got = append(got, c.Category+"/"+c.Name)
	}
	want := []string{
		"anti-malware/Xprotect", "anti-malware/Gatekeeper", "anti-malware/Cisco Secure Endpoint",
		"disk-backup/Time Machine", "disk-backup/Google Drive",
		"disk-encryption/FileVault",
		"firewall/Mac OS X Builtin Firewall", "firewall/Packet Filter",
		"patch-management/Software Update", "patch-management/Workspace ONE Intelligent Hub",
		"patch-management/Qualys Cloud Security Agent", "patch-management/Microsoft AutoUpdate",
		"custom-plist/",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name, toml, want string
	}{
		{"unknown category", `category = "antivirus"
vendor = "v"
name = "n"`, `unknown category "antivirus"`},
		{"missing required field", `category = "anti-malware"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }`, `needs field "real-time-protection"`},
		{"unknown field", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
is-enabled = { value = "yes" }
colour = { value = "red" }`, `no field "colour"`},
		{"relative command", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
is-enabled = { probe = "command", argv = ["pfctl"], map = [{ match = "x", value = "yes" }] }`, `not an absolute path`},
		{"bad regexp", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
is-enabled = { probe = "command", argv = ["/bin/x"], map = [{ match = "(", value = "yes" }] }`, `missing closing )`},
		{"missing param", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { probe = "bundle_version" }
is-enabled = { value = "yes" }`, `needs path`},
		{"extra param", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { probe = "os_version", path = "/x" }
is-enabled = { value = "yes" }`, `does not take path`},
		{"volumes on a string field", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { probe = "volumes" }
is-enabled = { value = "yes" }`, `only fits a drives field`},
		{"launchd without domain", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
is-enabled = { probe = "launchd", label = "com.example" }`, `needs a domain`},
		{"unknown fact", `category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
is-enabled = { probe = "privileged", fact = "sip.enabled" }`, `unknown privileged fact`},
		{"relative when", `category = "firewall"
vendor = "v"
name = "n"
when.exists = "Applications/X.app"
[fields]
version = { value = "1" }
is-enabled = { value = "yes" }`, `not an absolute path`},
		{"custom plist without path", `category = "custom-plist"
keys = ["Label"]`, `absolute path`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse([]byte(tc.toml))
			if err != nil {
				t.Fatal(err)
			}
			errs := c.Validate()
			var all []string
			for _, e := range errs {
				all = append(all, e.Error())
			}
			if !strings.Contains(strings.Join(all, "\n"), tc.want) {
				t.Errorf("errors %q, want one containing %q", all, tc.want)
			}
		})
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte(`category = "firewall"
vendor = "v"
name = "n"
[fields]
version = { value = "1", probe_typo = "x" }
`))
	if err == nil || !strings.Contains(err.Error(), "probe_typo") {
		t.Errorf("err = %v, want unknown key probe_typo", err)
	}
}

func TestLoadOverridesAndDisables(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Replace Gatekeeper, remove Time Machine, add a new product, and
	// include a broken file that must be skipped, not fatal.
	write("anti-malware/20-apple-gatekeeper.toml", `category = "anti-malware"
vendor = "Apple Inc."
name = "Gatekeeper (local)"
[fields]
version = { value = "1" }
real-time-protection = { value = "yes" }`)
	write("disk-backup/10-apple-time-machine.toml", `disabled = true`)
	write("firewall/90-little-snitch.toml", `category = "firewall"
vendor = "Objective Development"
name = "Little Snitch"
[fields]
version = { value = "6" }
is-enabled = { value = "yes" }`)
	write("firewall/99-broken.toml", `category = "firewall"`)

	set, errs := Load(&sys.Fake{}, []Source{{}, {Dir: dir, Dev: true}})
	if len(errs) == 0 {
		t.Error("broken file loaded without errors")
	}
	for _, e := range errs {
		if !strings.Contains(e.Error(), "99-broken.toml") {
			t.Errorf("unexpected error %v", e)
		}
	}
	if set.Trusted {
		t.Error("a dev source should make the set untrusted")
	}
	names := map[string]*Check{}
	for _, c := range set.Checks {
		names[c.Name] = c
	}
	if _, ok := names["Gatekeeper"]; ok {
		t.Error("built-in Gatekeeper was not replaced")
	}
	if c := names["Gatekeeper (local)"]; c == nil || c.Trusted {
		t.Errorf("local Gatekeeper = %+v, want loaded and untrusted", c)
	}
	if _, ok := names["Time Machine"]; ok {
		t.Error("Time Machine was not disabled")
	}
	if _, ok := names["Little Snitch"]; !ok {
		t.Error("Little Snitch was not added")
	}
}

func TestLoadSkipsMissingDir(t *testing.T) {
	_, errs := Load(&sys.Fake{}, []Source{{Dir: "/nonexistent/hipreport/checks.d"}})
	if len(errs) != 0 {
		t.Errorf("errs = %v", errs)
	}
}

func rootFile(path string, mode uint32) sys.FakeFile {
	return sys.FakeFile{Path: path, Mode: mode}
}

func TestCheckTrusted(t *testing.T) {
	base := []sys.FakeFile{
		{Path: "/", Dir: true, Mode: 0o755},
		{Path: "/Library", Dir: true, Mode: 0o755},
		{Path: "/Library/Application Support", Dir: true, Mode: 0o755, GID: 80},
		{Path: "/Library/Application Support/hipreport", Dir: true, Mode: 0o755},
		{Path: "/Library/Application Support/hipreport/checks.d", Dir: true, Mode: 0o755},
	}
	const dir = "/Library/Application Support/hipreport/checks.d"
	cases := []struct {
		name  string
		extra []sys.FakeFile
		path  string
		want  string // "" means trusted
	}{
		{"root owned", []sys.FakeFile{rootFile(dir+"/a.toml", 0o644)}, dir + "/a.toml", ""},
		{"user owned file", []sys.FakeFile{{Path: dir + "/a.toml", UID: 501}}, dir + "/a.toml", "owned by uid 501"},
		{"world writable file", []sys.FakeFile{rootFile(dir+"/a.toml", 0o666)}, dir + "/a.toml", "writable by anyone"},
		{"group writable, admin", []sys.FakeFile{{Path: dir + "/a.toml", Mode: 0o664, GID: 80}}, dir + "/a.toml", "writable by group 80"},
		{"group writable, wheel", []sys.FakeFile{{Path: dir + "/a.toml", Mode: 0o664, GID: 0}}, dir + "/a.toml", ""},
		{"symlink to user file", []sys.FakeFile{
			{Path: dir + "/a.toml", Symlink: "/Users/nate/a.toml", Mode: 0o777},
			{Path: "/Users", Dir: true, Mode: 0o755},
			{Path: "/Users/nate", Dir: true, Mode: 0o755, UID: 501},
			{Path: "/Users/nate/a.toml", UID: 501},
		}, dir + "/a.toml", "/Users/nate"},
		{"symlink to root file", []sys.FakeFile{
			{Path: dir + "/a.toml", Symlink: "/etc/hipreport/a.toml", Mode: 0o777},
			{Path: "/etc", Dir: true, Mode: 0o755},
			{Path: "/etc/hipreport", Dir: true, Mode: 0o755},
			{Path: "/etc/hipreport/a.toml"},
		}, dir + "/a.toml", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &sys.Fake{Files: append(append([]sys.FakeFile{}, base...), tc.extra...)}
			err := CheckTrusted(f, tc.path)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("err = %v, want trusted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// A user-owned parent directory taints everything below it.
	f := &sys.Fake{Files: append(append([]sys.FakeFile{}, base...),
		sys.FakeFile{Path: "/Library/Application Support/hipreport", Dir: true, Mode: 0o755, UID: 501},
		rootFile(dir+"/a.toml", 0o644))}
	f.Files = append(f.Files[:3], f.Files[4:]...) // drop the root-owned hipreport dir
	if err := CheckTrusted(f, dir+"/a.toml"); err == nil {
		t.Error("user-owned parent directory was trusted")
	}
}

func TestTrustedDirOnRealFS(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; a temp dir is root-owned")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.toml"), []byte(`disabled = true`), 0o644)
	_, errs := Load(sys.Real{}, []Source{{Dir: dir}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "untrusted") {
		t.Errorf("errs = %v, want the directory refused as untrusted", errs)
	}
}

func env(f *sys.Fake) *Env { return NewEnv(context.Background(), f) }

func str(s string) *string { return &s }

func TestProbes(t *testing.T) {
	mtime := time.Date(2026, 11, 4, 9, 15, 0, 0, time.UTC)
	f := &sys.Fake{
		UID: 501,
		Commands: []sys.FakeCommand{
			{Argv: []string{"/bin/ps", "-axo", "comm="}, Stdout: "/sbin/launchd\n/usr/bin/a\n"},
			{Argv: []string{"/bin/launchctl", "print", "gui/501/com.example.agent"}, Stdout: "ok"},
			{Argv: []string{"/bin/launchctl", "print", "system/com.example.missing"}, Exit: 113},
			{Argv: []string{"/usr/bin/tool"}, Stdout: "Firewall is disabled. (blocking off)\n"},
			{Argv: []string{"/usr/bin/odd"}, Stdout: "something else\n"},
		},
		Files: []sys.FakeFile{
			{Path: "/A.app/Contents/Info.plist", ModTime: mtime, Content: `<?xml version="1.0"?><plist version="1.0"><dict>
<key>CFBundleShortVersionString</key><string>2.5</string>
<key>Nested</key><dict><key>On</key><true/><key>N</key><integer>7</integer></dict>
</dict></plist>`},
		},
	}
	e := env(f)
	cases := []struct {
		name string
		p    Probe
		want string
	}{
		{"value", Probe{Value: str("yes")}, "yes"},
		{"bundle_version", Probe{Probe: "bundle_version", Path: "/A.app"}, "2.5"},
		{"bundle_version missing", Probe{Probe: "bundle_version", Path: "/B.app"}, ""},
		{"plist bool", Probe{Probe: "plist", Path: "/A.app/Contents/Info.plist", Key: "Nested.On"}, "true"},
		{"plist int", Probe{Probe: "plist", Path: "/A.app/Contents/Info.plist", Key: "Nested.N"}, "7"},
		{"plist missing key", Probe{Probe: "plist", Path: "/A.app/Contents/Info.plist", Key: "Nope"}, ""},
		{"mtime", Probe{Probe: "mtime", Path: "/A.app/Contents/Info.plist"}, "1793783700"},
		{"exists", Probe{Probe: "exists", Path: "/A.app"}, "yes"},
		{"not exists", Probe{Probe: "exists", Path: "/B.app"}, "no"},
		{"process running", Probe{Probe: "process", Path: "/usr/bin/a"}, "yes"},
		{"process not running", Probe{Probe: "process", Path: "/usr/bin/b"}, "no"},
		{"launchd gui", Probe{Probe: "launchd", Label: "gui/com.example.agent"}, "yes"},
		{"launchd missing", Probe{Probe: "launchd", Label: "system/com.example.missing"}, "no"},
		{"command first match wins", Probe{Probe: "command", Argv: []string{"/usr/bin/tool"}, Map: []MapEntry{
			{Match: "disabled", Value: "no"}, {Match: "enabled|blocking", Value: "yes"}}}, "no"},
		{"command no match", Probe{Probe: "command", Argv: []string{"/usr/bin/odd"}, Map: []MapEntry{{Match: "on", Value: "yes"}}}, "n/a"},
		{"command default", Probe{Probe: "command", Argv: []string{"/usr/bin/odd"}, Map: []MapEntry{{Match: "^on", Value: "yes"}}, Default: str("no")}, "no"},
		{"command missing", Probe{Probe: "command", Argv: []string{"/usr/bin/none"}, Map: []MapEntry{{Match: ".", Value: "yes"}}}, "n/a"},
		{"privileged as user", Probe{Probe: "privileged", Fact: "pf.enabled"}, "n/a"},
		{"all yes", Probe{Probe: "all", All: []Probe{{Probe: "process", Path: "/usr/bin/a"}, {Probe: "exists", Path: "/A.app"}}}, "yes"},
		{"all one no", Probe{Probe: "all", All: []Probe{{Probe: "process", Path: "/usr/bin/a"}, {Probe: "process", Path: "/usr/bin/b"}}}, "no"},
		{"all unknown", Probe{Probe: "all", All: []Probe{{Probe: "process", Path: "/usr/bin/a"}, {Value: str("n/a")}}}, "n/a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.Eval(tc.p); got.Str != tc.want {
				t.Errorf("got %q (%s, %s), want %q", got.Str, got.How, got.Err, tc.want)
			}
		})
	}
}

func TestPrivilegedAsRoot(t *testing.T) {
	f := &sys.Fake{UID: 0, Commands: []sys.FakeCommand{
		{Argv: []string{"/sbin/pfctl", "-s", "info"}, Stdout: "Status: Enabled for 0 days 01:02:03\n"},
	}}
	if got := env(f).Eval(Probe{Probe: "privileged", Fact: "pf.enabled"}); got.Str != "yes" {
		t.Errorf("pf.enabled as root = %q (%s)", got.Str, got.Err)
	}
}

func TestWhenExists(t *testing.T) {
	f := &sys.Fake{Files: []sys.FakeFile{{Path: "/Applications/X.app/Contents/Info.plist"}}}
	c := &Check{Category: "firewall", Vendor: "v", Name: "n", When: When{Exists: StringList{"/Applications/X.app", "/Applications/Y.app"}}}
	if _, ok := env(f).Evaluate(c); ok {
		t.Error("reported though /Applications/Y.app is missing")
	}
	c.When.Exists = StringList{"/Applications/X.app"}
	if p, ok := env(f).Evaluate(c); !ok || p.Fields["version"].Str != "" {
		t.Errorf("got %+v, %v", p, ok)
	}
}
