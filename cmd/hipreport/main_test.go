package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/njvack/openconnect-hipreports/internal/sys"
)

const fixture = "../../testdata/mac-basic.toml"

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, sys.Real{}, &out, &errb)
	return code, out.String(), errb.String()
}

// openconnect's exact wrapper invocation (gpst.c), plus an option it
// might add one day.
func TestWrapperMode(t *testing.T) {
	code, out, stderr := runCLI(t, "--cookie", "user=nate&domain=D&computer=c", "--client-ip", "10.99.0.2",
		"--md5", "feedface", "--client-os", "Mac", "--future-option", "x", "--checks-dir", "/nonexistent", "--fixture", fixture)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "ignoring unknown option --future-option") {
		t.Errorf("stderr: %s", stderr)
	}
	var doc struct {
		XMLName xml.Name `xml:"hip-report"`
		MD5     string   `xml:"md5-sum"`
		User    string   `xml:"user-name"`
		IP      string   `xml:"ip-address"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not XML: %v\n%s", err, out)
	}
	if doc.MD5 != "feedface" || doc.User != "nate" || doc.IP != "10.99.0.2" {
		t.Errorf("got %+v", doc)
	}
}

func TestClientVersionFromEnv(t *testing.T) {
	t.Setenv("APP_VERSION", "6.3.0-99")
	_, out, _ := runCLI(t, "--md5", "x", "--checks-dir", "/nonexistent", "--fixture", fixture)
	if !strings.Contains(out, "<client-version>6.3.0-99</client-version>") {
		t.Error("APP_VERSION not used as client-version")
	}
	_, out, _ = runCLI(t, "--md5", "x", "--client-version=7.0", "--checks-dir", "/nonexistent", "--fixture", fixture)
	if !strings.Contains(out, "<client-version>7.0</client-version>") {
		t.Error("--client-version should win over APP_VERSION")
	}
}

func TestFactsJSON(t *testing.T) {
	code, out, stderr := runCLI(t, "facts", "--json", "--checks-dir", "/nonexistent", "--fixture", fixture)
	if code != 0 {
		t.Fatal(stderr)
	}
	var f struct {
		Trusted  bool
		Products []struct {
			Name   string
			Fields map[string]struct{ Value, How string }
		}
	}
	if err := json.Unmarshal([]byte(out), &f); err != nil {
		t.Fatal(err)
	}
	if !f.Trusted || len(f.Products) == 0 {
		t.Fatalf("got %+v", f)
	}
	for _, p := range f.Products {
		if p.Name == "Gatekeeper" && p.Fields["real-time-protection"].How != "command /usr/sbin/spctl --status" {
			t.Errorf("Gatekeeper how = %q", p.Fields["real-time-protection"].How)
		}
	}
}

func TestDevChecksMarkedUntrusted(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.toml"), []byte(`category = "firewall"
vendor = "Objective Development"
name = "Little Snitch"
[fields]
version = { value = "6" }
is-enabled = { value = "yes" }
`), 0o644)
	_, out, stderr := runCLI(t, "--md5", "x", "--dev-checks", dir, "--checks-dir", "/nonexistent", "--fixture", fixture)
	if !strings.Contains(stderr, "untrusted") || !strings.Contains(out, "Little Snitch") {
		t.Errorf("stderr %q; Little Snitch in report: %v", stderr, strings.Contains(out, "Little Snitch"))
	}
}

func TestCheckPolicy(t *testing.T) {
	pol := filepath.Join(t.TempDir(), "policy.toml")
	os.WriteFile(pol, []byte(`
[[require]]
category = "disk-encryption"
field = "drive:All"
equals = "encrypted"

[[require]]
category = "firewall"
name = "Mac OS X Builtin Firewall"
field = "is-enabled"
equals = "yes"
`), 0o644)
	code, out, _ := runCLI(t, "check", "--policy", pol, "--checks-dir", "/nonexistent", "--fixture", fixture)
	if code != 1 || !strings.Contains(out, "FAIL  disk-encryption drive:All = encrypted") || !strings.Contains(out, "PASS  firewall") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestLint(t *testing.T) {
	code, out, stderr := runCLI(t, "lint", "--checks-dir", "/nonexistent")
	if code != 0 {
		t.Errorf("built-in library: exit %d\n%s%s", code, out, stderr)
	}
	bad := filepath.Join(t.TempDir(), "bad.toml")
	os.WriteFile(bad, []byte(`category = "anti-malware"
vendor = "v"
name = "n"
[fields]
version = { value = "1" }
`), 0o644)
	code, _, stderr = runCLI(t, "lint", "--no-builtin", "--checks-dir", "/nonexistent", bad)
	if code != 1 || !strings.Contains(stderr, "real-time-protection") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// A recording replayed as a fixture gives the same report.
func TestRecordReplay(t *testing.T) {
	f, err := sys.LoadFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--md5", "x", "--checks-dir", "/nonexistent"}
	var live, rec, errb bytes.Buffer
	run(args, f, &live, &errb)
	run(append([]string{"record"}, args...), f, &rec, &errb)
	p := filepath.Join(t.TempDir(), "rec.toml")
	os.WriteFile(p, rec.Bytes(), 0o644)
	var replay bytes.Buffer
	run(append(args, "--fixture", p), sys.Real{}, &replay, &errb)
	if live.String() != replay.String() {
		t.Errorf("replay differs:\n%s\n---\n%s", live.String(), replay.String())
	}
}
