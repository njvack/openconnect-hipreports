package policy

import (
	"strings"
	"testing"

	"github.com/njvack/openconnect-hipreports/internal/checks"
)

var products = []checks.Product{
	{Cat: "anti-malware", Vendor: "Apple Inc.", Name: "Xprotect", Fields: map[string]checks.Value{
		"version": {Str: "5329", How: "bundle_version /x"}, "real-time-protection": {Str: "yes"}}},
	{Cat: "firewall", Vendor: "Apple Inc.", Name: "Mac OS X Builtin Firewall", Fields: map[string]checks.Value{
		"is-enabled": {Str: "no", How: "command /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"}}},
	{Cat: "firewall", Vendor: "OpenBSD", Name: "Packet Filter", Fields: map[string]checks.Value{
		"is-enabled": {Str: "n/a", How: "privileged pf.enabled", Err: "needs root"}}},
	{Cat: "disk-encryption", Vendor: "Apple Inc.", Name: "FileVault", Fields: map[string]checks.Value{
		"drives": {How: "volumes", Drives: []checks.Drive{{Name: "Data", State: "encrypted"}, {Name: "All", State: "unencrypted"}}}}},
}

func TestPolicy(t *testing.T) {
	p, err := Parse([]byte(`
[[require]]
category = "anti-malware"
field = "real-time-protection"
equals = "yes"

[[require]]
category = "anti-malware"
name = "Xprotect"
field = "version"
min_version = "5300"

[[require]]
description = "some firewall is on"
category = "firewall"
field = "is-enabled"
equals = "yes"

[[require]]
category = "disk-encryption"
field = "drive:All"
equals = "encrypted"

[[require]]
category = "disk-encryption"
field = "drive:Data"
matches = "^encrypted$"

[[require]]
category = "patch-management"
`))
	if err != nil {
		t.Fatal(err)
	}
	res := p.Check(products)
	want := []bool{true, true, false, false, true, false}
	for i, r := range res {
		if r.Pass != want[i] {
			t.Errorf("%s: pass=%v, want %v (%s)", r.Req, r.Pass, want[i], strings.Join(r.Detail, "; "))
		}
	}
	if d := strings.Join(res[2].Detail, "\n"); !strings.Contains(d, "socketfilterfw") || !strings.Contains(d, "needs root") {
		t.Errorf("firewall detail should say how each value was found: %s", d)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{
		`[[require]]
field = "x"`,
		`[[require]]
category = "firewall"
equals = "yes"`,
		`[[require]]
category = "firewall"
field = "is-enabled"
matches = "("`,
		`[[require]]
category = "firewall"
colour = "red"`,
	} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("no error for %q", s)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"5329", "5300", 1}, {"27.1", "27.1.0", 0}, {"27.0.1", "27.1", -1},
		{"6.2.8-1045", "6.2.8-999", 1}, {"", "1", -1}, {"1.0b", "1.0a", 1},
	} {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
