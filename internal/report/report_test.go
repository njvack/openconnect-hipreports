package report

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/njvack/openconnect-hipreports/internal/checks"
	"github.com/njvack/openconnect-hipreports/internal/sys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestGoldenMacBasic(t *testing.T) {
	f, err := sys.LoadFixture("../../testdata/mac-basic.toml")
	if err != nil {
		t.Fatal(err)
	}
	set, errs := checks.Load(f, []checks.Source{{}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	facts := Collect(checks.NewEnv(context.Background(), f), set, Request{
		MD5:      "0123456789abcdef0123456789abcdef",
		Cookie:   "authcookie=abc&portal=vpn&user=nate&domain=AD+Domain%21&preferred-ip=&computer=nates-mbp",
		ClientIP: "10.99.0.2",
		ClientOS: "Mac",
	})
	got := facts.XML().String()
	const golden = "../../testdata/mac-basic.golden.xml"
	if *update {
		os.WriteFile(golden, []byte(got), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("report differs from %s (run go test ./internal/report -update to accept):\n%s", golden, got)
	}
}

func TestXMLEscaping(t *testing.T) {
	n := El("r", &Node{Name: "e", Attrs: [][2]string{{"name", `a"b<c>&'d` + "\n"}}, Text: `x<y>&"z'` + "\x01"})
	want := `<?xml version="1.0" encoding="UTF-8"?>
<r>
  <e name="a&quot;b&lt;c&gt;&amp;'d&#10;">x&lt;y&gt;&amp;"z'</e>
</r>
`
	if got := n.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestParseCookie(t *testing.T) {
	m := parseCookie("user=a%40b.edu&domain=My+Domain&computer=x&user=second&bad=%zz")
	if m["user"] != "a@b.edu" || m["domain"] != "My Domain" || m["computer"] != "x" || m["bad"] != "%zz" {
		t.Errorf("got %v", m)
	}
}

func TestCookieFallbacks(t *testing.T) {
	f := &sys.Fake{Host: "box.example.edu"}
	facts := Collect(checks.NewEnv(context.Background(), f), &checks.Set{}, Request{UserName: "localuser"})
	if facts.UserName != "localuser" || facts.Computer != "box" || facts.HostName != "box" {
		t.Errorf("got user %q computer %q host %q", facts.UserName, facts.Computer, facts.HostName)
	}
	if facts.ClientVersion != DefaultClientVersion {
		t.Errorf("client version %q", facts.ClientVersion)
	}
	if !strings.Contains(facts.XML().String(), "<data-loss-prevention") && !strings.Contains(facts.XML().String(), `name="data-loss-prevention"`) {
		t.Error("empty categories must still be listed")
	}
}
