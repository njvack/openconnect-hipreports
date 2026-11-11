// Package report assembles the GlobalProtect HIP report.
package report

import (
	"strconv"
	"strings"
	"time"

	"github.com/njvack/openconnect-hipreports/internal/checks"
)

// DefaultClientVersion is the GlobalProtect version we claim to be. Keep it
// in step with openconnect's --version-string if you set one.
const DefaultClientVersion = "6.2.8-1045"

// Request is what openconnect tells the wrapper, plus our own options.
type Request struct {
	MD5           string
	Cookie        string
	ClientIP      string
	ClientIPv6    string
	ClientOS      string
	ClientVersion string
	UserName      string // used when the cookie has none
	HostIDDevice  string // interface whose MAC is the host-id; default en0
}

// Facts is everything collected for one report.
type Facts struct {
	UserName      string           `json:"user_name"`
	Domain        string           `json:"domain"`
	Computer      string           `json:"computer"`
	HostName      string           `json:"host_name"`
	HostID        string           `json:"host_id"`
	ClientIP      string           `json:"client_ip,omitempty"`
	ClientIPv6    string           `json:"client_ipv6,omitempty"`
	ClientVersion string           `json:"client_version"`
	OSVersion     string           `json:"os_version"`
	MD5           string           `json:"md5,omitempty"`
	Generated     time.Time        `json:"generated"`
	Trusted       bool             `json:"trusted"`
	Interfaces    []Interface      `json:"interfaces"`
	Products      []checks.Product `json:"products"`
}

// Collect runs every check and gathers host facts.
func Collect(e *checks.Env, set *checks.Set, req Request) *Facts {
	cookie := parseCookie(req.Cookie)
	host, _ := e.Sys.Hostname()
	short, _, _ := strings.Cut(host, ".")
	f := &Facts{
		UserName:      cookie["user"],
		Domain:        cookie["domain"],
		Computer:      cookie["computer"],
		HostName:      short,
		ClientIP:      req.ClientIP,
		ClientIPv6:    req.ClientIPv6,
		ClientVersion: req.ClientVersion,
		MD5:           req.MD5,
		Generated:     e.Sys.Now(),
		Trusted:       set.Trusted,
	}
	// These must match what the client sent at login, so the cookie wins.
	if f.UserName == "" {
		f.UserName = req.UserName
	}
	if f.Computer == "" {
		f.Computer = short
	}
	if f.ClientVersion == "" {
		f.ClientVersion = DefaultClientVersion
	}
	dev := req.HostIDDevice
	if dev == "" {
		dev = "en0"
	}
	f.OSVersion = e.OSVersion()
	f.HostID = HardwareMAC(e, dev)
	f.Interfaces = Interfaces(e)
	for _, c := range set.Checks {
		if p, ok := e.Evaluate(c); ok {
			f.Products = append(f.Products, p)
		}
	}
	return f
}

// parseCookie decodes the URL-encoded login cookie (user=...&domain=...).
// Only the first value of each field counts, as in hipreport.zsh.
func parseCookie(s string) map[string]string {
	m := map[string]string{}
	for _, pair := range strings.Split(s, "&") {
		k, v, _ := strings.Cut(pair, "=")
		if _, seen := m[k]; seen || k == "" {
			continue
		}
		m[k] = urlDecode(v)
	}
	return m
}

func urlDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// XML builds the report.
func (f *Facts) XML() *Node {
	root := El("hip-report",
		Text("md5-sum", f.MD5),
		Text("user-name", f.UserName),
		Text("domain", f.Domain),
		Text("host-name", f.Computer),
		Text("host-id", f.HostID),
		Text("ip-address", f.ClientIP),
		Text("ipv6-address", f.ClientIPv6),
		Text("generate-time", f.Generated.Format("01/02/2006 15:04:05")),
		Text("hip-report-version", "4"),
	)
	cats := El("categories", f.hostInfo())
	for _, def := range checks.Categories {
		cats.Add(f.category(def))
	}
	root.Add(cats, f.customChecks())
	return root
}

func (f *Facts) hostInfo() *Node {
	nics := El("network-interface")
	for _, i := range f.Interfaces {
		e := Entry(i.Device, Text("description", i.Device), Text("mac-address", i.MAC))
		if len(i.IPv4) > 0 {
			e.Add(addrList("ip-address", i.IPv4))
		}
		if len(i.IPv6) > 0 {
			e.Add(addrList("ipv6-address", i.IPv6))
		}
		nics.Add(e)
	}
	return Entry("host-info",
		Text("client-version", f.ClientVersion),
		Text("os", "Apple Mac OS X "+f.OSVersion),
		Text("os-vendor", "Apple"),
		Text("domain", f.Domain),
		Text("host-name", f.HostName),
		Text("host-id", f.HostID),
		nics,
	)
}

func addrList(tag string, addrs []string) *Node {
	n := El(tag)
	for _, a := range addrs {
		n.Add(&Node{Name: "entry", Attrs: [][2]string{{"name", a}}})
	}
	return n
}

func (f *Facts) category(def checks.CategoryDef) *Node {
	list := El("list")
	for _, p := range f.Products {
		if p.Cat == def.Name {
			list.Add(El("entry", El("ProductInfo", product(def, p, f.Generated.Location())...)))
		}
	}
	e := Entry(def.Name, list)
	if def.Name == "patch-management" {
		// Pending updates aren't checked, so this always claims none.
		e.Add(El("missing-patches"))
	}
	return e
}

// product builds the children of <ProductInfo>: a <Prod> element whose
// attributes carry vendor, name and version (and, for anti-malware, the
// definition version and date), then one element per remaining field.
func product(def checks.CategoryDef, p checks.Product, loc *time.Location) []*Node {
	val := func(name string) string { return p.Fields[name].Str }
	prod := &Node{Name: "Prod", Attrs: [][2]string{
		{"vendor", p.Vendor}, {"name", p.Name}, {"version", val("version")},
	}}
	out := []*Node{prod}
	switch def.Name {
	case "anti-malware":
		mon, day, year := dateParts(val("updated"), loc)
		prod.Attrs = append(prod.Attrs,
			[2]string{"defver", val("defver")}, [2]string{"engver", val("engver")},
			[2]string{"datemon", mon}, [2]string{"dateday", day}, [2]string{"dateyear", year},
			[2]string{"prodType", "3"}, [2]string{"osType", "4"})
		out = append(out, Text("real-time-protection", val("real-time-protection")),
			Text("last-full-scan-time", val("last-full-scan-time")))
	case "disk-encryption":
		drives := El("drives")
		for _, d := range p.Fields["drives"].Drives {
			drives.Add(El("entry", Text("drive-name", d.Name), Text("enc-state", d.State)))
		}
		out = append(out, drives)
	default:
		for _, fd := range def.Fields {
			if fd.Name != "version" {
				out = append(out, Text(fd.Name, val(fd.Name)))
			}
		}
	}
	return out
}

// dateParts gives the unpadded local month, day and year of a Unix time.
func dateParts(epoch string, loc *time.Location) (string, string, string) {
	n, err := strconv.ParseInt(epoch, 10, 64)
	if epoch == "" || err != nil {
		return "", "", ""
	}
	t := time.Unix(n, 0).In(loc)
	return strconv.Itoa(int(t.Month())), strconv.Itoa(t.Day()), strconv.Itoa(t.Year())
}

func (f *Facts) customChecks() *Node {
	pl := El("plist")
	for _, p := range f.Products {
		if p.Plist == nil {
			continue
		}
		prefs := El("preference-value")
		for _, k := range p.Plist.Keys {
			prefs.Add(Entry(k.Key, Text("exist", yesNo(k.Exists)), Text("value", k.Value)))
		}
		pl.Add(Entry(p.Plist.Path, Text("exist", yesNo(p.Plist.Exists)), Text("value", ""), prefs))
	}
	return El("custom-checks", pl)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
