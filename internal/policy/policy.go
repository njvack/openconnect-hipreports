// Package policy compares collected HIP facts with what the gateway is
// expected to require. The gateway never says pass or fail, so the
// expectations come from the firewall admins, written down as a policy file.
package policy

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/njvack/openconnect-hipreports/internal/checks"
)

// Policy is a list of requirements; each must be met by some product.
type Policy struct {
	Require []Requirement `toml:"require"`
}

// Requirement matches products by category (and optionally vendor and
// name) and tests one field. With no test, a matching product being
// present is enough. Field "drive:NAME" tests a disk-encryption drive's
// state, for example drive:All.
type Requirement struct {
	Description string `toml:"description"`
	Category    string `toml:"category"`
	Vendor      string `toml:"vendor"`
	Name        string `toml:"name"`
	Field       string `toml:"field"`
	Equals      string `toml:"equals"`
	Matches     string `toml:"matches"`
	MinVersion  string `toml:"min_version"`

	re *regexp.Regexp
}

func Parse(b []byte) (*Policy, error) {
	p := &Policy{}
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(p)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("unknown keys: %v", und)
	}
	for i := range p.Require {
		r := &p.Require[i]
		if r.Category == "" {
			return nil, fmt.Errorf("require[%d]: missing category", i)
		}
		if (r.Equals != "" || r.Matches != "" || r.MinVersion != "") && r.Field == "" {
			return nil, fmt.Errorf("require[%d]: a test needs a field", i)
		}
		if r.Matches != "" {
			if r.re, err = regexp.Compile(r.Matches); err != nil {
				return nil, fmt.Errorf("require[%d]: %w", i, err)
			}
		}
	}
	return p, nil
}

// Result is one requirement's outcome.
type Result struct {
	Req    Requirement
	Pass   bool
	Detail []string // one line per product examined, or why none matched
}

func (r Requirement) String() string {
	if r.Description != "" {
		return r.Description
	}
	s := r.Category
	if r.Vendor != "" {
		s += " " + r.Vendor
	}
	if r.Name != "" {
		s += " " + r.Name
	}
	if r.Field != "" {
		s += " " + r.Field
	}
	switch {
	case r.Equals != "":
		s += " = " + r.Equals
	case r.Matches != "":
		s += " ~ " + r.Matches
	case r.MinVersion != "":
		s += " >= " + r.MinVersion
	default:
		s += " present"
	}
	return s
}

// Check evaluates every requirement against the products.
func (p *Policy) Check(products []checks.Product) []Result {
	var out []Result
	for _, r := range p.Require {
		res := Result{Req: r}
		for _, prod := range products {
			if prod.Cat != r.Category || (r.Vendor != "" && prod.Vendor != r.Vendor) || (r.Name != "" && prod.Name != r.Name) {
				continue
			}
			label := strings.TrimSpace(prod.Vendor + " " + prod.Name)
			if r.Field == "" {
				res.Pass = true
				res.Detail = append(res.Detail, label+": present ("+prod.Source+")")
				continue
			}
			v, ok := fieldValue(prod, r.Field)
			if !ok {
				res.Detail = append(res.Detail, label+": no field "+r.Field)
				continue
			}
			pass := r.test(v.Str)
			if pass {
				res.Pass = true
			}
			line := fmt.Sprintf("%s: %s = %q via %s", label, r.Field, v.Str, v.How)
			if v.Err != "" {
				line += " (" + v.Err + ")"
			}
			res.Detail = append(res.Detail, line)
		}
		if len(res.Detail) == 0 {
			res.Detail = []string{"no matching product reported"}
		}
		out = append(out, res)
	}
	return out
}

func fieldValue(p checks.Product, field string) (checks.Value, bool) {
	if name, ok := strings.CutPrefix(field, "drive:"); ok {
		d := p.Fields["drives"]
		for _, dr := range d.Drives {
			if dr.Name == name {
				return checks.Value{Str: dr.State, How: d.How}, true
			}
		}
		return checks.Value{}, false
	}
	v, ok := p.Fields[field]
	return v, ok
}

func (r Requirement) test(v string) bool {
	switch {
	case r.Equals != "":
		return v == r.Equals
	case r.re != nil:
		return r.re.MatchString(v)
	case r.MinVersion != "":
		return CompareVersions(v, r.MinVersion) >= 0
	}
	return true
}

// CompareVersions compares dotted numeric versions such as 5329 or 27.1.2.
// A non-numeric part compares as text; a missing part counts as 0.
func CompareVersions(a, b string) int {
	if a == "" {
		return -1
	}
	pa, pb := strings.FieldsFunc(a, sep), strings.FieldsFunc(b, sep)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

func sep(r rune) bool { return r == '.' || r == '-' || r == '_' }
