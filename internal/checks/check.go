// Package checks loads HIP check files and evaluates them.
//
// A check file is TOML describing one product in one HIP category: its
// vendor and name, an optional condition for reporting it at all, and one
// probe per field the category needs. Probes are a fixed vocabulary
// implemented here; check files cannot run code except through the
// command probe, which takes an absolute path and runs it with a fixed
// environment and a timeout.
package checks

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Check is one parsed check file.
type Check struct {
	Category string           `toml:"category"`
	Vendor   string           `toml:"vendor"`
	Name     string           `toml:"name"`
	Disabled bool             `toml:"disabled"`
	When     When             `toml:"when"`
	Fields   map[string]Probe `toml:"fields"`

	// custom-plist only
	Path string   `toml:"path"`
	Keys []string `toml:"keys"`

	ID      string `toml:"-"` // path relative to its source; a later source's file with the same ID replaces it
	Source  string `toml:"-"` // where it was loaded from, for messages
	Trusted bool   `toml:"-"`
}

// When gates whether a product is reported at all.
type When struct {
	Exists StringList `toml:"exists"` // every path must exist
}

// StringList is a TOML string or array of strings.
type StringList []string

func (l *StringList) UnmarshalTOML(v any) error {
	switch v := v.(type) {
	case string:
		*l = StringList{v}
	case []any:
		out := make(StringList, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return fmt.Errorf("expected a string, got %T", x)
			}
			out = append(out, s)
		}
		*l = out
	default:
		return fmt.Errorf("expected a string or array of strings, got %T", v)
	}
	return nil
}

// Probe says how to find one field's value.
type Probe struct {
	Probe   string     `toml:"probe"`
	Value   *string    `toml:"value"` // a constant; no probe
	Path    string     `toml:"path"`
	Key     string     `toml:"key"`
	Label   string     `toml:"label"`
	Fact    string     `toml:"fact"`
	Argv    []string   `toml:"argv"`
	Map     []MapEntry `toml:"map"`
	Default *string    `toml:"default"`
	Timeout int        `toml:"timeout"` // seconds
	All     []Probe    `toml:"all"`
}

// MapEntry maps command output matching a regexp to a value.
type MapEntry struct {
	Match string `toml:"match"`
	Value string `toml:"value"`
}

// Probe names and the parameters each requires.
var probeParams = map[string][]string{
	"bundle_version": {"path"},
	"plist":          {"path", "key"},
	"mtime":          {"path"},
	"exists":         {"path"},
	"process":        {"path"},
	"launchd":        {"label"},
	"command":        {"argv", "map"},
	"volumes":        {},
	"os_version":     {},
	"privileged":     {"fact"},
	"all":            {"all"},
}

// Validate reports every problem with a check, in the order found.
func (c *Check) Validate() []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Category == CustomPlist {
		if !path.IsAbs(c.Path) {
			bad("custom-plist needs an absolute path")
		}
		if len(c.Fields) > 0 {
			bad("custom-plist takes path and keys, not fields")
		}
		for _, k := range c.Keys {
			if k == "" {
				bad("empty key")
			}
		}
		return errs
	}

	def, ok := Category(c.Category)
	if !ok {
		names := []string{}
		for _, d := range Categories {
			names = append(names, d.Name)
		}
		bad("unknown category %q (want one of %s, %s)", c.Category, strings.Join(names, ", "), CustomPlist)
		return errs
	}
	if c.Vendor == "" {
		bad("missing vendor")
	}
	if c.Name == "" {
		bad("missing name")
	}
	if c.Path != "" || len(c.Keys) > 0 {
		bad("path and keys are only for custom-plist")
	}
	for _, p := range c.When.Exists {
		if !path.IsAbs(p) {
			bad("when.exists: %q is not an absolute path", p)
		}
	}
	for _, f := range def.Fields {
		if _, have := c.Fields[f.Name]; f.Required && !have {
			bad("%s needs field %q", c.Category, f.Name)
		}
	}
	for name, p := range c.Fields {
		f, ok := def.Field(name)
		if !ok {
			bad("%s has no field %q", c.Category, name)
			continue
		}
		for _, e := range p.validate() {
			bad("field %s: %v", name, e)
		}
		if f.Drives != (p.Probe == "volumes") {
			if f.Drives {
				bad("field %s: needs the volumes probe", name)
			} else {
				bad("field %s: the volumes probe only fits a drives field", name)
			}
		}
	}
	return errs
}

func (p *Probe) validate() []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if p.Value != nil {
		if p.Probe != "" {
			bad("give either value or probe, not both")
		}
		return errs
	}
	params, ok := probeParams[p.Probe]
	if !ok {
		if p.Probe == "" {
			bad("needs a probe or a value")
		} else {
			bad("unknown probe %q", p.Probe)
		}
		return errs
	}
	has := map[string]bool{
		"path": p.Path != "", "key": p.Key != "", "label": p.Label != "",
		"fact": p.Fact != "", "argv": len(p.Argv) > 0, "map": len(p.Map) > 0,
		"all": len(p.All) > 0,
	}
	want := map[string]bool{}
	for _, k := range params {
		want[k] = true
		if !has[k] {
			bad("probe %s needs %s", p.Probe, k)
		}
	}
	for k, v := range has {
		if v && !want[k] {
			bad("probe %s does not take %s", p.Probe, k)
		}
	}
	if p.Default != nil && p.Probe != "command" {
		bad("only the command probe takes a default")
	}
	if p.Timeout != 0 && p.Probe != "command" {
		bad("only the command probe takes a timeout")
	}
	if p.Path != "" && !path.IsAbs(p.Path) {
		bad("path %q is not absolute", p.Path)
	}
	if len(p.Argv) > 0 && !path.IsAbs(p.Argv[0]) {
		bad("command %q is not an absolute path", p.Argv[0])
	}
	for _, m := range p.Map {
		if _, err := regexp.Compile(m.Match); err != nil {
			bad("map: %v", err)
		}
	}
	if p.Label != "" && !strings.Contains(p.Label, "/") {
		bad("launchd label %q needs a domain, such as system/%s or gui/%s", p.Label, p.Label, p.Label)
	}
	if p.Fact != "" {
		if _, ok := privilegedFacts[p.Fact]; !ok {
			bad("unknown privileged fact %q", p.Fact)
		}
	}
	for i := range p.All {
		if p.All[i].Probe == "all" || p.All[i].Probe == "volumes" {
			bad("all: %s cannot be nested", p.All[i].Probe)
		}
		for _, e := range p.All[i].validate() {
			bad("all[%d]: %v", i, e)
		}
	}
	return errs
}
