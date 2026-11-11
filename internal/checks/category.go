package checks

// FieldDef is one field a category's products report.
type FieldDef struct {
	Name     string
	Required bool
	Default  string // used when an optional field is absent
	Drives   bool   // takes a list of drives (the volumes probe), not a string
	Epoch    bool   // a Unix time, reported as datemon/dateday/dateyear
}

// CategoryDef describes one HIP report category. The report lists
// categories in this order.
type CategoryDef struct {
	Name   string
	Fields []FieldDef
}

// CustomPlist is the pseudo-category for GP's custom plist checks, which
// sit outside <categories> in the report.
const CustomPlist = "custom-plist"

var Categories = []CategoryDef{
	{Name: "anti-malware", Fields: []FieldDef{
		{Name: "version", Required: true},
		{Name: "defver"},
		{Name: "engver"},
		{Name: "updated", Epoch: true},
		{Name: "real-time-protection", Required: true},
		{Name: "last-full-scan-time", Default: "n/a"},
	}},
	{Name: "disk-backup", Fields: []FieldDef{
		{Name: "version", Required: true},
		{Name: "last-backup-time", Default: "n/a"},
	}},
	{Name: "disk-encryption", Fields: []FieldDef{
		{Name: "version", Required: true},
		{Name: "drives", Required: true, Drives: true},
	}},
	{Name: "firewall", Fields: []FieldDef{
		{Name: "version", Required: true},
		{Name: "is-enabled", Required: true},
	}},
	{Name: "patch-management", Fields: []FieldDef{
		{Name: "version", Required: true},
		{Name: "is-enabled", Required: true},
	}},
	{Name: "data-loss-prevention", Fields: []FieldDef{
		{Name: "version", Required: true},
	}},
}

// Category returns the definition of a named category.
func Category(name string) (CategoryDef, bool) {
	for _, c := range Categories {
		if c.Name == name {
			return c, true
		}
	}
	return CategoryDef{}, false
}

func categoryRank(name string) int {
	for i, c := range Categories {
		if c.Name == name {
			return i
		}
	}
	return len(Categories) // custom-plist last
}

func (c CategoryDef) Field(name string) (FieldDef, bool) {
	for _, f := range c.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return FieldDef{}, false
}
