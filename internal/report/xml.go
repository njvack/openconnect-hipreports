package report

import (
	"strings"
)

// Node is a minimal XML element: attributes in order, and either text or
// children. String serializes it the way `xmllint --format` does, so the
// output matches what hipreport.zsh produced.
type Node struct {
	Name     string
	Attrs    [][2]string
	Text     string
	Children []*Node
}

func El(name string, children ...*Node) *Node { return &Node{Name: name, Children: children} }

func Text(name, text string) *Node { return &Node{Name: name, Text: text} }

// Entry is GP's <entry name="..."> wrapper.
func Entry(name string, children ...*Node) *Node {
	return &Node{Name: "entry", Attrs: [][2]string{{"name", name}}, Children: children}
}

func (n *Node) Add(children ...*Node) *Node {
	n.Children = append(n.Children, children...)
	return n
}

func (n *Node) String() string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	n.write(&b, 0)
	return b.String()
}

func (n *Node) write(b *strings.Builder, depth int) {
	b.WriteString(strings.Repeat("  ", depth))
	b.WriteString("<" + n.Name)
	for _, a := range n.Attrs {
		b.WriteString(" " + a[0] + `="` + escapeAttr(a[1]) + `"`)
	}
	switch {
	case len(n.Children) > 0:
		b.WriteString(">\n")
		for _, c := range n.Children {
			c.write(b, depth+1)
		}
		b.WriteString(strings.Repeat("  ", depth) + "</" + n.Name + ">\n")
	case n.Text != "":
		b.WriteString(">" + escapeText(n.Text) + "</" + n.Name + ">\n")
	default:
		b.WriteString("/>\n")
	}
}

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#13;")

var attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;",
	"\n", "&#10;", "\r", "&#13;", "\t", "&#9;")

func escapeText(s string) string { return textEscaper.Replace(stripInvalid(s)) }
func escapeAttr(s string) string { return attrEscaper.Replace(stripInvalid(s)) }

// stripInvalid drops characters XML 1.0 cannot carry at all.
func stripInvalid(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return r
		case r < 0x20, r == 0xFFFE, r == 0xFFFF:
			return -1
		}
		return r
	}, s)
}
