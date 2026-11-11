package checks

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

var mountLine = regexp.MustCompile(`^.+ on (.+) \(([^)]*)\)$`)

// Volumes reports FileVault state for the boot volume, its Data half, and
// browsable internal disks under /Volumes, then an "All" entry: encrypted
// only if every one is, unencrypted if any is not, otherwise unknown.
func (e *Env) Volumes() ([]Drive, error) {
	out, err := e.Run(0, "/sbin/mount")
	if err != nil && out == "" {
		return []Drive{{Name: "All", State: "unknown"}}, err
	}
	var drives []Drive
	all := "encrypted"
	for _, line := range strings.Split(out, "\n") {
		m := mountLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mp, flags := m[1], m[2]
		if !strings.Contains(flags, "local") {
			continue
		}
		var label string
		info := e.diskInfo(mp)
		switch {
		case mp == "/":
			label, _ = PlistString(info["VolumeName"])
		case mp == "/System/Volumes/Data":
			label = "Data"
		case strings.HasPrefix(mp, "/Volumes/"):
			if strings.Contains(flags, "nobrowse") || info["Internal"] != true {
				continue
			}
			label = path.Base(mp)
		default:
			continue
		}
		state := "unknown"
		switch info["FileVault"] {
		case true:
			state = "encrypted"
		case false:
			state = "unencrypted"
		}
		drives = append(drives, Drive{Name: label, State: state})
		switch state {
		case "unencrypted":
			all = "unencrypted"
		case "unknown":
			if all != "unencrypted" {
				all = "unknown"
			}
		}
	}
	if len(drives) == 0 && err == nil {
		err = errors.New("no local volumes found")
	}
	return append(drives, Drive{Name: "All", State: all}), err
}

func (e *Env) diskInfo(mp string) map[string]any {
	out, _ := e.Run(0, "/usr/sbin/diskutil", "info", "-plist", mp)
	m, err := DecodePlist([]byte(out))
	if err != nil {
		return map[string]any{}
	}
	return m
}
