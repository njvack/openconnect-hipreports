package checks

import (
	"errors"
	"strings"
)

// privilegedFacts are facts only root can read. They are answered in
// process when hipreport runs as root (as it will inside the HIP helper),
// and reported as n/a otherwise. Each takes no input from check files.
var privilegedFacts = map[string]func(*Env) (string, error){
	"pf.enabled": pfEnabled,
}

func pfEnabled(e *Env) (string, error) {
	out, err := e.Run(0, "/sbin/pfctl", "-s", "info")
	switch {
	case strings.Contains(out, "Status: Enabled"):
		return "yes", nil
	case strings.Contains(out, "Status: Disabled"):
		return "no", nil
	}
	if err == nil {
		err = errors.New("pfctl gave no status")
	}
	return NA, err
}
