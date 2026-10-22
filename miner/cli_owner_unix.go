//go:build linux || darwin

package miner

import (
	"os"
	"path/filepath"
	"syscall"
)

// ownerProblem says when a folder isn't owned by this user.
func ownerProblem(dir string, info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && int(stat.Uid) != os.Geteuid() {
		return displayStateDir() + " belongs to another user. Fix: sudo chown -R $(id -un) " + cliShellQuote(dir)
	}
	return ""
}

// rootOnlyProblem says when someone other than root could change the file
// or the folders that hold it.
func rootOnlyProblem(path string) string {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			return err.Error()
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && stat.Uid != 0 || info.Mode().Perm()&0022 != 0 && !(info.IsDir() && info.Mode()&os.ModeSticky != 0) {
			return current + " can be changed by a user other than root."
		}
		if parent := filepath.Dir(current); parent == current {
			return ""
		}
	}
}
