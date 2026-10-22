//go:build !linux && !darwin

package miner

import "os"

func ownerProblem(string, os.FileInfo) string {
	return ""
}

func rootOnlyProblem(string) string {
	return ""
}
