// +build windows

// This tool is used to launch the zeek executable on windows, handling
// any cygwin path conversions as needed.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func cygPaths(topDir string, subPaths []string) []string {
	var ret []string
	for _, l := range scriptLocations {
		p := filepath.Join(topDir, filepath.FromSlash(l))
		vol := filepath.VolumeName(p)
		cyg := "/cygdrive/" + vol[0:1] + filepath.ToSlash(p[len(vol):])
		ret = append(ret, cyg)
	}
	return ret
}

var scriptLocations = []string{
	"share/zeek",
	"share/zeek/policy",
	"share/zeek/site",
}

func launchZeek(logDir, zeekDir, zeekExec string, args []string) error {
	cpaths := cygPaths(zeekDir, scriptLocations)
	strings.Join(cpaths, ":")
	zeekPathEnvVar := "ZEEKPATH=" + strings.Join(cpaths, ":")

	cmd := exec.Command(zeekExec, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = logDir
	cmd.Env = append(os.Environ(), zeekPathEnvVar)

	return cmd.Run()
}

func main() {
	execFile, err := os.Executable()
	if err != nil {
		panic(err)
	}

	execDir, err := filepath.Abs(filepath.Dir(execFile))
	if err != nil {
		panic(err)
	}

	workingDir, err := filepath.Abs(".")
	if err != nil {
		panic(err)
	}

	zeekExec := filepath.Join(execDir, "bin", "zeek.exe")
	if _, err := os.Stat(zeekExec); err != nil {
		panic(err)
	}

	err = launchZeek(workingDir, execDir, zeekExec, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
