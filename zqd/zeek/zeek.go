package zeek

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ExecScript will be fed into a launched zeek process as the --exec option. The
// default script disables the packet_filter and loaded scripts logs. These logs
// are disabled because the emit either timeless logs or logs with timestamp
// set to execution time rather than time of capture.
var ExecScript = `
event zeek_init() {
	Log::disable_stream(PacketFilter::LOG);
	Log::disable_stream(LoadedScripts::LOG);
}`

// ErrNotFound is returned from LauncherFromPath when the zeek executable is not
// found.
var ErrNotFound = errors.New("zeek not found")

// Process is an interface for interacting running with a running zeek process.
type Process interface {
	// Wait waits for a running process to exit, returning any errors that
	// occur.
	Wait() error
}

// Launcher is a function when fed a context, pcap reader stream, and a zeek
// log output dir, will return a running zeek process. If there is an error
// starting the Process, that error will be returned.
type Launcher func(context.Context, io.Reader, string) (Process, error)

// LauncherFromPath returns a Launcher instance that will launch zeek processes
// using the provided path to a zeek executable. If an empty string is provided,
// this will attempt to load zeek from $PATH. If zeek cannot be found
// ErrNotFound is returned.
func LauncherFromPath(logger *zap.Logger, zeekpath string) (Launcher, error) {
	if zeekpath == "" {
		zeekpath = "zeek"
	}
	zeekpath, err := exec.LookPath(zeekpath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("zeek path error: %w", err)
	}
	return func(ctx context.Context, r io.Reader, dir string) (Process, error) {
		p, err := newProcess(ctx, logger, r, zeekpath, dir)
		if err != nil {
			return nil, err
		}
		return p, p.start()
	}, nil
}

type process struct {
	cmd       *exec.Cmd
	stderrBuf *bytes.Buffer
}

func windowsZeekPathEnv(zeekpath string) (string, error) {
	topDir, err := filepath.Abs(filepath.Join(filepath.Dir(zeekpath), ".."))
	if err != nil {
		return "", err
	}

	var scriptLocations = []string{
		"share/zeek",
		"share/zeek/policy",
		"share/zeek/site",
	}

	var paths []string
	for _, l := range scriptLocations {
		p := filepath.Join(topDir, filepath.FromSlash(l))
		vol := filepath.VolumeName(p)
		cyg := "/cygdrive/" + vol[0:1] + filepath.ToSlash(p[len(vol):])
		paths = append(paths, cyg)
	}

	return "ZEEKPATH=" + strings.Join(paths, ":"), nil
}

func newProcess(ctx context.Context, logger *zap.Logger, pcap io.Reader, zeekpath, outdir string) (*process, error) {
	cmd := exec.CommandContext(ctx, zeekpath, "-C", "-r", "-", "--exec", ExecScript, "local")
	cmd.Dir = outdir
	cmd.Stdin = pcap

	if runtime.GOOS == "windows" {
		zeekPathEnv, err := windowsZeekPathEnv(zeekpath)
		if err != nil {
			return nil, err
		}
		cmd.Env = append(os.Environ(), zeekPathEnv)
		logger.Error("alfred: windows env is", zap.String("env", zeekPathEnv))
	}

	p := &process{cmd: cmd, stderrBuf: bytes.NewBuffer(nil)}
	// Capture stderr for error reporting.
	cmd.Stderr = p.stderrBuf
	return p, nil
}

func (p *process) wrapError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr := p.stderrBuf.String()
		stderr = strings.TrimSpace(stderr)
		return fmt.Errorf("zeek exited with status %d: %s", exitErr.ExitCode(), stderr)
	}
	return err
}

func (p *process) start() error {
	return p.wrapError(p.cmd.Start())
}

func (p *process) Wait() error {
	return p.wrapError(p.cmd.Wait())
}
