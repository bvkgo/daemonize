// Copyright (c) 2023 BVK Chaitanya

package daemonize

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// HealthChecker is a function that checks for the initialization of the
// background process. Health checker function is run in the parent process
// after spawning the background child process.
//
// Health check function should return retry=false and err=nil after successful
// initialization or retry=false and err=non-nil for initialization
// failure. Health check is performed repeatedly as long as retry=true and the
// Daemonize context is not expired.
//
// As an example, child process could be implemented expose a REST endpoint
// with it's process id after it initializes successfully and health checker
// function could probe for matching process id at the well-known REST endpoint
// to confirm child process's successful initialization in the background.
type HealthChecker = func(ctx context.Context, child *os.Process) (retry bool, err error)

// Daemonize runs the current program in the background as a daemon. This
// function should be called during the program startup, before performing any
// other significant work, like opening databases, opening network connections,
// etc.
//
// Daemonize execs the current program with all the same command-line
// arguments, but with limited environment and an additional `envkey` variable
// that indicates background mode to the new child process.
//
// Users are required to pass an unique, application-specific, non-empty
// environment variable name to indicate to the background process that it is a
// daemon and to put itself in the background.
//
// Standard input and outputs of the background process are replaced with
// `/dev/null`. Standard library's log output is redirected to the `io.Discard`
// backend. Current working directory of the background process is changed to
// the root directory. Background process's environment is also restricted to
// just PATH, USER, HOME and the user supplied "envkey" variables.
//
// Parent process will use the check function to wait for the background
// process to initialize successfully or die unsuccessfully. Health checker
// function is expected to verify that a new instance of child process is
// initialized successfully.
//
// When successfull, Daemonize returns nil to the background process and exits
// in the parent process (i.e., never returns). When unsuccessful, Daemonize
// returns non-nil error to the parent process and kills the background process
// (i.e., never returns).
func Daemonize(ctx context.Context, envkey string, check HealthChecker) error {
	if len(envkey) == 0 {
		return os.ErrInvalid
	}
	if v := os.Getenv(envkey); len(v) == 0 {
		if err := daemonizeParent(ctx, envkey, check); err != nil {
			return err
		}
		os.Exit(0)
	}
	if err := daemonizeChild(envkey); err != nil {
		os.Exit(1)
	}
	return nil
}

func daemonizeParent(ctx context.Context, envkey string, check HealthChecker) (status error) {
	binary, err := exec.LookPath(os.Args[0])
	if err != nil {
		return fmt.Errorf("failed to lookup binary: %w", err)
	}
	binaryPath, err := filepath.Abs(binary)
	if err != nil {
		return fmt.Errorf("could not determine absolute path for binary: %w", err)
	}

	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer file.Close()

	// Receive signal when child-process dies.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGCHLD, os.Interrupt)
	defer stop()

	attr := &os.ProcAttr{
		Dir: "/",
		Env: []string{
			fmt.Sprintf("PATH=%s", os.Getenv("PATH")),
			fmt.Sprintf("USER=%s", os.Getenv("USER")),
			fmt.Sprintf("HOME=%s", os.Getenv("HOME")),
			fmt.Sprintf("%s=%d", envkey, os.Getpid()),
		},
		Files: []*os.File{file, file, file},
	}
	proc, err := os.StartProcess(binaryPath, os.Args, attr)
	if err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}
	defer func() {
		if status != nil {
			if _, err := proc.Wait(); err != nil {
				log.Printf("could not wait for child process cleanup (ignored): %v", err)
			}
		}
	}()

	if check != nil {
		if _, err := retryCheck(ctx, proc, check); err != nil {
			log.Printf("error: background process is not initialized properly: %v", err)
			return fmt.Errorf("background process isn't initialized: %w", err)
		}
		log.Printf("background process is initialized successfully")
	}
	return nil
}

func daemonizeChild(envkey string) error {
	if ppid := os.Getppid(); fmt.Sprintf("%d", ppid) != os.Getenv(envkey) {
		return fmt.Errorf("parent pid in the environment key is unexpected")
	}

	if _, err := unix.Setsid(); err != nil {
		return fmt.Errorf("could not set session id: %w", err)
	}

	log.SetOutput(io.Discard)
	return nil
}

func retryCheck(ctx context.Context, proc *os.Process, check HealthChecker) (retry bool, err error) {
	for retry, err = check(ctx, proc); retry && ctx.Err() == nil; retry, err = check(ctx, proc) {
		if err != nil {
			log.Printf("warning: background process is not yet initialized (retrying): %v", err)
			sctx, scancel := context.WithTimeout(ctx, time.Second)
			<-sctx.Done()
			scancel()
		}
	}
	return
}
