package fastd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"testing"
)

// getShortfile returns (file name, line number) of the caller.
func getShortfile() (string, int) {
	_, f, l, ok := runtime.Caller(1)
	if !ok {
		panic("runtime.Caller should not fail")
	}
	return path.Base(f), l
}

func check(t *testing.T, buf *bytes.Buffer, expected string) {
	line := buf.String()
	buf.Reset()

	if actual := string(line); actual != expected {
		t.Errorf("expected log output to be %q, got %q", expected, actual)
	}
}

func TestLogger(t *testing.T) {
	defer func() {
		SetLogger(nil) // undo
	}()

	// log.LstdFlags is a timestamp, and we don't want to mock time here
	// (which would make this excercise unnecessary complex)
	var buf bytes.Buffer
	l := log.New(&buf, "", log.Lshortfile)
	SetLogger(&stdlogLogger{l.Output})

	{
		logger.Infof("test %d", 1)
		fn, ln := getShortfile()
		check(t, &buf, fmt.Sprintf("%s:%d: INFO - test 1\n", fn, ln-1))
	}
	{
		logger.Errorf("test %d", 2)
		fn, ln := getShortfile()
		check(t, &buf, fmt.Sprintf("%s:%d: ERROR - test 2\n", fn, ln-1))
	}
}

func TestUpdateStdLogOutput(t *testing.T) {
	defer func() { // undo changes
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	}()

	var buf bytes.Buffer
	log.SetFlags(log.Lshortfile)
	log.SetOutput(&buf)

	{
		logger.Errorf("test %d", 3)
		fn, ln := getShortfile()
		check(t, &buf, fmt.Sprintf("%s:%d: ERROR - test 3\n", fn, ln-1))
	}
	{
		logger.Infof("test %d", 4)
		fn, ln := getShortfile()
		check(t, &buf, fmt.Sprintf("%s:%d: INFO - test 4\n", fn, ln-1))
	}
}
