package fastd

import (
	"fmt"
	"log"
)

// Logger defines log methods used by this package.
type Logger interface {
	Infof(format string, a ...interface{})
	Errorf(format string, a ...interface{})
}

var logger Logger = &stdlogLogger{}

// SetLogger updates the logger fastd uses. If l is nil, we'll use a
// thin wrapper around the standard log package.
func SetLogger(l Logger) {
	if l == nil {
		logger = &stdlogLogger{}
	} else {
		logger = l
	}
}

// log.std is not exposed, so we need to trick a bit to make tests working
type stdlogOutput func(int, string) error

// stdlogLogger is a thin wrapper around the standard log package.
type stdlogLogger struct {
	o stdlogOutput // set in tests
}

func (l *stdlogLogger) Infof(format string, a ...interface{})  { l.out("INFO", format, a...) }
func (l *stdlogLogger) Errorf(format string, a ...interface{}) { l.out("ERROR", format, a...) }

func (l *stdlogLogger) out(level, format string, a ...interface{}) {
	msg := fmt.Sprintf(level+" - "+format, a...)
	if l.o == nil {
		log.Output(3, msg)
		return
	}
	l.o(4, msg)
}
