package fastd

import "log"

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

// stdlogLogger is a thin wrapper around the standard log package.
type stdlogLogger struct{}

func (l *stdlogLogger) Infof(format string, a ...interface{})  { log.Printf("INFO - "+format, a...) }
func (l *stdlogLogger) Errorf(format string, a ...interface{}) { log.Printf("ERROR - "+format, a...) }
