package telemetry

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Level is a diagnostic severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// ParseLevel maps names to Level; unknown → LevelInfo.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger writes structured JSON lines to an io.Writer (typically stderr).
// All string fields pass through redact.Secrets. Concurrent-safe.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	min    Level
	fields map[string]string // static low-cardinality labels
}

// NewLogger returns a logger writing to w (os.Stderr when nil).
func NewLogger(w io.Writer, min Level) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{w: w, min: min, fields: map[string]string{}}
}

// DefaultLogger is stderr at info.
func DefaultLogger() *Logger {
	return NewLogger(os.Stderr, LevelInfo)
}

// With returns a child logger that includes extra static fields (copied).
// Field values are redacted. Prefer low-cardinality keys only.
func (l *Logger) With(kvs ...string) *Logger {
	if l == nil {
		return NewLogger(os.Stderr, LevelInfo).With(kvs...)
	}
	child := &Logger{
		w:      l.w,
		min:    l.min,
		fields: make(map[string]string, len(l.fields)+len(kvs)/2),
	}
	for k, v := range l.fields {
		child.fields[k] = v
	}
	for i := 0; i+1 < len(kvs); i += 2 {
		k := strings.TrimSpace(kvs[i])
		if k == "" {
			continue
		}
		child.fields[k] = redact.Secrets(kvs[i+1])
	}
	return child
}

// SetMinLevel updates the minimum emitted level.
func (l *Logger) SetMinLevel(min Level) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.min = min
	l.mu.Unlock()
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, kvs ...string) { l.log(LevelDebug, msg, kvs...) }

// Info logs at info level.
func (l *Logger) Info(msg string, kvs ...string) { l.log(LevelInfo, msg, kvs...) }

// Warn logs at warn level.
func (l *Logger) Warn(msg string, kvs ...string) { l.log(LevelWarn, msg, kvs...) }

// Error logs at error level.
func (l *Logger) Error(msg string, kvs ...string) { l.log(LevelError, msg, kvs...) }

func (l *Logger) log(level Level, msg string, kvs ...string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	min := l.min
	w := l.w
	base := l.fields
	l.mu.Unlock()
	if level < min {
		return
	}
	rec := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level.String(),
		"msg":   redact.Secrets(msg),
	}
	for k, v := range base {
		rec[k] = v
	}
	for i := 0; i+1 < len(kvs); i += 2 {
		k := strings.TrimSpace(kvs[i])
		if k == "" || k == "ts" || k == "level" || k == "msg" {
			continue
		}
		rec[k] = redact.Secrets(kvs[i+1])
	}
	line, err := json.Marshal(rec)
	if err != nil {
		// Fallback without risking secret-bearing Go %v of the map.
		_, _ = fmt.Fprintf(w, `{"level":%q,"msg":"log_marshal_error"}`+"\n", level.String())
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = w.Write(append(line, '\n'))
}
