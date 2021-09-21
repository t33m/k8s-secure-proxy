package zap

import "go.uber.org/zap"

type Logger struct {
	inner *zap.SugaredLogger
}

func New(logger *zap.SugaredLogger) *Logger {
	return &Logger{inner: logger}
} 

func (l *Logger) Debug(msg string, v ...interface{}){
	l.inner.Debugw(msg, v...)
}

func (l *Logger) Info(msg string, v ...interface{}){
	l.inner.Infow(msg, v...)
}

func (l *Logger) Warn(msg string, v ...interface{}){
	l.inner.Warnw(msg, v...)
}

func (l *Logger) Error(msg string, v ...interface{}){
	l.inner.Errorw(msg, v...)
}
