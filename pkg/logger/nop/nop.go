package nop

type Logger struct {}

func (*Logger) Debug(string, ...interface{}) {}
func (*Logger) Info(string, ...interface{}) {}
func (*Logger) Warn(string, ...interface{}) {}
func (*Logger) Error(string, ...interface{}) {}
