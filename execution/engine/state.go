package engine

import (
	"github.com/certikfoundation/burrow/execution/exec"
)

type State struct {
	*CallFrame
	Blockchain
	exec.EventSink
}
