// Copyright Monax Industries Limited
// SPDX-License-Identifier: Apache-2.0

package loggers

import (
	"github.com/certikfoundation/burrow/logging/structure"
	"github.com/go-kit/kit/log"
)

// Treat duplicate key-values as consecutive entries in a vector-valued lookup
type vectorValuedLogger struct {
	logger log.Logger
}

var _ log.Logger = &vectorValuedLogger{}

func (vvl *vectorValuedLogger) Log(keyvals ...interface{}) error {
	return vvl.logger.Log(structure.Vectorise(keyvals)...)
}

func VectorValuedLogger(logger log.Logger) *vectorValuedLogger {
	return &vectorValuedLogger{logger: logger}
}
