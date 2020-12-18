// Copyright Monax Industries Limited
// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certikfoundation/burrow/logging"
	"github.com/certikfoundation/burrow/rpc"
	"github.com/certikfoundation/burrow/rpc/lib/server"
)

func StartServer(service *rpc.Service, pattern string, listener net.Listener, blockSampleSize int,
	logger *logging.Logger) (*http.Server, error) {

	// instantiate metrics and variables we do not expect to change during runtime
	exporter, err := NewExporter(service, blockSampleSize, logger)
	if err != nil {
		return nil, err
	}

	// Register Metrics from each of the endpoints
	// This invokes the Collect method through the prometheus client libraries.
	prometheus.MustRegister(exporter)

	mux := http.NewServeMux()
	mux.Handle(pattern, server.RecoverAndLogHandler(promhttp.Handler(), logger))

	srv, err := server.StartHTTPServer(listener, mux, logger)
	if err != nil {
		return nil, err
	}
	return srv, nil
}
