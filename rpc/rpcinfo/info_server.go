// Copyright Monax Industries Limited
// SPDX-License-Identifier: Apache-2.0

package rpcinfo

import (
	"net"
	"net/http"

	"github.com/certikfoundation/burrow/logging"
	"github.com/certikfoundation/burrow/logging/structure"
	"github.com/certikfoundation/burrow/rpc"
	"github.com/certikfoundation/burrow/rpc/lib/server"
)

func StartServer(service *rpc.Service, pattern string, listener net.Listener, logger *logging.Logger) (*http.Server, error) {
	logger = logger.With(structure.ComponentKey, "RPC_Info")
	routes := GetRoutes(service)
	mux := http.NewServeMux()
	wm := server.NewWebsocketManager(routes, logger)
	mux.HandleFunc(pattern, wm.WebsocketHandler)
	server.RegisterRPCFuncs(mux, routes, logger)
	srv, err := server.StartHTTPServer(listener, mux, logger)
	if err != nil {
		return nil, err
	}
	return srv, nil
}
