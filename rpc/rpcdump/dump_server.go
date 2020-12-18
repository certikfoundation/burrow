package rpcdump

import (
	"github.com/certikfoundation/burrow/bcm"
	"github.com/certikfoundation/burrow/dump"
	"github.com/certikfoundation/burrow/execution/state"
	"github.com/certikfoundation/burrow/logging"
)

type dumpServer struct {
	dumper *dump.Dumper
}

var _ DumpServer = &dumpServer{}

func NewDumpServer(state *state.State, blockchain bcm.BlockchainInfo, logger *logging.Logger) *dumpServer {
	return &dumpServer{
		dumper: dump.NewDumper(state, blockchain).WithLogger(logger),
	}
}

func (ds *dumpServer) GetDump(param *GetDumpParam, stream Dump_GetDumpServer) error {
	return ds.dumper.Transmit(stream, 0, param.Height, dump.All)
}
