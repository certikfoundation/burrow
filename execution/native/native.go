package native

import (
	"github.com/certikfoundation/burrow/acm"
	"github.com/certikfoundation/burrow/crypto"
	"github.com/certikfoundation/burrow/execution/engine"
)

type Native interface {
	engine.Callable
	SetExternals(externals engine.Dispatcher)
	ContractMeta() []*acm.ContractMeta
	FullName() string
	Address() crypto.Address
}

func MustDefaultNatives() *Natives {
	ns, err := DefaultNatives()
	if err != nil {
		panic(err)
	}
	return ns
}

func DefaultNatives() (*Natives, error) {
	ns, err := Merge(Permissions, Precompiles)
	if err != nil {
		return nil, err
	}
	return ns, nil
}
