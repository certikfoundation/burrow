package payload

import (
	"fmt"

	"github.com/certikfoundation/burrow/crypto"
	"github.com/certikfoundation/burrow/execution/registry"
)

func NewIdentifyTx(address crypto.Address, node *registry.NodeIdentity) *IdentifyTx {
	return &IdentifyTx{
		Inputs: []*TxInput{&TxInput{
			Address: address,
		}},
		Node: node,
	}
}

func (tx *IdentifyTx) Type() Type {
	return TypeIdentify
}

func (tx *IdentifyTx) GetInputs() []*TxInput {
	return tx.Inputs
}

func (tx *IdentifyTx) String() string {
	return fmt.Sprintf("IdentifyTx{%v -> %v}", tx.Inputs, tx.Node.NetworkAddress)
}

func (tx *IdentifyTx) Any() *Any {
	return &Any{
		IdentifyTx: tx,
	}
}
