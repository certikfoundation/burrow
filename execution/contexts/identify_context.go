package contexts

import (
	"fmt"

	"github.com/certikfoundation/burrow/acm/acmstate"
	"github.com/certikfoundation/burrow/execution/errors"
	"github.com/certikfoundation/burrow/execution/exec"
	"github.com/certikfoundation/burrow/execution/registry"
	"github.com/certikfoundation/burrow/logging"
	"github.com/certikfoundation/burrow/permission"
	"github.com/certikfoundation/burrow/txs/payload"
)

type IdentifyContext struct {
	NodeWriter  registry.ReaderWriter
	StateReader acmstate.Reader
	Logger      *logging.Logger
	tx          *payload.IdentifyTx
}

func (ctx *IdentifyContext) Execute(txe *exec.TxExecution, p payload.Payload) error {
	var ok bool
	ctx.tx, ok = p.(*payload.IdentifyTx)
	if !ok {
		return fmt.Errorf("payload must be IdentifyTx, but is: %v", txe.Envelope.Tx.Payload)
	}

	inputs, _, err := getInputs(ctx.StateReader, ctx.tx.Inputs)
	if err != nil {
		return err
	}

	// One of our inputs must have identify permissions
	err = oneHasPermission(ctx.StateReader, permission.Identify, inputs, ctx.Logger)
	if err != nil {
		return errors.Wrap(err, "at least one input lacks permission for IdentifyTx")
	}

	// Registry updates must be consensual and binding so we requires signatures
	// from the validator key of the node being added
	validatorAddress := ctx.tx.Node.ValidatorPublicKey.GetAddress()
	if _, ok := inputs[validatorAddress]; !ok {
		return fmt.Errorf("IdentifyTx must be signed by node's validator key, but missing %v in inputs",
			validatorAddress)
	}

	return ctx.NodeWriter.UpdateNode(ctx.tx.Node.TendermintNodeID, ctx.tx.Node)
}
