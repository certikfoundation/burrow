package tendermint

import (
	"fmt"

	"github.com/hyperledger/burrow/crypto"
	tmCrypto "github.com/tendermint/tendermint/crypto"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmTypes "github.com/tendermint/tendermint/types"
)

type privValidatorMemory struct {
	crypto.Addressable
	signer         func(msg []byte) []byte
	lastSignedInfo *LastSignedInfo
}

var _ tmTypes.PrivValidator = &privValidatorMemory{}

// Create a PrivValidator with in-memory state that takes an addressable representing the validator identity
// and a signer providing private signing for that identity.
func NewPrivValidatorMemory(addressable crypto.Addressable, signer crypto.Signer) *privValidatorMemory {
	return &privValidatorMemory{
		Addressable:    addressable,
		signer:         asTendermintSigner(signer),
		lastSignedInfo: NewLastSignedInfo(),
	}
}

func asTendermintSigner(signer crypto.Signer) func(msg []byte) []byte {
	return func(msg []byte) []byte {
		sig, err := signer.Sign(msg)
		if err != nil {
			return nil
		}
		return sig.TendermintSignature()
	}
}

func (pvm *privValidatorMemory) GetAddress() tmTypes.Address {
	return pvm.Addressable.GetAddress().Bytes()
}

func (pvm *privValidatorMemory) GetPubKey() (tmCrypto.PubKey, error) {
	pk := pvm.GetPublicKey().TendermintPubKey()
	if pk == nil {
		return nil, fmt.Errorf("error getting tendermint pubkey")
	}
	return pk, nil
}

// TODO: consider persistence to disk/database to avoid double signing after a crash
func (pvm *privValidatorMemory) SignVote(chainID string, vote *tmproto.Vote) error {
	return pvm.lastSignedInfo.SignVote(pvm.signer, chainID, vote)
}

func (pvm *privValidatorMemory) SignProposal(chainID string, proposal *tmproto.Proposal) error {
	return pvm.lastSignedInfo.SignProposal(pvm.signer, chainID, proposal)
}
