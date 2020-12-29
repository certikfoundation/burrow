package registry

import (
	"testing"

	"github.com/certikfoundation/burrow/binary"
	"github.com/certikfoundation/burrow/crypto"
	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeProtobuf(t *testing.T) {
	entry := &NodeIdentity{
		Moniker:          "test",
		TendermintNodeID: crypto.Address{},
		ValidatorPublicKey: crypto.PublicKey{
			CurveType: crypto.CurveTypeEd25519,
			PublicKey: binary.HexBytes{1, 2, 3, 4, 5},
		},
		NetworkAddress: "localhost",
	}
	encoded, err := proto.Marshal(entry)
	require.NoError(t, err)
	entryOut := new(NodeIdentity)
	err = proto.Unmarshal(encoded, entryOut)
	require.NoError(t, err)
	assert.Equal(t, entry, entryOut)
}
