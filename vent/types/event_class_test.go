package types

import (
	"fmt"
	"testing"

	"github.com/certikfoundation/burrow/config/source"
)

func TestEventTablesSchema(t *testing.T) {
	schema := ProjectionSpecSchema()
	fmt.Println(source.JSONString(schema))
}
