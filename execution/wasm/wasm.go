package wasm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/hyperledger/burrow/acm/acmstate"
	burrow_binary "github.com/hyperledger/burrow/binary"
	crypto "github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/errors"
	burrowexec "github.com/hyperledger/burrow/execution/exec"
	"github.com/perlin-network/life/exec"
)

type execContext struct {
	errors.Maybe
	code       []byte
	output     []byte
	returnData []byte
	params     engine.CallParams
	state      acmstate.ReaderWriter
}

// Implements ewasm, see https://github.com/ewasm/design

// RunWASM creates a WASM VM, and executes the given WASM contract code
func RunWASM(state acmstate.ReaderWriter, params engine.CallParams, wasm []byte) (output []byte, cerr error) {
	const errHeader = "ewasm"
	defer func() {
		if r := recover(); r != nil {
			cerr = errors.Codes.ExecutionAborted
		}
	}()

	// WASM
	config := exec.VMConfig{
		DisableFloatingPoint: true,
		MaxMemoryPages:       16,
		DefaultMemoryPages:   16,
	}

	execContext := execContext{
		params: params,
		code:   wasm,
		state:  state,
	}

	// panics in ResolveFunc() will be recovered for us, no need for our own
	vm, err := exec.NewVirtualMachine(wasm, config, &execContext, nil)
	if err != nil {
		return nil, errors.Errorf(errors.Codes.InvalidContract, "%s: %v", errHeader, err)
	}
	if execContext.Error() != nil {
		return nil, execContext.Error()
	}

	entryID, ok := vm.GetFunctionExport("main")
	if !ok {
		return nil, errors.Codes.UnresolvedSymbols
	}

	_, err = vm.Run(entryID)
	if err != nil && errors.GetCode(err) != errors.Codes.None {
		return nil, errors.Errorf(errors.Codes.ExecutionAborted, "%s: %v", errHeader, err)
	}

	return execContext.output, nil
}

func (e *execContext) ResolveFunc(module, field string) exec.FunctionImport {
	if module != "ethereum" {
		panic(fmt.Sprintf("unknown module %s", module))
	}

	switch field {
	case "useGas":
		return func(vm *exec.VirtualMachine) int64 {
			amount := uint64(vm.GetCurrentFrame().Locals[0])
			*e.params.Gas -= amount
			return 0
		}

	case "getBlockHash":
		return func(vm *exec.VirtualMachine) int64 {
			// TODO: implement this
			// number := int(uint64(vm.GetCurrentFrame().Locals[0]))
			// resultOffset := int(uint64(vm.GetCurrentFrame().Locals[1]))
			return 1
		}

	case "call", "callStatic", "callDelegate", "callCode":
		return func(vm *exec.VirtualMachine) int64 {
			gas := uint64(vm.GetCurrentFrame().Locals[0])
			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))
			var value uint64
			var data []byte
			switch field {
			case "call":
				valuePtr := int(uint32(vm.GetCurrentFrame().Locals[2]))
				value = binary.LittleEndian.Uint64(vm.Memory[valuePtr : valuePtr+32])
				dataPtr := int(uint32(vm.GetCurrentFrame().Locals[3]))
				dataLen := int(uint32(vm.GetCurrentFrame().Locals[4]))
				data = vm.Memory[dataPtr : dataPtr+dataLen]
			default:
				dataPtr := int(uint32(vm.GetCurrentFrame().Locals[2]))
				dataLen := int(uint32(vm.GetCurrentFrame().Locals[3]))
				data = vm.Memory[dataPtr : dataPtr+dataLen]
			}

			// fixed support for system contract of keccak256
			address := make([]byte, crypto.AddressLength)

			copy(address[:], vm.Memory[addressPtr:addressPtr+crypto.AddressLength])

			if bytes.Equal(address, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}) ||
				bytes.Equal(address, []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
				e.returnData = make([]byte, 32)
				copy(e.returnData[0:32], crypto.SHA256(data))
				return 0
			} else if bytes.Equal(address, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}) ||
				bytes.Equal(address, []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
				e.returnData = make([]byte, 32)
				copy(e.returnData[0:32], crypto.RIPEMD160(data))
				return 0
			} else if bytes.Equal(address, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}) ||
				bytes.Equal(address, []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
				e.returnData = make([]byte, len(e.params.Input))
				e.returnData = e.params.Input
				return 0
			} else if bytes.Equal(address, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}) ||
				bytes.Equal(address, []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
				e.returnData = make([]byte, 32)
				copy(e.returnData[0:32], crypto.Keccak256(data))
				return 0
			}

			target, err := crypto.AddressFromBytes(address)
			if err != nil {
				return 1
			}
			acc, err := e.state.GetAccount(target)
			if err != nil {
				return 1
			}

			code := acc.WASMCode
			if len(code) == 0 {
				return 1
			}

			callframe := engine.NewCallFrame(e.state, acmstate.Named("TxCache"))
			childcache := callframe.Cache

			calleeParams := engine.CallParams{
				Origin: e.params.Origin,
				Input:  data,
				Value:  value,
				Gas:    &gas,
			}

			switch field {
			case "call":
				calleeParams.CallType = burrowexec.CallTypeCall
				calleeParams.Caller = e.params.Callee
				calleeParams.Callee = target

			case "callStatic":
				calleeParams.CallType = burrowexec.CallTypeStatic
				calleeParams.Caller = e.params.Callee
				calleeParams.Callee = target

				callframe.ReadOnly()

			case "callCode":
				calleeParams.CallType = burrowexec.CallTypeCode
				calleeParams.Caller = e.params.Callee
				calleeParams.Callee = e.params.Callee

			case "callDelegate":
				calleeParams.CallType = burrowexec.CallTypeDelegate
				calleeParams.Caller = e.params.Caller
				calleeParams.Callee = e.params.Callee
			}

			// TODO: block events
			res, err := RunWASM(childcache, calleeParams, data)
			if errors.GetCode(err) == errors.Codes.ExecutionReverted {
				return 2
			}

			if err == nil {
				// Sync error is a hard stop
				e.PushError(callframe.Sync())
			}
			// Handle remaining gas.
			*e.params.Gas += *calleeParams.Gas
			e.returnData = res

			return 0
		}

	case "getCaller":
		return func(vm *exec.VirtualMachine) int64 {
			e.returnData = make([]byte, 20)
			copy(e.returnData[0:20], e.params.Caller.Bytes())
			return 0
		}

	case "getGasLeft":
		return func(vm *exec.VirtualMachine) int64 {
			return int64(*e.params.Gas)
		}

	case "getCallDataSize":
		return func(vm *exec.VirtualMachine) int64 {
			return int64(len(e.params.Input))
		}

	case "callDataCopy":
		return func(vm *exec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], e.params.Input[dataOffset:dataOffset+dataLen])
			}

			return 0
		}

	case "getReturnDataSize":
		return func(vm *exec.VirtualMachine) int64 {
			return int64(len(e.returnData))
		}

	case "returnDataCopy":
		return func(vm *exec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], e.returnData[dataOffset:dataOffset+dataLen])
			}

			return 0
		}

	case "getCodeSize":
		return func(vm *exec.VirtualMachine) int64 {
			return int64(len(e.code))
		}

	case "codeCopy":
		return func(vm *exec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], e.code[dataOffset:dataOffset+dataLen])
			}

			return 0
		}

	case "storageStore":
		return func(vm *exec.VirtualMachine) int64 {
			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			key := burrow_binary.Word256{}

			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

			e.Void(e.state.SetStorage(e.params.Callee, key, vm.Memory[dataPtr:dataPtr+32]))
			return 0
		}

	case "storageLoad":
		return func(vm *exec.VirtualMachine) int64 {

			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			key := burrow_binary.Word256{}

			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

			val := e.Bytes(e.state.GetStorage(e.params.Callee, key))
			copy(vm.Memory[dataPtr:], val)

			return 0
		}

	case "finish":
		return func(vm *exec.VirtualMachine) int64 {
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

			e.output = vm.Memory[dataPtr : dataPtr+dataLen]

			panic(errors.Codes.None)
		}

	case "revert":
		return func(vm *exec.VirtualMachine) int64 {

			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

			e.output = vm.Memory[dataPtr : dataPtr+dataLen]

			panic(errors.Codes.ExecutionReverted)
		}

	case "getAddress":
		return func(vm *exec.VirtualMachine) int64 {
			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

			copy(vm.Memory[addressPtr:], e.params.Callee.Bytes())

			return 0
		}

	case "getCallValue":
		return func(vm *exec.VirtualMachine) int64 {

			valuePtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

			// ewasm value is little endian 128 bit value
			bs := make([]byte, 16)
			binary.LittleEndian.PutUint64(bs, e.params.Value)

			copy(vm.Memory[valuePtr:], bs)

			return 0
		}

	case "getExternalBalance":
		return func(vm *exec.VirtualMachine) int64 {
			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			balancePtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			address := crypto.Address{}

			copy(address[:], vm.Memory[addressPtr:addressPtr+crypto.AddressLength])
			acc, err := e.state.GetAccount(address)
			if err != nil {
				panic(errors.Codes.InvalidAddress)
			}

			// ewasm value is little endian 128 bit value
			bs := make([]byte, 16)
			binary.LittleEndian.PutUint64(bs, acc.Balance)

			copy(vm.Memory[balancePtr:], bs)

			return 0
		}

	default:
		panic(fmt.Sprintf("unknown function %s", field))
	}
}

func (e *execContext) ResolveGlobal(module, field string) int64 {
	panic(fmt.Sprintf("global %s module %s not found", field, module))
}
