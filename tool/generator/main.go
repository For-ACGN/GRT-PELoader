package main

import (
	"bytes"
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var (
	tplDir  string
	pePath  string
	cmdLine string
	wait    bool
	outPath string
)

func init() {
	flag.StringVar(&tplDir, "tpl", "templates", "set shellcode templates directory")
	flag.StringVar(&pePath, "pe", "", "set input PE file path")
	flag.StringVar(&cmdLine, "cmd", "", "set command line for exe")
	flag.BoolVar(&wait, "wait", false, "wait for shellcode to exit")
	flag.StringVar(&outPath, "o", "output.bin", "set output file path")
	flag.Parse()
}

func main() {
	fmt.Println("load PE Loader templates")
	ldrX64, err := os.ReadFile(filepath.Join(tplDir, "PELoader_x64.bin"))
	checkError(err)
	ldrX86, err := os.ReadFile(filepath.Join(tplDir, "PELoader_x86.bin"))
	checkError(err)

	fmt.Println("parse PE image file")
	peData, err := os.ReadFile(pePath)
	checkError(err)
	peFile, err := pe.NewFile(bytes.NewReader(peData))
	checkError(err)

	var template []byte
	switch peFile.OptionalHeader.(type) {
	case pe.OptionalHeader64:
		template = ldrX64
		fmt.Println("select template for x64")
	case pe.OptionalHeader32:
		template = ldrX86
		fmt.Println("select template for x86")
	default:
		fmt.Println("unknown optional header type")
		return
	}

}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// +---------+----------+-----------+----------+----------+
// |   key   | num args | args size | arg size | arg data |
// +---------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32   |  uint32  |   var    |
// +---------+----------+-----------+----------+----------+

const (
	cryptoKeySize  = 32
	offsetFirstArg = 32 + 4 + 4
)

// EncodeArgStub is used to encode and encrypt arguments for runtime
func EncodeArgStub(args [][]byte) ([]byte, error) {
	key := make([]byte, cryptoKeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("failed to generate crypto key")
	}
	// write crypto key
	buf := bytes.NewBuffer(make([]byte, 0, offsetFirstArg))
	buf.Write(key)
	// write the number of arguments
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(args)))
	buf.Write(b)
	// calculate the total size of the arguments
	var totalSize int
	for i := 0; i < len(args); i++ {
		totalSize += 4 + len(args[i])
	}
	binary.LittleEndian.PutUint32(b, uint32(totalSize))
	buf.Write(b)
	// write arguments
	for i := 0; i < len(args); i++ {
		// write argument size
		binary.LittleEndian.PutUint32(b, uint32(len(args[i])))
		buf.Write(b)
		// write argument data
		buf.Write(args[i])
	}
	output := buf.Bytes()
	encryptArgStub(output)
	return output, nil
}

func encryptArgStub(stub []byte) {
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		last = data[i]
		data[i] = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}

// DecodeArgStub is used to decode and decrypt arguments from raw stub.
func DecodeArgStub(stub []byte) ([][]byte, error) {
	if len(stub) < offsetFirstArg {
		return nil, errors.New("stub is too short")
	}
	numArgs := binary.LittleEndian.Uint32(stub[cryptoKeySize:])
	if numArgs == 0 {
		return nil, nil
	}
	decryptArgStub(stub)
	args := make([][]byte, 0, numArgs)
	offset := offsetFirstArg
	for i := 0; i < int(numArgs); i++ {
		l := binary.LittleEndian.Uint32(stub[offset:])
		arg := make([]byte, l)
		copy(arg, stub[offset+4:offset+4+int(l)])
		args = append(args, arg)
		offset += 4 + int(l)
	}
	return args, nil
}

func decryptArgStub(stub []byte) {
	key := stub[:cryptoKeySize]
	data := stub[offsetFirstArg:]
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(data); i++ {
		b := data[i] ^ last
		b ^= key[keyIdx]
		data[i] = b
		last = b
		// update key index
		keyIdx++
		if keyIdx >= cryptoKeySize {
			keyIdx = 0
		}
	}
}
