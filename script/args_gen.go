package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/RSSU-Shellcode/RT-Argument"
)

func main() {
	args := [][]byte{
		{0xFF, 0xFF, 0x00, 0x00},             // invalid PE image
		[]byte("test_x86.exe -arg 1234\x00"), // command line
		make([]byte, 4),                      // std input handle
		make([]byte, 4),                      // std output handle
		make([]byte, 4),                      // std error handle
		{0x01},                               // wait main
	}
	stub, err := argument.Encode(args)
	checkError(err)

	fmt.Println("============x86============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")

	fmt.Println()

	args = [][]byte{
		{0xFF, 0xFF, 0x00, 0x00},             // invalid PE image
		[]byte("test_x64.exe -arg 1234\x00"), // command line
		make([]byte, 8),                      // std input handle
		make([]byte, 8),                      // std output handle
		make([]byte, 8),                      // std error handle
		{0x01},                               // wait main
	}
	stub, err = argument.Encode(args)
	checkError(err)

	fmt.Println("============x64============")
	fmt.Println(dumpBytesHex(stub))
	fmt.Println("===========================")
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 4 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.String()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
