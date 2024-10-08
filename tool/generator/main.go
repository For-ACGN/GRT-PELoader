package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/RSSU-Shellcode/GRT-Config/argument"
	"github.com/RSSU-Shellcode/GRT-Config/option"
)

var (
	tplDir  string
	pePath  string
	cmdLine string
	wait    bool
	outPath string
	options option.Options
)

func init() {
	option.Flag(&options)
	flag.StringVar(&tplDir, "tpl", "template", "set shellcode templates directory")
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

	var (
		template  []byte
		stdHandle []byte
	)
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		template = ldrX64
		stdHandle = make([]byte, 8)
		fmt.Println("select template for x64")
	case *pe.OptionalHeader32:
		template = ldrX86
		stdHandle = make([]byte, 4)
		fmt.Println("select template for x86")
	default:
		fmt.Println("unknown optional header type")
		return
	}

	fmt.Println("set runtime options to template")
	output, err := option.Set(template, &options)
	checkError(err)

	fmt.Println("encode arguments to stub")
	var (
		cmdLineA []byte
		cmdLineW []byte
	)
	if cmdLine != "" {
		peName := filepath.Base(pePath)
		if strings.Contains(peName, " ") {
			peName = "\"" + peName + "\""
		}
		peName += " "
		cmdLineA = []byte(peName + cmdLine + "\x00")

		w := utf16.Encode([]rune(peName + cmdLine))
		cmdLineW = make([]byte, len(w)*2+2)
		for i := 0; i < len(w); i++ {
			binary.LittleEndian.PutUint16(cmdLineW[i*2:], w[i])
		}
	}

	argWait := make([]byte, 1)
	if wait {
		argWait[0] = 1
	}
	args := [][]byte{
		peData, cmdLineA, cmdLineW,
		stdHandle, stdHandle, stdHandle,
		argWait,
	}
	stub, err := argument.Encode(args...)
	checkError(err)

	fmt.Println("generate shellcode about PE Loader")
	output = append(output, stub...)
	err = os.WriteFile(outPath, output, 0600)
	checkError(err)

	fmt.Println("generate shellcode successfully")
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
