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
	arch    int
	mode    string
	pePath  string
	cmdLine string
	wait    bool
	outPath string
	options option.Options
)

func init() {
	option.Flag(&options)
	flag.StringVar(&tplDir, "tpl", "template", "set shellcode templates directory")
	flag.IntVar(&arch, "arch", 0, "set shellcode template architecture")
	flag.StringVar(&mode, "mode", "", "select load mode")
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

	peConfig := make([]byte, 1)
	switch mode {
	case "embed":
		peConfig[0] = 1
		fmt.Println("use embed image mode")

		// disable compression
		// TODO update it
		peConfig = append(peConfig, 0)

		fmt.Println("parse PE image file")
		peData, err := os.ReadFile(pePath)
		checkError(err)
		peFile, err := pe.NewFile(bytes.NewReader(peData))
		checkError(err)
		switch peFile.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			arch = 64
		case *pe.OptionalHeader32:
			arch = 32
		default:
			fmt.Println("unknown optional header type")
			return
		}
		// write length
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(len(peData)))
		peConfig = append(peConfig, buf...)
		// write pe image
		peConfig = append(peConfig, peData...)
	case "file":
		peConfig[0] = 2
		path := stringToUTF16(pePath + "\x00")
		peConfig = append(peConfig, path...)
	case "http":
		peConfig[0] = 3
		path := stringToUTF16(pePath + "\x00")
		peConfig = append(peConfig, path...)
	default:
		fmt.Println("unknown load mode")
		return
	}

	var (
		template  []byte
		stdHandle []byte
	)
	switch arch {
	case 64:
		template = ldrX64
		stdHandle = make([]byte, 8)
		fmt.Println("select template for x64")
	case 32:
		template = ldrX86
		stdHandle = make([]byte, 4)
		fmt.Println("select template for x86")
	default:
		fmt.Println("unknown template architecture")
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
		if peName == string(filepath.Separator) {
			peName = "test.exe"
		}
		if strings.Contains(peName, " ") {
			peName = "\"" + peName + "\""
		}
		peName += " "
		cmdLine = peName + cmdLine + "\x00"
		cmdLineA = []byte(cmdLine)
		cmdLineW = []byte(stringToUTF16(cmdLine))
	}

	argWait := make([]byte, 1)
	if wait {
		argWait[0] = 1
	}
	args := [][]byte{
		peConfig, cmdLineA, cmdLineW,
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

func stringToUTF16(s string) string {
	w := utf16.Encode([]rune(s))
	output := make([]byte, len(w)*2)
	for i := 0; i < len(w); i++ {
		binary.LittleEndian.PutUint16(output[i*2:], w[i])
	}
	return string(output)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
