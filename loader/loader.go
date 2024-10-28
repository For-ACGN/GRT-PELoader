package loader

import (
	"github.com/RSSU-Shellcode/GRT-Config/option"
)

// the load mode about image source.
const (
	ModeEmbed = "embed"
	ModeFile  = "file"
	ModeHTTP  = "http"
)

// Config contains config about create instance.
type Config struct {
	// set the load mode about image source
	Mode string

	// image data or image file path/URL
	Image interface{}

	// set the command about the image
	CommandLine string

	// set standard handles for hook GetStdHandle,
	// if them are NULL, call original GetStdHandle
	StdInput  uintptr
	StdOutput uintptr
	StdError  uintptr

	// wait main thread exit if it is an exe image
	WaitMain bool

	// set Gleam-RT options, usually keep the default value
	Runtime *option.Options
}

// CreateInstance is used to create instance from PE Loader template.
func CreateInstance(tpl []byte, cfg *Config) ([]byte, error) {
	return nil, nil
}
