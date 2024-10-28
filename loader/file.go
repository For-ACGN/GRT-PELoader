package loader

import (
	"bytes"
)

// +-----------+-----------+
// | mode flag | file path |
// +-----------+-----------+
// |   byte    |    var    |
// +-----------+-----------+

const modeFile = 2

// File is the local file mode.
type File struct {
	Path string
}

// NewFile is used to create image config with local file mode.
func NewFile(path string) Image {
	return &File{Path: path}
}

// Encode implement Image interface.
func (f *File) Encode() ([]byte, error) {
	config := bytes.NewBuffer(make([]byte, 0, 32))
	// write the mode
	config.WriteByte(modeFile)
	// write the file path
	config.WriteString(stringToUTF16(f.Path + "\x00"))
	return config.Bytes(), nil
}

// Mode implement Image interface.
func (f *File) Mode() string {
	return ModeFile
}
