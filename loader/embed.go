package loader

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/bovarysme/lzss"
)

// disable compress
// +-----------+----------+-------+
// | mode flag | compress | image |
// +-----------+----------+-------+
// |   byte    |   bool   |  var  |
// +-----------+----------+-------+

// enable compress
// +-----------+----------+----------+-----------------+-------+
// | mode flag | compress | raw size | compressed size | image |
// +-----------+----------+----------+-----------------+-------+
// |   byte    |   bool   |  uint32  |     uint32      |  var  |
// +-----------+----------+----------+-----------------+-------+

const modeEmbed = 1

const (
	disableCompress = 0
	enableCompress  = 1
)

// Embed is the embed mode.
type Embed struct {
	Image    []byte
	Compress bool
}

// NewEmbed is used to create image config with embed mode.
func NewEmbed(image []byte, compress bool) Image {
	return &Embed{
		Image:    image,
		Compress: compress,
	}
}

// Encode implement Image interface.
func (e *Embed) Encode() ([]byte, error) {
	// check PE image
	_, err := pe.NewFile(bytes.NewReader(e.Image))
	if err != nil {
		return nil, fmt.Errorf("invalid PE image: %s", err)
	}
	config := bytes.NewBuffer(make([]byte, 0, 16))
	// write the mode
	config.WriteByte(modeEmbed)
	if !e.Compress {
		config.WriteByte(disableCompress)
		config.Write(e.Image)
		return config.Bytes(), nil
	}
	// set the compressed flag
	config.WriteByte(enableCompress)
	// compress PE image
	buf := bytes.NewBuffer(make([]byte, 0, len(e.Image)/2))
	w := lzss.NewWriter(buf)
	_, err = w.Write(e.Image)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}
	// write raw size
	size := binary.LittleEndian.AppendUint32(nil, uint32(len(e.Image)))
	config.Write(size)
	// write compressed size
	size = binary.LittleEndian.AppendUint32(nil, uint32(buf.Len()))
	config.Write(size)
	// write compressed PE image
	config.Write(buf.Bytes())
	return config.Bytes(), nil
}

// Mode implement Image interface.
func (e *Embed) Mode() string {
	return ModeEmbed
}
