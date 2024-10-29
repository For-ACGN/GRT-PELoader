package loader

import (
	"bytes"
	"net/url"
	"time"
)

// +-----------+-----+
// | mode flag | URL |
// +-----------+-----+
// |   byte    | var |
// +-----------+-----+

const modeHTTP = 3

// HTTP is the HTTP mode.
type HTTP struct {
	URL  string
	Opts *HTTPOptions
}

// HTTPOptions contain HTTP mode options.
type HTTPOptions struct {
	ProxyURL string
	Timeout  time.Duration
}

// NewHTTP is used to create image config with HTTP mode.
func NewHTTP(url string, opts *HTTPOptions) Image {
	return &HTTP{
		URL:  url,
		Opts: opts,
	}
}

// Encode implement Image interface.
func (f *HTTP) Encode() ([]byte, error) {
	req, err := url.ParseRequestURI(f.URL)
	if err != nil {
		return nil, err
	}
	config := bytes.NewBuffer(make([]byte, 0, 64))
	// write the mode
	config.WriteByte(modeHTTP)
	// write the URL
	config.WriteString(stringToUTF16(req.String() + "\x00"))
	// TODO write the options
	return config.Bytes(), nil
}

// Mode implement Image interface.
func (f *HTTP) Mode() string {
	return ModeHTTP
}
