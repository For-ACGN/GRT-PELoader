package loader

import (
	"crypto/rand"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testURL = "https://github.com/RSSU-Shellcode/GRT-PELoader"

func TestHTTP(t *testing.T) {
	image := make([]byte, 512)
	_, err := rand.Read(image[:256])
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		http := NewHTTP(testURL, nil)

		config, err := http.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("invalid URL", func(t *testing.T) {
		http := NewHTTP("invalid url", nil)

		config, err := http.Encode()
		errStr := "parse \"invalid url\": invalid URI for request"
		require.EqualError(t, err, errStr)
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		http := NewHTTP(testURL, nil)
		require.Equal(t, ModeHTTP, http.Mode())
	})
}
