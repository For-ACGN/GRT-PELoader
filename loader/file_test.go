package loader

import (
	"crypto/rand"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestFile(t *testing.T) {
	image := make([]byte, 512)
	_, err := rand.Read(image[:256])
	require.NoError(t, err)

	t.Run("common", func(t *testing.T) {
		file := NewFile("C:\\Windows\\System32\\cmd.exe")

		config, err := file.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		file := NewFile("C:\\Windows\\System32\\cmd.exe")
		require.Equal(t, ModeFile, file.Mode())
	})
}
