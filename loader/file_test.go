package loader

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

const testFilePath = "C:\\Windows\\System32\\cmd.exe"

func TestFile(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		file := NewFile(testFilePath)

		config, err := file.Encode()
		require.NoError(t, err)

		spew.Dump(config)
	})

	t.Run("mode", func(t *testing.T) {
		file := NewFile(testFilePath)
		require.Equal(t, ModeFile, file.Mode())
	})
}
