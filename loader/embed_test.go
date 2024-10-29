package loader

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	image, err := os.ReadFile("testdata/executable.dat")
	require.NoError(t, err)

	t.Run("enable compress", func(t *testing.T) {
		embed := NewEmbed(image, true)

		config, err := embed.Encode()
		require.NoError(t, err)

		require.Less(t, len(config), len(image))
	})

	t.Run("disable compress", func(t *testing.T) {
		embed := NewEmbed(image, false)

		config, err := embed.Encode()
		require.NoError(t, err)

		require.Greater(t, len(config), len(image))
	})

	t.Run("invalid PE image", func(t *testing.T) {
		embed := NewEmbed([]byte{0x00, 0x01}, false)

		config, err := embed.Encode()
		require.EqualError(t, err, "invalid PE image: EOF")
		require.Nil(t, config)
	})

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(image, true)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}
