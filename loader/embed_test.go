package loader

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbed(t *testing.T) {
	image := make([]byte, 512)
	_, err := rand.Read(image[:256])
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

	t.Run("mode", func(t *testing.T) {
		embed := NewEmbed(image, true)
		require.Equal(t, ModeEmbed, embed.Mode())
	})
}
