package redis

import (
	"os"
	"sync"

	"github.com/alicebob/miniredis/v2"
)

var (
	miniServer *miniredis.Miniredis
	miniOnce   sync.Once
)

// StartEmbeddedRedis starts an in-process miniredis instance and sets the
// REDIS_ADDR environment variable so all Redis clients connect to it.
// This is used in local mode when no external Redis is available.
func StartEmbeddedRedis() (string, error) {
	var startErr error
	miniOnce.Do(func() {
		miniServer, startErr = miniredis.Run()
		if startErr != nil {
			return
		}
		// Point all Redis clients to the embedded instance
		os.Setenv("REDIS_ADDR", miniServer.Addr())
	})
	if startErr != nil {
		return "", startErr
	}
	return miniServer.Addr(), nil
}

// StopEmbeddedRedis shuts down the embedded Redis server.
func StopEmbeddedRedis() {
	if miniServer != nil {
		miniServer.Close()
	}
}

// IsEmbeddedRunning returns true if an embedded Redis is running.
func IsEmbeddedRunning() bool {
	return miniServer != nil
}
