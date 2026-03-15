package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"armur-codescanner/internal/redis"
)

const cacheTTL = 24 * time.Hour

// CacheKey generates a cache key for a tool result on a specific file.
func CacheKey(repoURL, filePath, toolName string, fileHash string) string {
	return fmt.Sprintf("cache:%s:%s:%s:%s", repoURL, filePath, fileHash, toolName)
}

// FileHash computes the SHA256 hash of a file for cache key generation.
func FileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetCachedResult checks if a tool result is cached for the given file hash.
func GetCachedResult(key string) (string, bool) {
	ctx := context.Background()
	result, err := redis.RedisClient().Get(ctx, key).Result()
	if err != nil {
		return "", false
	}
	return result, true
}

// SetCachedResult stores a tool result in the cache.
func SetCachedResult(key, value string) error {
	ctx := context.Background()
	return redis.RedisClient().Set(ctx, key, value, cacheTTL).Err()
}

// ClearCache flushes all cached results.
func ClearCache() error {
	ctx := context.Background()
	iter := redis.RedisClient().Scan(ctx, 0, "cache:*", 0).Iterator()
	for iter.Next(ctx) {
		redis.RedisClient().Del(ctx, iter.Val())
	}
	return iter.Err()
}

// CacheStats returns cache hit/miss statistics for a scan.
type CacheStats struct {
	TotalFiles     int     `json:"total_files"`
	CacheHits      int     `json:"cache_hits"`
	CacheMisses    int     `json:"cache_misses"`
	HitRate        float64 `json:"hit_rate"`
	FilesFromCache int     `json:"files_from_cache"`
}

// ComputeCacheStats calculates cache performance metrics.
func ComputeCacheStats(hits, misses int) CacheStats {
	total := hits + misses
	rate := 0.0
	if total > 0 {
		rate = float64(hits) / float64(total)
	}
	return CacheStats{
		TotalFiles:     total,
		CacheHits:      hits,
		CacheMisses:    misses,
		HitRate:        rate,
		FilesFromCache: hits,
	}
}
