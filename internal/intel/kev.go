package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVEntry represents an entry in the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID            string `json:"cveID"`
	VendorProject    string `json:"vendorProject"`
	Product          string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded        string `json:"dateAdded"`
	ShortDescription string `json:"shortDescription"`
	DueDate          string `json:"dueDate"`
	RansomwareUse    string `json:"knownRansomwareCampaignUse"`
}

var (
	kevCache     map[string]KEVEntry
	kevCacheOnce sync.Once
	kevCacheTime time.Time
)

// LoadKEV fetches and caches the CISA KEV catalog (24-hour cache).
func LoadKEV() (map[string]KEVEntry, error) {
	kevCacheOnce.Do(func() {
		kevCache = map[string]KEVEntry{}
		refreshKEV()
	})

	// Refresh if cache is stale
	if time.Since(kevCacheTime) > 24*time.Hour {
		refreshKEV()
	}

	return kevCache, nil
}

func refreshKEV() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(kevURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var catalog struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return
	}

	newCache := make(map[string]KEVEntry, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		newCache[v.CVEID] = v
	}
	kevCache = newCache
	kevCacheTime = time.Now()
}

// IsKEV checks if a CVE ID is in the CISA KEV catalog.
func IsKEV(cveID string) (bool, *KEVEntry) {
	kev, _ := LoadKEV()
	if entry, ok := kev[cveID]; ok {
		return true, &entry
	}
	return false, nil
}

// EnrichWithKEV adds KEV information to a finding message.
func EnrichWithKEV(cveID string) string {
	if ok, entry := IsKEV(cveID); ok {
		return fmt.Sprintf("ACTIVELY EXPLOITED (CISA KEV) — Due: %s. %s", entry.DueDate, entry.ShortDescription)
	}
	return ""
}
