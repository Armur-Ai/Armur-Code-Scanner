package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const epssURL = "https://api.first.org/data/v1/epss"

// EPSSScore represents the exploit prediction scoring for a CVE.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`       // 0.0-1.0 probability
	Percentile float64 `json:"percentile"` // 0.0-1.0
}

// QueryEPSS queries the FIRST.org EPSS API for a list of CVE IDs.
func QueryEPSS(cveIDs []string) (map[string]EPSSScore, error) {
	if len(cveIDs) == 0 {
		return map[string]EPSSScore{}, nil
	}

	// Batch query (max 30 per request)
	result := make(map[string]EPSSScore)
	for i := 0; i < len(cveIDs); i += 30 {
		end := i + 30
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		scores, err := queryEPSSBatch(batch)
		if err != nil {
			continue // Don't fail on EPSS enrichment errors
		}
		for k, v := range scores {
			result[k] = v
		}
	}

	return result, nil
}

func queryEPSSBatch(cveIDs []string) (map[string]EPSSScore, error) {
	url := fmt.Sprintf("%s?cve=%s", epssURL, strings.Join(cveIDs, ","))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("EPSS API error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Data []struct {
			CVE        string  `json:"cve"`
			EPSS       string  `json:"epss"`
			Percentile string  `json:"percentile"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	result := make(map[string]EPSSScore)
	for _, d := range response.Data {
		var epss, percentile float64
		fmt.Sscanf(d.EPSS, "%f", &epss)
		fmt.Sscanf(d.Percentile, "%f", &percentile)

		result[d.CVE] = EPSSScore{
			CVE:        d.CVE,
			EPSS:       epss,
			Percentile: percentile,
		}
	}

	return result, nil
}

// EPSSRiskMultiplier returns a risk multiplier based on the EPSS score.
func EPSSRiskMultiplier(epss float64) float64 {
	if epss > 0.5 {
		return 1.5
	}
	if epss > 0.1 {
		return 1.2
	}
	return 1.0
}

// FormatEPSS returns a human-readable EPSS annotation.
func FormatEPSS(score EPSSScore) string {
	pct := score.EPSS * 100
	if pct > 50 {
		return fmt.Sprintf("EPSS: %.0f%% exploitation probability (HIGH)", pct)
	}
	if pct > 10 {
		return fmt.Sprintf("EPSS: %.0f%% exploitation probability (moderate)", pct)
	}
	return fmt.Sprintf("EPSS: %.1f%% exploitation probability (low)", pct)
}
