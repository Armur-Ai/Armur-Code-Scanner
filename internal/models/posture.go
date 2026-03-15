package models

import "math"

// PostureScore represents a project's security posture.
type PostureScore struct {
	Score    int    `json:"score"`    // 0-100
	Grade    string `json:"grade"`    // A, B, C, D, F
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

// ComputePosture calculates the security posture score from findings.
func ComputePosture(findings []Finding) PostureScore {
	counts := PostureScore{}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			counts.Critical++
		case SeverityHigh:
			counts.High++
		case SeverityMedium:
			counts.Medium++
		case SeverityLow:
			counts.Low++
		case SeverityInfo:
			counts.Info++
		}
	}

	score := 100.0
	score -= float64(counts.Critical) * 20
	score -= float64(counts.High) * 10
	score -= float64(counts.Medium) * 3
	score -= float64(counts.Low) * 0.5

	// Bonus for zero critical
	if counts.Critical == 0 {
		score += 10
	}

	score = math.Max(0, math.Min(100, score))
	counts.Score = int(score)

	switch {
	case score >= 90:
		counts.Grade = "A"
	case score >= 75:
		counts.Grade = "B"
	case score >= 60:
		counts.Grade = "C"
	case score >= 40:
		counts.Grade = "D"
	default:
		counts.Grade = "F"
	}

	return counts
}
