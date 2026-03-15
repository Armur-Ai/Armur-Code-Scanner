package models

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// SLA defines remediation time limits per severity.
type SLA struct {
	Critical time.Duration `json:"critical"` // e.g., 24 hours
	High     time.Duration `json:"high"`     // e.g., 7 days
	Medium   time.Duration `json:"medium"`   // e.g., 30 days
	Low      time.Duration `json:"low"`      // e.g., 90 days
}

// DefaultSLA returns industry-standard remediation SLAs.
func DefaultSLA() SLA {
	return SLA{
		Critical: 24 * time.Hour,
		High:     7 * 24 * time.Hour,
		Medium:   30 * 24 * time.Hour,
		Low:      90 * 24 * time.Hour,
	}
}

// SLAStatus tracks whether a finding is within SLA.
type SLAStatus struct {
	FindingID   string        `json:"finding_id"`
	Severity    Severity      `json:"severity"`
	DetectedAt  time.Time     `json:"detected_at"`
	Deadline    time.Time     `json:"deadline"`
	Overdue     bool          `json:"overdue"`
	TimeLeft    time.Duration `json:"time_left,omitempty"`
	OverdueBy   time.Duration `json:"overdue_by,omitempty"`
}

// CheckSLA determines if a finding is within its remediation SLA.
func CheckSLA(severity Severity, detectedAt time.Time, sla SLA) SLAStatus {
	var limit time.Duration
	switch severity {
	case SeverityCritical:
		limit = sla.Critical
	case SeverityHigh:
		limit = sla.High
	case SeverityMedium:
		limit = sla.Medium
	case SeverityLow:
		limit = sla.Low
	default:
		limit = 365 * 24 * time.Hour // INFO: 1 year
	}

	deadline := detectedAt.Add(limit)
	now := time.Now()
	overdue := now.After(deadline)

	status := SLAStatus{
		Severity:   severity,
		DetectedAt: detectedAt,
		Deadline:   deadline,
		Overdue:    overdue,
	}

	if overdue {
		status.OverdueBy = now.Sub(deadline)
	} else {
		status.TimeLeft = deadline.Sub(now)
	}

	return status
}

// SecurityDebt represents the total remediation effort for a project.
type SecurityDebt struct {
	TotalHours     float64 `json:"total_hours"`
	CriticalHours  float64 `json:"critical_hours"`
	HighHours      float64 `json:"high_hours"`
	MediumHours    float64 `json:"medium_hours"`
	LowHours       float64 `json:"low_hours"`
	TrendDirection string  `json:"trend_direction"` // up, down, stable
}

// EstimateDebt computes estimated security debt in engineering hours.
func EstimateDebt(findings []Finding) SecurityDebt {
	// Hours per finding by severity (industry average estimates)
	hoursPerFinding := map[Severity]float64{
		SeverityCritical: 8.0,
		SeverityHigh:     4.0,
		SeverityMedium:   2.0,
		SeverityLow:      0.5,
		SeverityInfo:     0.25,
	}

	debt := SecurityDebt{}
	for _, f := range findings {
		hours := hoursPerFinding[f.Severity]
		debt.TotalHours += hours
		switch f.Severity {
		case SeverityCritical:
			debt.CriticalHours += hours
		case SeverityHigh:
			debt.HighHours += hours
		case SeverityMedium:
			debt.MediumHours += hours
		case SeverityLow:
			debt.LowHours += hours
		}
	}

	// Round to 1 decimal
	debt.TotalHours = math.Round(debt.TotalHours*10) / 10
	debt.CriticalHours = math.Round(debt.CriticalHours*10) / 10
	debt.HighHours = math.Round(debt.HighHours*10) / 10
	debt.MediumHours = math.Round(debt.MediumHours*10) / 10
	debt.LowHours = math.Round(debt.LowHours*10) / 10

	return debt
}

// FormatDebt returns a human-readable security debt summary.
func FormatDebt(debt SecurityDebt) string {
	var b strings.Builder
	b.WriteString("Security Debt Summary\n")
	b.WriteString(strings.Repeat("─", 40) + "\n")
	b.WriteString(fmt.Sprintf("Critical:  %.1fh\n", debt.CriticalHours))
	b.WriteString(fmt.Sprintf("High:      %.1fh\n", debt.HighHours))
	b.WriteString(fmt.Sprintf("Medium:    %.1fh\n", debt.MediumHours))
	b.WriteString(fmt.Sprintf("Low:       %.1fh\n", debt.LowHours))
	b.WriteString(strings.Repeat("─", 40) + "\n")
	b.WriteString(fmt.Sprintf("Total:     %.1fh (~%.0f engineering days)\n", debt.TotalHours, debt.TotalHours/8))
	return b.String()
}

// NeverAllowRule defines a rule that must never have findings (breaks the build).
type NeverAllowRule struct {
	CWE      string `yaml:"cwe" json:"cwe"`
	RuleID   string `yaml:"rule_id" json:"rule_id"`
	Severity string `yaml:"severity" json:"severity"` // block findings at this severity or above
	Reason   string `yaml:"reason" json:"reason"`
}

// CheckNeverAllow verifies that no findings violate never-allow rules.
func CheckNeverAllow(findings []Finding, rules []NeverAllowRule) []Finding {
	var violations []Finding
	for _, f := range findings {
		for _, rule := range rules {
			if rule.CWE != "" && strings.EqualFold(f.CWE, rule.CWE) {
				violations = append(violations, f)
				continue
			}
			if rule.RuleID != "" && strings.EqualFold(f.RuleID, rule.RuleID) {
				violations = append(violations, f)
				continue
			}
			if rule.Severity != "" && SeverityOrder(f.Severity) >= SeverityOrder(Severity(strings.ToUpper(rule.Severity))) {
				violations = append(violations, f)
			}
		}
	}
	return violations
}
