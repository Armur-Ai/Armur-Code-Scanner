package compliance

import (
	"armur-codescanner/internal/models"
	"fmt"
	"strings"
)

// CWETop25Entry represents a single entry in the CWE Top 25 Most Dangerous Software Weaknesses.
type CWETop25Entry struct {
	Rank         int    `json:"rank"`
	ID           string `json:"id"`   // e.g. "CWE-787"
	Name         string `json:"name"`
	Description  string `json:"description"`
	FindingCount int    `json:"finding_count"`
	Status       string `json:"status"` // "pass", "fail", "not_applicable"
}

// CWETop25 is the 2024 CWE Top 25 Most Dangerous Software Weaknesses list.
var CWETop25 = []CWETop25Entry{
	{Rank: 1, ID: "CWE-787", Name: "Out-of-bounds Write", Description: "The product writes data past the end, or before the beginning, of the intended buffer"},
	{Rank: 2, ID: "CWE-79", Name: "Cross-site Scripting", Description: "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page"},
	{Rank: 3, ID: "CWE-89", Name: "SQL Injection", Description: "The product constructs all or part of an SQL command using externally-influenced input without proper neutralization"},
	{Rank: 4, ID: "CWE-416", Name: "Use After Free", Description: "The product references memory after it has been freed, which can cause a program to crash or execute arbitrary code"},
	{Rank: 5, ID: "CWE-78", Name: "OS Command Injection", Description: "The product constructs all or part of an OS command using externally-influenced input without proper neutralization"},
	{Rank: 6, ID: "CWE-20", Name: "Improper Input Validation", Description: "The product receives input but does not validate or incorrectly validates that the input has the properties required to process the data safely"},
	{Rank: 7, ID: "CWE-125", Name: "Out-of-bounds Read", Description: "The product reads data past the end, or before the beginning, of the intended buffer"},
	{Rank: 8, ID: "CWE-22", Name: "Path Traversal", Description: "The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize special elements"},
	{Rank: 9, ID: "CWE-352", Name: "Cross-Site Request Forgery", Description: "The web application does not sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user"},
	{Rank: 10, ID: "CWE-434", Name: "Unrestricted Upload of File with Dangerous Type", Description: "The product allows the upload of files with dangerous types that can be automatically processed within the product's environment"},
	{Rank: 11, ID: "CWE-862", Name: "Missing Authorization", Description: "The product does not perform an authorization check when an actor attempts to access a resource or perform an action"},
	{Rank: 12, ID: "CWE-476", Name: "NULL Pointer Dereference", Description: "The product dereferences a pointer that it expects to be valid but is NULL, typically causing a crash or exit"},
	{Rank: 13, ID: "CWE-287", Name: "Improper Authentication", Description: "The product does not prove or insufficiently proves that the claimed identity of an actor is correct"},
	{Rank: 14, ID: "CWE-190", Name: "Integer Overflow or Wraparound", Description: "The product performs a calculation that can produce an integer overflow or wraparound when the logic assumes the result will always be larger than the original value"},
	{Rank: 15, ID: "CWE-502", Name: "Deserialization of Untrusted Data", Description: "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid"},
	{Rank: 16, ID: "CWE-77", Name: "Command Injection", Description: "The product constructs all or part of a command using externally-influenced input but does not neutralize special elements that could modify the intended command"},
	{Rank: 17, ID: "CWE-119", Name: "Improper Restriction of Operations within the Bounds of a Memory Buffer", Description: "The product performs operations on a memory buffer but can read from or write to a memory location outside the intended boundary"},
	{Rank: 18, ID: "CWE-798", Name: "Use of Hard-coded Credentials", Description: "The product contains hard-coded credentials such as a password or cryptographic key for its own inbound or outbound authentication"},
	{Rank: 19, ID: "CWE-918", Name: "Server-Side Request Forgery", Description: "The web server receives a URL or similar request and retrieves the contents of this URL without ensuring that the request is being sent to the expected destination"},
	{Rank: 20, ID: "CWE-306", Name: "Missing Authentication for Critical Function", Description: "The product does not perform any authentication for functionality that requires a provable user identity"},
	{Rank: 21, ID: "CWE-362", Name: "Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)", Description: "The product contains a code sequence that can run concurrently with other code, and requires temporary exclusive access to a shared resource but does not properly synchronize"},
	{Rank: 22, ID: "CWE-269", Name: "Improper Privilege Management", Description: "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control"},
	{Rank: 23, ID: "CWE-94", Name: "Improper Control of Generation of Code (Code Injection)", Description: "The product constructs all or part of a code segment using externally-influenced input but does not neutralize special elements that could modify the code syntax"},
	{Rank: 24, ID: "CWE-863", Name: "Incorrect Authorization", Description: "The product performs an authorization check but does not correctly perform the check, allowing bypass of intended access restrictions"},
	{Rank: 25, ID: "CWE-276", Name: "Incorrect Default Permissions", Description: "During installation, the product sets incorrect permissions for an object that exposes it to an unintended actor"},
}

// CWETop25IDs provides a quick lookup set for whether a CWE ID is in the Top 25.
var CWETop25IDs = func() map[string]bool {
	m := make(map[string]bool, len(CWETop25))
	for _, entry := range CWETop25 {
		m[entry.ID] = true
	}
	return m
}()

// MapFindingsToCWETop25 maps a list of findings to CWE Top 25 entries,
// counts matches, and sets the status of each entry.
func MapFindingsToCWETop25(findings []models.Finding) []CWETop25Entry {
	// Clone the entries
	report := make([]CWETop25Entry, len(CWETop25))
	copy(report, CWETop25)

	for _, f := range findings {
		if f.CWE == "" {
			continue
		}
		cwe := strings.ToUpper(f.CWE)
		if !strings.HasPrefix(cwe, "CWE-") {
			cwe = "CWE-" + cwe
		}

		if CWETop25IDs[cwe] {
			for i := range report {
				if report[i].ID == cwe {
					report[i].FindingCount++
					break
				}
			}
		}
	}

	// Set status
	for i := range report {
		if report[i].FindingCount > 0 {
			report[i].Status = "fail"
		} else {
			report[i].Status = "pass"
		}
	}

	return report
}

// FormatCWETop25Report generates a text report from the CWE Top 25 mapping.
func FormatCWETop25Report(report []CWETop25Entry) string {
	var b strings.Builder
	b.WriteString("CWE Top 25 Most Dangerous Software Weaknesses (2024) — Compliance Report\n")
	b.WriteString(strings.Repeat("═", 80) + "\n\n")

	for _, entry := range report {
		icon := "✓"
		if entry.Status == "fail" {
			icon = "✗"
		}
		b.WriteString(fmt.Sprintf("%s  #%-2d  %-10s  %-55s  %d findings\n",
			icon, entry.Rank, entry.ID, entry.Name, entry.FindingCount))
	}

	return b.String()
}
