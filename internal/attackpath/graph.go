package attackpath

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"armur-codescanner/internal/models"
)

// AttackGraph represents the full attack graph for a scan.
type AttackGraph struct {
	Nodes []AttackNode `json:"nodes"`
	Edges []AttackEdge `json:"edges"`
	Paths []AttackPath `json:"paths"`
}

// AttackNode represents a node in the attack graph.
type AttackNode struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id,omitempty"`
	Type      string `json:"type"`     // entry_point, vulnerability, privilege, asset
	Label     string `json:"label"`
	Severity  string `json:"severity"`
}

// AttackEdge represents a directed edge between nodes.
type AttackEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Label     string `json:"label"`     // exploits, leads_to, escalates_to, accesses
	Technique string `json:"technique"` // MITRE ATT&CK ID if applicable
}

// AttackPath represents an ordered sequence through the graph.
type AttackPath struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	NodeIDs     []string `json:"node_ids"`
	Impact      string   `json:"impact"`
	Likelihood  string   `json:"likelihood"` // high, medium, low
	Description string   `json:"description"`
}

// ChainRule defines a vulnerability chaining pattern.
type ChainRule struct {
	Name        string
	RequiresCWE []string // CWEs that must be present
	Severity    string
	Impact      string
	Description string
}

// DefaultChainRules returns the built-in vulnerability chaining rules.
func DefaultChainRules() []ChainRule {
	return []ChainRule{
		{
			Name:        "SSRF → Cloud Credential Theft",
			RequiresCWE: []string{"CWE-918"},
			Severity:    "CRITICAL",
			Impact:      "AWS/GCP/Azure credential theft via cloud metadata endpoint",
			Description: "SSRF vulnerability can access cloud metadata services to steal IAM credentials",
		},
		{
			Name:        "SQL Injection → Full Database Access",
			RequiresCWE: []string{"CWE-89"},
			Severity:    "CRITICAL",
			Impact:      "Full database read/write access; data exfiltration",
			Description: "SQL injection enables UNION-based extraction of all database tables including credentials",
		},
		{
			Name:        "XSS → Session Hijacking",
			RequiresCWE: []string{"CWE-79"},
			Severity:    "HIGH",
			Impact:      "Session token theft; account takeover",
			Description: "Cross-site scripting can steal session cookies and hijack authenticated sessions",
		},
		{
			Name:        "Command Injection → Remote Code Execution",
			RequiresCWE: []string{"CWE-78"},
			Severity:    "CRITICAL",
			Impact:      "Full system compromise; reverse shell; lateral movement",
			Description: "OS command injection enables arbitrary code execution on the server",
		},
		{
			Name:        "Path Traversal → Configuration Disclosure",
			RequiresCWE: []string{"CWE-22"},
			Severity:    "HIGH",
			Impact:      "Read sensitive files: /etc/passwd, .env, config files with credentials",
			Description: "Path traversal vulnerability can read arbitrary files from the server filesystem",
		},
		{
			Name:        "Weak Crypto + Hardcoded Secret → Token Forgery",
			RequiresCWE: []string{"CWE-327", "CWE-798"},
			Severity:    "CRITICAL",
			Impact:      "JWT/session token forgery; authentication bypass",
			Description: "Weak cryptographic algorithm combined with a hardcoded secret enables token forgery",
		},
		{
			Name:        "Insecure Deserialization → Remote Code Execution",
			RequiresCWE: []string{"CWE-502"},
			Severity:    "CRITICAL",
			Impact:      "Arbitrary object instantiation; code execution",
			Description: "Unsafe deserialization of user-controlled data enables gadget chain exploitation",
		},
		{
			Name:        "SQL Injection + Weak Auth → Admin Access",
			RequiresCWE: []string{"CWE-89", "CWE-287"},
			Severity:    "CRITICAL",
			Impact:      "Full admin access; bypass authentication via SQL injection in login",
			Description: "SQL injection in authentication flow combined with weak auth enables admin impersonation",
		},
	}
}

// BuildGraph constructs an attack graph from scan findings using chain rules.
func BuildGraph(findings []models.Finding) *AttackGraph {
	graph := &AttackGraph{}

	// Build CWE index
	cweFindings := map[string][]models.Finding{}
	for _, f := range findings {
		if f.CWE != "" {
			cweFindings[f.CWE] = append(cweFindings[f.CWE], f)
		}
	}

	// Apply chain rules
	rules := DefaultChainRules()
	for _, rule := range rules {
		matchedFindings := matchRule(rule, cweFindings)
		if len(matchedFindings) == 0 {
			continue
		}

		// Create attack path
		path := buildPathFromRule(rule, matchedFindings)
		for _, node := range path.nodes {
			if !hasNode(graph, node.ID) {
				graph.Nodes = append(graph.Nodes, node)
			}
		}
		for _, edge := range path.edges {
			graph.Edges = append(graph.Edges, edge)
		}
		graph.Paths = append(graph.Paths, path.attackPath)
	}

	// Sort paths by score descending
	sort.Slice(graph.Paths, func(i, j int) bool {
		return graph.Paths[i].Score > graph.Paths[j].Score
	})

	return graph
}

type pathBuild struct {
	nodes      []AttackNode
	edges      []AttackEdge
	attackPath AttackPath
}

func matchRule(rule ChainRule, cweFindings map[string][]models.Finding) []models.Finding {
	var matched []models.Finding
	for _, cwe := range rule.RequiresCWE {
		if findings, ok := cweFindings[cwe]; ok {
			matched = append(matched, findings...)
		}
	}
	// For multi-CWE rules, require ALL CWEs present
	if len(rule.RequiresCWE) > 1 {
		for _, cwe := range rule.RequiresCWE {
			if _, ok := cweFindings[cwe]; !ok {
				return nil
			}
		}
	}
	return matched
}

func buildPathFromRule(rule ChainRule, findings []models.Finding) pathBuild {
	var nodes []AttackNode
	var edges []AttackEdge
	var nodeIDs []string

	// Entry point node
	entryID := nodeID("entry", "Internet User")
	nodes = append(nodes, AttackNode{
		ID:    entryID,
		Type:  "entry_point",
		Label: "Internet User",
	})
	nodeIDs = append(nodeIDs, entryID)

	prevID := entryID
	for _, f := range findings {
		vulnID := nodeID("vuln", f.ID)
		nodes = append(nodes, AttackNode{
			ID:        vulnID,
			FindingID: f.ID,
			Type:      "vulnerability",
			Label:     fmt.Sprintf("%s (%s:%d)", f.CWE, f.File, f.Line),
			Severity:  string(f.Severity),
		})
		edges = append(edges, AttackEdge{
			From:  prevID,
			To:    vulnID,
			Label: "exploits",
		})
		nodeIDs = append(nodeIDs, vulnID)
		prevID = vulnID
	}

	// Impact node
	impactID := nodeID("asset", rule.Impact)
	nodes = append(nodes, AttackNode{
		ID:       impactID,
		Type:     "asset",
		Label:    rule.Impact,
		Severity: rule.Severity,
	})
	edges = append(edges, AttackEdge{
		From:  prevID,
		To:    impactID,
		Label: "leads_to",
	})
	nodeIDs = append(nodeIDs, impactID)

	// Score the path
	score := scorePath(rule, findings)

	return pathBuild{
		nodes: nodes,
		edges: edges,
		attackPath: AttackPath{
			ID:          pathID(rule.Name),
			Name:        rule.Name,
			Severity:    rule.Severity,
			Score:       score,
			NodeIDs:     nodeIDs,
			Impact:      rule.Impact,
			Likelihood:  assessLikelihood(len(findings)),
			Description: rule.Description,
		},
	}
}

func scorePath(rule ChainRule, findings []models.Finding) float64 {
	baseScore := 5.0
	switch rule.Severity {
	case "CRITICAL":
		baseScore = 9.0
	case "HIGH":
		baseScore = 7.0
	case "MEDIUM":
		baseScore = 5.0
	}

	// Fewer steps = easier to exploit = higher score
	complexityFactor := 1.0
	if len(findings) <= 1 {
		complexityFactor = 1.5
	} else if len(findings) <= 3 {
		complexityFactor = 1.2
	}

	// Confirmed findings boost score
	confirmFactor := 1.0
	for _, f := range findings {
		if f.Confirmed {
			confirmFactor = 2.0
			break
		}
	}

	return baseScore * complexityFactor * confirmFactor
}

func assessLikelihood(steps int) string {
	if steps <= 1 {
		return "high"
	}
	if steps <= 3 {
		return "medium"
	}
	return "low"
}

func nodeID(prefix, data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%s_%x", prefix, hash[:8])
}

func pathID(name string) string {
	hash := sha256.Sum256([]byte(name))
	return fmt.Sprintf("path_%x", hash[:8])
}

func hasNode(graph *AttackGraph, id string) bool {
	for _, n := range graph.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// ToMermaid generates a Mermaid flowchart diagram from an attack path.
func (p *AttackPath) ToMermaid(graph *AttackGraph) string {
	var b strings.Builder
	b.WriteString("graph LR\n")

	for i, nodeID := range p.NodeIDs {
		node := findNode(graph, nodeID)
		if node == nil {
			continue
		}

		label := strings.ReplaceAll(node.Label, "\"", "'")
		b.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", nodeID, label))

		// Style based on type
		switch node.Type {
		case "vulnerability":
			b.WriteString(fmt.Sprintf("    style %s fill:#ff4444,color:#fff\n", nodeID))
		case "asset":
			b.WriteString(fmt.Sprintf("    style %s fill:#ff0000,color:#fff\n", nodeID))
		case "entry_point":
			b.WriteString(fmt.Sprintf("    style %s fill:#4488ff,color:#fff\n", nodeID))
		}

		// Edge to next node
		if i < len(p.NodeIDs)-1 {
			nextID := p.NodeIDs[i+1]
			edge := findEdge(graph, nodeID, nextID)
			edgeLabel := ""
			if edge != nil {
				edgeLabel = edge.Label
			}
			b.WriteString(fmt.Sprintf("    %s -->|%s| %s\n", nodeID, edgeLabel, nextID))
		}
	}

	return b.String()
}

func findNode(graph *AttackGraph, id string) *AttackNode {
	for i := range graph.Nodes {
		if graph.Nodes[i].ID == id {
			return &graph.Nodes[i]
		}
	}
	return nil
}

func findEdge(graph *AttackGraph, from, to string) *AttackEdge {
	for i := range graph.Edges {
		if graph.Edges[i].From == from && graph.Edges[i].To == to {
			return &graph.Edges[i]
		}
	}
	return nil
}
