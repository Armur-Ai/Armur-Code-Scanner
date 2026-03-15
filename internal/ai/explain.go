package ai

import (
	"context"
	"fmt"
)

// ExplainFinding generates a plain-English explanation of a security finding.
func ExplainFinding(ctx context.Context, provider AIProvider, finding map[string]string) (string, error) {
	prompt := fmt.Sprintf(`You are a senior security engineer explaining a vulnerability to a developer.
Be concise, practical, and actionable. Format your response in four sections:

**What it is**: One sentence description of this vulnerability class.
**Why it matters**: Real-world impact — what can an attacker do?
**Attack scenario**: A short, realistic attack walkthrough for this specific code.
**How to fix**: Concrete code change recommendation.

Here is the finding:
- File: %s (line %s)
- Severity: %s
- CWE: %s
- Tool: %s
- Message: %s
- Code context: %s`,
		finding["file"], finding["line"],
		finding["severity"], finding["cwe"],
		finding["tool"], finding["message"],
		finding["snippet"],
	)

	return provider.Complete(ctx, prompt, CompletionOpts{
		MaxTokens:   1024,
		Temperature: 0.3,
		SystemPrompt: "You are Armur, a personal security agent. Explain vulnerabilities clearly and concisely for developers.",
	})
}

// GenerateFix generates a code patch to fix a security finding.
func GenerateFix(ctx context.Context, provider AIProvider, finding map[string]string, codeContext string) (string, error) {
	prompt := fmt.Sprintf(`You are a senior security engineer. Generate a minimal code patch that fixes ONLY the reported security issue without changing functionality.

Output a unified diff format patch.

Finding:
- File: %s (line %s)
- Severity: %s
- CWE: %s
- Message: %s

Code context (±10 lines around the issue):
%s

Generate ONLY the diff patch, nothing else.`,
		finding["file"], finding["line"],
		finding["severity"], finding["cwe"],
		finding["message"], codeContext,
	)

	return provider.Complete(ctx, prompt, CompletionOpts{
		MaxTokens:   2048,
		Temperature: 0.2,
		SystemPrompt: "You are Armur, a personal security agent. Generate minimal, safe code patches.",
	})
}
