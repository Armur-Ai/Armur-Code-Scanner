package agent

import (
	"context"
	"fmt"
	"time"
)

// ScanMode represents the depth of analysis the agent performs.
type ScanMode string

const (
	ModeSASTOnly  ScanMode = "sast_only"
	ModeSASTSCA   ScanMode = "sast_sca"
	ModeFullAgent ScanMode = "full_agent" // SAST + DAST + Exploit Simulation
)

// AgentConfig controls the security agent's behavior.
type AgentConfig struct {
	Mode          ScanMode `yaml:"mode" json:"mode"`
	AutoDAST      bool     `yaml:"auto_dast" json:"auto_dast"`
	AutoExploit   bool     `yaml:"auto_exploit" json:"auto_exploit"`
	Watch         bool     `yaml:"watch" json:"watch"`
	PRReview      bool     `yaml:"pr_review" json:"pr_review"`
}

// DefaultConfig returns sensible defaults for the agent.
func DefaultConfig() AgentConfig {
	return AgentConfig{
		Mode:        ModeSASTSCA,
		AutoDAST:    false,
		AutoExploit: false,
		Watch:       false,
		PRReview:    false,
	}
}

// Pipeline represents the full agent analysis pipeline.
type Pipeline struct {
	Config  AgentConfig
	Target  string
	Started time.Time
	Stages  []Stage
}

// Stage represents one phase of the agent pipeline.
type Stage struct {
	Name    string
	Status  string // "pending", "running", "completed", "failed", "skipped"
	Started time.Time
	Ended   time.Time
}

// NewPipeline creates a new agent pipeline for a target.
func NewPipeline(target string, cfg AgentConfig) *Pipeline {
	stages := []Stage{
		{Name: "SAST Analysis", Status: "pending"},
		{Name: "SCA Check", Status: "pending"},
	}

	if cfg.AutoDAST || cfg.Mode == ModeFullAgent {
		stages = append(stages, Stage{Name: "DAST (Sandbox)", Status: "pending"})
	}

	if cfg.AutoExploit || cfg.Mode == ModeFullAgent {
		stages = append(stages, Stage{Name: "Exploit Simulation", Status: "pending"})
	}

	// Attack path analysis always runs if DAST or exploits run
	if cfg.AutoDAST || cfg.AutoExploit || cfg.Mode == ModeFullAgent {
		stages = append(stages, Stage{Name: "Attack Path Analysis", Status: "pending"})
	}

	return &Pipeline{
		Config:  cfg,
		Target:  target,
		Started: time.Now(),
		Stages:  stages,
	}
}

// Run executes the full agent pipeline.
func (p *Pipeline) Run(ctx context.Context) error {
	for i := range p.Stages {
		select {
		case <-ctx.Done():
			p.Stages[i].Status = "cancelled"
			return ctx.Err()
		default:
		}

		p.Stages[i].Status = "running"
		p.Stages[i].Started = time.Now()

		var err error
		switch p.Stages[i].Name {
		case "SAST Analysis":
			err = p.runSAST(ctx)
		case "SCA Check":
			err = p.runSCA(ctx)
		case "DAST (Sandbox)":
			err = p.runDAST(ctx)
		case "Exploit Simulation":
			err = p.runExploitSim(ctx)
		case "Attack Path Analysis":
			err = p.runAttackPaths(ctx)
		}

		p.Stages[i].Ended = time.Now()
		if err != nil {
			p.Stages[i].Status = "failed"
			// Don't fail the whole pipeline on one stage failure
			continue
		}
		p.Stages[i].Status = "completed"
	}

	return nil
}

// Placeholder implementations — these will be filled in by Sprints 16-20.

func (p *Pipeline) runSAST(ctx context.Context) error {
	// This calls the existing RunSimpleScan/RunAdvancedScans pipeline
	fmt.Println("Running SAST analysis...")
	return nil
}

func (p *Pipeline) runSCA(ctx context.Context) error {
	fmt.Println("Running SCA dependency check...")
	return nil
}

func (p *Pipeline) runDAST(ctx context.Context) error {
	// Sprint 17: Sandboxed DAST
	fmt.Println("Running DAST in sandbox...")
	return nil
}

func (p *Pipeline) runExploitSim(ctx context.Context) error {
	// Sprint 18: Exploit Simulation
	fmt.Println("Running exploit simulation...")
	return nil
}

func (p *Pipeline) runAttackPaths(ctx context.Context) error {
	// Sprint 19: Attack Path Analysis
	fmt.Println("Analyzing attack paths...")
	return nil
}
