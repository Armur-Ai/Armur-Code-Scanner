package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TechProfile describes the detected technology stack of a project.
type TechProfile struct {
	Language     string   `json:"language"`
	Framework    string   `json:"framework"`
	BuildSystem  string   `json:"build_system"`
	BuildCommand string   `json:"build_command"`
	RunCommand   string   `json:"run_command"`
	Port         int      `json:"port"`
	Databases    []string `json:"databases"`
	EnvVars      []string `json:"env_vars"`
}

// DetectTechStack analyzes a project directory and returns a TechProfile.
// Uses AI when available for better detection; falls back to heuristics.
func DetectTechStack(ctx context.Context, dirPath string, provider AIProvider) (*TechProfile, error) {
	// First try heuristic detection
	profile := heuristicDetect(dirPath)

	// If AI is available, enhance the detection
	if provider != nil && provider.Available() {
		enhanced, err := aiEnhancedDetect(ctx, dirPath, provider)
		if err == nil && enhanced != nil {
			// Merge AI results with heuristic results
			if enhanced.Framework != "" {
				profile.Framework = enhanced.Framework
			}
			if enhanced.RunCommand != "" {
				profile.RunCommand = enhanced.RunCommand
			}
			if enhanced.Port != 0 {
				profile.Port = enhanced.Port
			}
			if len(enhanced.Databases) > 0 {
				profile.Databases = enhanced.Databases
			}
		}
	}

	return profile, nil
}

func heuristicDetect(dirPath string) *TechProfile {
	p := &TechProfile{Port: 8080}

	// Go
	if fileExists(dirPath, "go.mod") {
		p.Language = "go"
		p.BuildSystem = "go"
		p.BuildCommand = "go build -o app ."
		p.RunCommand = "./app"
		if containsText(dirPath, "go.mod", "gin-gonic/gin") {
			p.Framework = "gin"
		} else if containsText(dirPath, "go.mod", "gorilla/mux") {
			p.Framework = "gorilla"
		} else if containsText(dirPath, "go.mod", "labstack/echo") {
			p.Framework = "echo"
		}
	}

	// Python
	if fileExists(dirPath, "requirements.txt") || fileExists(dirPath, "pyproject.toml") {
		p.Language = "python"
		p.BuildSystem = "pip"
		p.BuildCommand = "pip install -r requirements.txt"
		if fileExists(dirPath, "manage.py") {
			p.Framework = "django"
			p.RunCommand = "python manage.py runserver 0.0.0.0:8000"
			p.Port = 8000
		} else if containsAnyFile(dirPath, "requirements.txt", "fastapi", "uvicorn") {
			p.Framework = "fastapi"
			p.RunCommand = "uvicorn main:app --host 0.0.0.0 --port 8000"
			p.Port = 8000
		} else if containsAnyFile(dirPath, "requirements.txt", "flask") {
			p.Framework = "flask"
			p.RunCommand = "flask run --host 0.0.0.0"
			p.Port = 5000
		}
	}

	// Node.js
	if fileExists(dirPath, "package.json") {
		p.Language = "javascript"
		p.BuildSystem = "npm"
		p.BuildCommand = "npm install"
		p.RunCommand = "npm start"
		p.Port = 3000
		if fileExists(dirPath, "next.config.js") || fileExists(dirPath, "next.config.mjs") {
			p.Framework = "nextjs"
		} else if containsText(dirPath, "package.json", "express") {
			p.Framework = "express"
		} else if containsText(dirPath, "package.json", "@nestjs") {
			p.Framework = "nestjs"
		}
	}

	// Java
	if fileExists(dirPath, "pom.xml") {
		p.Language = "java"
		p.BuildSystem = "maven"
		p.BuildCommand = "mvn package -DskipTests"
		p.RunCommand = "java -jar target/*.jar"
		p.Framework = "spring-boot"
		p.Port = 8080
	} else if fileExists(dirPath, "build.gradle") || fileExists(dirPath, "build.gradle.kts") {
		p.Language = "java"
		p.BuildSystem = "gradle"
		p.BuildCommand = "gradle build -x test"
		p.RunCommand = "java -jar build/libs/*.jar"
		p.Framework = "spring-boot"
		p.Port = 8080
	}

	// Ruby
	if fileExists(dirPath, "Gemfile") {
		p.Language = "ruby"
		p.BuildSystem = "bundler"
		p.BuildCommand = "bundle install"
		if fileExists(dirPath, "config.ru") {
			p.Framework = "rails"
			p.RunCommand = "rails server -b 0.0.0.0"
			p.Port = 3000
		}
	}

	// Rust
	if fileExists(dirPath, "Cargo.toml") {
		p.Language = "rust"
		p.BuildSystem = "cargo"
		p.BuildCommand = "cargo build --release"
		p.RunCommand = "./target/release/*"
	}

	return p
}

func aiEnhancedDetect(ctx context.Context, dirPath string, provider AIProvider) (*TechProfile, error) {
	// Gather key file contents for AI analysis
	var fileInfo strings.Builder
	for _, name := range []string{"go.mod", "package.json", "requirements.txt", "pyproject.toml", "pom.xml", "Dockerfile", "docker-compose.yml"} {
		content, err := os.ReadFile(filepath.Join(dirPath, name))
		if err == nil {
			if len(content) > 2000 {
				content = content[:2000]
			}
			fileInfo.WriteString(fmt.Sprintf("--- %s ---\n%s\n\n", name, string(content)))
		}
	}

	if fileInfo.Len() == 0 {
		return nil, fmt.Errorf("no manifest files found")
	}

	prompt := fmt.Sprintf(`Analyze this project and return a JSON object with:
- framework: the web framework being used (e.g., "gin", "express", "django", "spring-boot")
- run_command: the exact command to run this project
- port: the port it listens on (as a number)
- databases: array of database types used (e.g., ["postgresql", "redis"])

Return ONLY valid JSON, no explanation.

Project files:
%s`, fileInfo.String())

	resp, err := provider.Complete(ctx, prompt, CompletionOpts{
		MaxTokens:   512,
		Temperature: 0.1,
	})
	if err != nil {
		return nil, err
	}

	var profile TechProfile
	if err := json.Unmarshal([]byte(resp), &profile); err != nil {
		// Try extracting JSON from markdown code block
		if idx := strings.Index(resp, "{"); idx >= 0 {
			if end := strings.LastIndex(resp, "}"); end > idx {
				json.Unmarshal([]byte(resp[idx:end+1]), &profile)
			}
		}
	}
	return &profile, nil
}

func fileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func containsText(dir, filename, text string) bool {
	content, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return false
	}
	return strings.Contains(string(content), text)
}

func containsAnyFile(dir, filename string, texts ...string) bool {
	content, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return false
	}
	s := string(content)
	for _, t := range texts {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
