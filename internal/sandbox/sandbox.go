package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"armur-codescanner/internal/ai"
	"armur-codescanner/internal/logger"
)

// Sandbox represents an isolated execution environment for DAST testing.
type Sandbox struct {
	ID          string
	ProjectPath string
	TechProfile *ai.TechProfile
	ContainerID string
	Port        int
	BaseURL     string
	Status      string // "creating", "building", "running", "healthy", "failed", "destroyed"
	tempDir     string
}

// Create creates a new sandbox for the given project.
func Create(ctx context.Context, projectPath string, profile *ai.TechProfile) (*Sandbox, error) {
	s := &Sandbox{
		ID:          fmt.Sprintf("sandbox-%d", time.Now().UnixNano()),
		ProjectPath: projectPath,
		TechProfile: profile,
		Status:      "creating",
	}

	// Find an available port
	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("no free port: %w", err)
	}
	s.Port = port
	s.BaseURL = fmt.Sprintf("http://localhost:%d", port)

	// Create temp dir for generated Dockerfile if needed
	s.tempDir = filepath.Join(os.TempDir(), s.ID)
	os.MkdirAll(s.tempDir, 0755)

	return s, nil
}

// Build builds the project inside a Docker container.
func (s *Sandbox) Build(ctx context.Context) error {
	s.Status = "building"

	// Check if project already has a Dockerfile
	dockerfilePath := filepath.Join(s.ProjectPath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		// Generate a Dockerfile based on the tech profile
		generated := generateDockerfile(s.TechProfile)
		dockerfilePath = filepath.Join(s.tempDir, "Dockerfile")
		if err := os.WriteFile(dockerfilePath, []byte(generated), 0644); err != nil {
			return fmt.Errorf("failed to write generated Dockerfile: %w", err)
		}
		logger.Info().Str("sandbox", s.ID).Msg("generated Dockerfile for sandbox")
	}

	// Build the Docker image
	cmd := exec.CommandContext(ctx, "docker", "build",
		"-t", s.ID,
		"-f", dockerfilePath,
		"--memory=2g",
		"--cpu-period=100000",
		"--cpu-quota=200000", // 2 CPUs
		s.ProjectPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Status = "failed"
		return fmt.Errorf("docker build failed: %w\n%s", err, string(output))
	}

	return nil
}

// Start starts the container and maps the port.
func (s *Sandbox) Start(ctx context.Context) error {
	s.Status = "running"

	appPort := s.TechProfile.Port
	if appPort == 0 {
		appPort = 8080
	}

	args := []string{
		"run", "-d",
		"--name", s.ID,
		"--memory=2g",
		"--cpus=2",
		"--network=none", // No external network access
		"-p", fmt.Sprintf("%d:%d", s.Port, appPort),
	}

	// Add environment variables
	for _, env := range s.TechProfile.EnvVars {
		args = append(args, "-e", env)
	}
	// Add safe defaults for common env vars
	args = append(args, "-e", "NODE_ENV=test")
	args = append(args, "-e", "RAILS_ENV=test")
	args = append(args, "-e", "DJANGO_SETTINGS_MODULE=config.settings.test")

	args = append(args, s.ID)

	if s.TechProfile.RunCommand != "" {
		args = append(args, "sh", "-c", s.TechProfile.RunCommand)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Status = "failed"
		return fmt.Errorf("docker run failed: %w\n%s", err, string(output))
	}

	s.ContainerID = strings.TrimSpace(string(output))
	return nil
}

// WaitHealthy waits for the application to be ready.
func (s *Sandbox) WaitHealthy(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	healthPaths := []string{"/", "/health", "/healthz", "/api/health", "/ping", "/ready"}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try TCP connect first
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", s.Port), 500*time.Millisecond)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		conn.Close()

		// Try HTTP health checks
		for _, path := range healthPaths {
			cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
				"--max-time", "2", fmt.Sprintf("http://localhost:%d%s", s.Port, path))
			out, err := cmd.Output()
			if err == nil {
				code, _ := strconv.Atoi(strings.TrimSpace(string(out)))
				if code > 0 && code < 500 {
					s.Status = "healthy"
					logger.Info().Str("sandbox", s.ID).Int("port", s.Port).Str("path", path).Msg("sandbox is healthy")
					return nil
				}
			}
		}

		time.Sleep(1 * time.Second)
	}

	s.Status = "failed"
	return fmt.Errorf("sandbox not healthy after %v", timeout)
}

// Destroy removes the container and cleans up.
func (s *Sandbox) Destroy(ctx context.Context) error {
	s.Status = "destroyed"

	// Stop and remove container
	exec.CommandContext(ctx, "docker", "stop", s.ID).Run()
	exec.CommandContext(ctx, "docker", "rm", "-f", s.ID).Run()

	// Remove image
	exec.CommandContext(ctx, "docker", "rmi", s.ID).Run()

	// Clean up temp dir
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}

	return nil
}

// generateDockerfile creates a Dockerfile based on the detected tech profile.
func generateDockerfile(profile *ai.TechProfile) string {
	switch profile.Language {
	case "go":
		return `FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o app .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/app .
EXPOSE 8080
CMD ["./app"]`

	case "python":
		port := profile.Port
		if port == 0 {
			port = 8000
		}
		return fmt.Sprintf(`FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE %d
CMD ["%s"]`, port, profile.RunCommand)

	case "javascript":
		return `FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]`

	case "java":
		return `FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY . .
RUN mvn package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]`

	case "ruby":
		return `FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install
COPY . .
EXPOSE 3000
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"]`

	case "rust":
		return `FROM rust:1.76 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/* .
EXPOSE 8080
CMD ["./app"]`

	default:
		return fmt.Sprintf(`FROM ubuntu:22.04
WORKDIR /app
COPY . .
EXPOSE %d
CMD ["%s"]`, profile.Port, profile.RunCommand)
	}
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
