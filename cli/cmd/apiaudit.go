package cmd

import (
	"armur-cli/internal/config"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Send a vulnerability/codefix/documentation audit request",
	Long:  "Interactively send content to the /apiaudit/audit/create endpoint and receive results.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Failed to load config: %v", err)
			os.Exit(1)
		}

		var auditType, content string

		var tokenStr, temperature string

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Select the audit type").
					Options(
						huh.NewOption("Vulnerability", "Vulnerability"),
						huh.NewOption("Audit", "Audit"),
						huh.NewOption("Optimization", "Optimization"),
						huh.NewOption("Codefix", "Codefix"),
						huh.NewOption("Documentation", "Documentation"),
					).
					Value(&auditType),
				huh.NewText().
					Title("Enter the code/content to analyze").
					Value(&content),

				huh.NewInput().
					Title("Token Count (e.g. 200)").
					Value(&tokenStr).
					Validate(func(val string) error {
						t, err := strconv.Atoi(val)
						if err != nil || t <= 0 {
							return fmt.Errorf("enter a valid positive number")
						}
						return nil
					}),

				huh.NewInput().
					Title("Temperature (0.0 to 1.0)").
					Value(&temperature).
					Validate(func(val string) error {
						f, err := strconv.ParseFloat(val, 64)
						if err != nil || f < 0.0 || f > 1.0 {
							return fmt.Errorf("temperature must be between 0.0 and 1.0")
						}
						return nil
					}),
			),
		)

		if err := form.Run(); err != nil {
			fmt.Println("Prompt canceled.")
			return
		}

		apiURL := fmt.Sprintf("https://api.armur.ai/go/apiaudit/audit/create?data=%s", url.QueryEscape(auditType))

		formData := url.Values{}
		formData.Set("content", content)
		formData.Set("token", tokenStr)

		fTemp, err := strconv.ParseFloat(temperature, 64)
		if err != nil {
			color.Red("Invalid temperature: %v", err)
			os.Exit(1)
		}
		formData.Set("temperature", fmt.Sprintf("%0.1f", fTemp))

		client := &http.Client{}
		req, err := http.NewRequest("POST", apiURL, strings.NewReader(formData.Encode()))
		if err != nil {
			color.Red("Failed to create request: %v", err)
			os.Exit(1)
		}

		req.Header.Add("Authorization", "Bearer "+cfg.APIKey)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			color.Red("Request failed: %v", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			color.Red("Failed to read response: %v", err)
			os.Exit(1)
		}

		fmt.Println(color.CyanString("=== API Response ==="))
		fmt.Println(string(body))
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
}
