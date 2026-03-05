package cmd

import (
	"armur-cli/internal/config"
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config [key] [value]",
	Short: "Manage CLI configuration",
	Long:  `Manage the configuration settings for the Armur CLI.`,
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Error loading configuration: %v", err)
			os.Exit(1)
		}

		// CLI mode: user passed key and value
		if len(args) == 2 {
			key, value := args[0], args[1]

			if !setConfigValue(cfg, key, value) {
				color.Red("Invalid configuration key: %s", key)
				os.Exit(1)
			}

			if err := config.SaveConfig(cfg); err != nil {
				color.Red("Error saving configuration: %v", err)
				os.Exit(1)
			}

			fmt.Println(color.GreenString("Configuration updated successfully."))
			return
		}

		// Interactive mode
		configAction()
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

func configAction() {
	cfg, err := config.LoadConfig()
	if err != nil {
		color.Red("Error loading configuration: %v", err)
		os.Exit(1)
	}

	var key, value string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Which config value would you like to set?").
				Options(
					huh.NewOption("API URL", "api_url"),
					huh.NewOption("Redis URL", "redis_url"),
					huh.NewOption("API Key", "api_key"),
				).
				Value(&key),
			huh.NewInput().
				Title("Enter the new value").
				Value(&value),
		),
	)

	if err := form.Run(); err != nil {
		fmt.Println("Prompt canceled.")
		return
	}

	if !setConfigValue(cfg, key, value) {
		color.Red("Invalid configuration key.")
		os.Exit(1)
	}

	if err := config.SaveConfig(cfg); err != nil {
		color.Red("Error saving configuration: %v", err)
		os.Exit(1)
	}

	fmt.Println(color.GreenString("Configuration updated successfully."))
}

func setConfigValue(cfg *config.Config, key, value string) bool {
	switch key {
	case "api_url":
		cfg.API.URL = value
	case "redis_url":
		cfg.Redis.URL = value
	case "api_key":
		cfg.APIKey = value
	default:
		return false
	}
	return true
}
