package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for armur.

To load completions:

Bash:
  $ source <(vibescan completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ vibescan completion bash > /etc/bash_completion.d/armur
  # macOS:
  $ vibescan completion bash > $(brew --prefix)/etc/bash_completion.d/armur

Zsh:
  $ source <(vibescan completion zsh)
  # To load completions for each session, execute once:
  $ vibescan completion zsh > "${fpath[1]}/_armur"

Fish:
  $ vibescan completion fish | source
  # To load completions for each session, execute once:
  $ vibescan completion fish > ~/.config/fish/completions/armur.fish

PowerShell:
  PS> vibescan completion powershell | Out-String | Invoke-Expression
  # To load completions for each session, add to your profile:
  PS> vibescan completion powershell > armur.ps1 && . ./armur.ps1
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
