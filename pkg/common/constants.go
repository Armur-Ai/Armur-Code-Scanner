// internal/common/constants.go
package pkg

// LanguageFileExtensions maps programming languages to their file extensions
var LanguageFileExtensions = map[string][]string{
	"py": {
		".py",    // Python files
		".pyc",   // Compiled Python files
		".pyo",   // Optimized Python files
		".pyd",   // Python extension modules
		".ipynb", // Jupyter Notebook files
	},
	"js": {
		".js",   // JavaScript files
		".jsx",  // React JavaScript files
		".mjs",  // ES module JavaScript files
		".json", // JSON files
		".ts",   // TypeScript files
		".tsx",  // React TypeScript files
		".html", // HTML templates
		".css",  // CSS files
		".scss", // SCSS files
		".less", // LESS files
		".sass", // SASS files
	},
	"go": {
		".go",    // Go source files
		".mod",   // Go module files
		".sum",   // Go module sum files
		".cgo",   // Go Cgo files
		".proto", // Protocol Buffer files
	},
	"rust": {
		".rs",   // Rust source files
		".toml", // Cargo.toml
	},
	"java": {
		".java",   // Java source files
		".kt",     // Kotlin source files
		".kts",    // Kotlin script files
		".gradle", // Gradle build files
		".xml",    // Maven pom.xml
	},
	"ruby": {
		".rb",   // Ruby source files
		".rake", // Rake task files
		".gemspec", // Gem spec files
	},
	"php": {
		".php",  // PHP source files
		".phtml", // PHP HTML templates
	},
	"c": {
		".c",   // C source files
		".h",   // C header files
		".cpp", // C++ source files
		".cc",  // C++ source files
		".cxx", // C++ source files
		".hpp", // C++ header files
	},
	"iac": {
		".tf",      // Terraform files
		".tfvars",  // Terraform variable files
		".yaml",    // YAML (k8s, Ansible, etc.)
		".yml",     // YAML (k8s, Ansible, etc.)
		".json",    // JSON config files
	},
	"sol": {
		".sol", // Solidity smart contract files
	},
}

const (
	// General constants
	Unknown = "UNKNOWN"

	// Issue categories
	DocstringAbsent  = "docstring_absent"
	SecurityIssues   = "security_issues"
	ComplexFunctions = "complex_functions"
	AntipatternsBugs = "antipatterns_bugs"
	SCA              = "sca"

	// Advanced categories
	DeadCode        = "dead_code"
	DuplicateCode   = "duplicate_code"
	SecretDetection = "secret_detection"
	InfraSecurity   = "infra_security"

	// Thresholds
	DuplicateCodeLineThreshold = 25
)
