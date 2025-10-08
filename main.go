package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// OpenVEX document structure
type OpenVEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Time       time.Time      `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

type VEXStatement struct {
	Vulnerability       VEXVulnerability `json:"vulnerability"`
	Time                time.Time        `json:"timestamp"`
	Products            []VEXProduct     `json:"products"`
	Status              string           `json:"status"`
	Justification       *string          `json:"justification,omitempty"`
	ActionStatement     *string          `json:"action_statement,omitempty"`
	ActionStatementTime *time.Time       `json:"action_statement_timestamp,omitempty"`
}

type VEXVulnerability struct {
	Name string `json:"name"`
}

type VEXProduct struct {
	ID            string            `json:"@id"`
	Subcomponents []VEXSubcomponent `json:"subcomponents,omitempty"`
}

type VEXSubcomponent struct {
	ID string `json:"@id"`
}

// Vulnerability represents a found vulnerability
type Vulnerability struct {
	ID          string                 `json:"id"`
	Package     string                 `json:"package"`
	Version     string                 `json:"version"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	References  []string               `json:"references"`
	CVSS        map[string]interface{} `json:"cvss"`
	Published   string                 `json:"published"`
	Modified    string                 `json:"modified"`
}

// Trivexer represents the main application
type Trivexer struct {
	imageName  string
	verbose    bool
	outputFile string
	author     string
}

// Status justifications for not_affected status
var notAffectedJustifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Status options
var statusOptions = []string{
	"not_affected",
	"affected",
	"fixed",
	"under_investigation",
}

func main() {
	var trivexer Trivexer

	rootCmd := &cobra.Command{
		Use:   "trivexer <image>",
		Short: "Trivexer - Container vulnerability scanner and VEX document generator",
		Long: `Trivexer scans container images for vulnerabilities using Trivy and generates 
OpenVEX documents for selected vulnerabilities.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			trivexer.imageName = args[0]
			if err := trivexer.Run(); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().BoolVarP(&trivexer.verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().StringVarP(&trivexer.outputFile, "output", "o", "", "Output file for VEX document")
	rootCmd.Flags().StringVar(&trivexer.author, "author", "", "Author for VEX document")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func (t *Trivexer) Run() error {
	fmt.Println("🔍 Trivexer - Container Vulnerability Scanner")
	fmt.Println(strings.Repeat("=", 50))

	// Check if trivy is available
	if err := t.checkDependencies(); err != nil {
		return err
	}

	// Scan the image
	fmt.Printf("\n📦 Scanning image: %s\n", t.imageName)
	vulnerabilities, err := t.scanImage()
	if err != nil {
		return fmt.Errorf("failed to scan image: %w", err)
	}

	if len(vulnerabilities) == 0 {
		fmt.Println("✅ No vulnerabilities found!")
		return nil
	}

	// Display vulnerabilities
	t.displayVulnerabilities(vulnerabilities)

	// Select vulnerability
	selectedVuln, err := t.selectVulnerability(vulnerabilities)
	if err != nil {
		return fmt.Errorf("failed to select vulnerability: %w", err)
	}
	if selectedVuln == nil {
		fmt.Println("❌ No vulnerability selected")
		return nil
	}

	// Display vulnerability details
	t.displayVulnerabilityDetails(selectedVuln)

	// Get author if not provided
	if t.author == "" {
		t.author = t.getAuthor()
	}

	// Get status and generate VEX
	vexDoc, err := t.generateVEXDocument(selectedVuln)
	if err != nil {
		return fmt.Errorf("failed to generate VEX document: %w", err)
	}

	// Save or display VEX document
	if t.outputFile != "" {
		if err := t.saveVEXDocument(vexDoc); err != nil {
			return fmt.Errorf("failed to save VEX document: %w", err)
		}
		fmt.Printf("📁 VEX document saved to: %s\n", t.outputFile)
	} else {
		fmt.Println("\n📄 Generated VEX Document:")
		fmt.Println(strings.Repeat("-", 40))
		vexJSON, _ := json.MarshalIndent(vexDoc, "", "  ")
		fmt.Println(string(vexJSON))
	}

	return nil
}

func (t *Trivexer) checkDependencies() error {
	// Check trivy
	if _, err := exec.LookPath("trivy"); err != nil {
		return fmt.Errorf("trivy not found. Please install trivy: https://github.com/aquasecurity/trivy#installation")
	}

	if t.verbose {
		fmt.Println("✅ Trivy is available")
	}
	return nil
}

func (t *Trivexer) scanImage() ([]Vulnerability, error) {
	// Run trivy scan
	cmd := exec.Command("trivy", "image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM,LOW", t.imageName)

	if t.verbose {
		fmt.Printf("Running command: %s\n", cmd.String())
	}

	output, err := cmd.Output()
	if err != nil {
		if t.verbose {
			fmt.Printf("Trivy error: %v\n", err)
		}
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	if t.verbose {
		fmt.Printf("Trivy output length: %d bytes\n", len(output))
	}

	// Parse trivy output
	var scanResults map[string]interface{}
	if err := json.Unmarshal(output, &scanResults); err != nil {
		if t.verbose {
			fmt.Printf("Failed to parse JSON: %v\n", err)
			fmt.Printf("Raw output: %s\n", string(output))
		}
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	if t.verbose {
		fmt.Printf("Scan results keys: %v\n", getMapKeys(scanResults))
	}

	// Extract vulnerabilities
	var vulnerabilities []Vulnerability
	if results, ok := scanResults["Results"].([]interface{}); ok {
		if t.verbose {
			fmt.Printf("Found %d result groups\n", len(results))
		}

		for i, result := range results {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if t.verbose {
					fmt.Printf("Result %d keys: %v\n", i, getMapKeys(resultMap))
				}

				if vulns, ok := resultMap["Vulnerabilities"].([]interface{}); ok {
					if t.verbose {
						fmt.Printf("Found %d vulnerabilities in result %d\n", len(vulns), i)
					}

					for j, vuln := range vulns {
						if vulnMap, ok := vuln.(map[string]interface{}); ok {
							vulnerability := Vulnerability{
								ID:          getString(vulnMap, "VulnerabilityID"),
								Package:     getString(vulnMap, "PkgName"),
								Version:     getString(vulnMap, "InstalledVersion"),
								Severity:    getString(vulnMap, "Severity"),
								Title:       getString(vulnMap, "Title"),
								Description: getString(vulnMap, "Description"),
							}

							if t.verbose && vulnerability.ID != "" {
								fmt.Printf("Vulnerability %d: %s (%s)\n", j, vulnerability.ID, vulnerability.Severity)
							}

							// Extract references
							if refs, ok := vulnMap["References"].([]interface{}); ok {
								for _, ref := range refs {
									if refStr, ok := ref.(string); ok {
										vulnerability.References = append(vulnerability.References, refStr)
									}
								}
							}

							// Extract CVSS
							if cvss, ok := vulnMap["CVSS"].(map[string]interface{}); ok {
								vulnerability.CVSS = cvss
							}

							// Only add if we have a valid vulnerability ID
							if vulnerability.ID != "" {
								vulnerabilities = append(vulnerabilities, vulnerability)
							}
						}
					}
				}
			}
		}
	} else {
		if t.verbose {
			fmt.Printf("No 'Results' key found in scan output\n")
		}
	}

	if t.verbose {
		fmt.Printf("Total vulnerabilities found: %d\n", len(vulnerabilities))
	}

	// Sort by severity
	sort.Slice(vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
		return severityOrder[vulnerabilities[i].Severity] < severityOrder[vulnerabilities[j].Severity]
	})

	return vulnerabilities, nil
}

func (t *Trivexer) displayVulnerabilities(vulnerabilities []Vulnerability) {
	fmt.Printf("\n🔍 Found %d vulnerabilities:\n", len(vulnerabilities))
	fmt.Println(strings.Repeat("=", 120))
	fmt.Printf("%-3s %-20s %-20s %-8s %-50s\n", "#", "ID", "Package", "Severity", "Title")
	fmt.Println(strings.Repeat("=", 120))

	for i, vuln := range vulnerabilities {
		severity := vuln.Severity
		switch severity {
		case "CRITICAL":
			severity = "🔴 " + severity
		case "HIGH":
			severity = "🟠 " + severity
		case "MEDIUM":
			severity = "🟡 " + severity
		case "LOW":
			severity = "🟢 " + severity
		}

		title := vuln.Title
		if len(title) > 47 {
			title = title[:47] + "..."
		}

		fmt.Printf("%-3d %-20s %-20s %-8s %-50s\n", i+1, vuln.ID, vuln.Package, severity, title)
	}
	fmt.Println(strings.Repeat("=", 120))
}

func (t *Trivexer) selectVulnerability(vulnerabilities []Vulnerability) (*Vulnerability, error) {
	if len(vulnerabilities) == 0 {
		return nil, fmt.Errorf("no vulnerabilities to select from")
	}

	// Check if we're in a non-interactive environment
	if !isTerminal() {
		fmt.Printf("\n⚠️  Running in non-interactive mode. Auto-selecting first vulnerability.\n")
		selected := &vulnerabilities[0]
		fmt.Printf("✅ Auto-selected vulnerability: %s\n", selected.ID)
		fmt.Printf("   Package: %s %s\n", selected.Package, selected.Version)
		fmt.Printf("   Severity: %s\n", selected.Severity)
		fmt.Printf("   Title: %s\n", selected.Title)
		return selected, nil
	}

	for {
		fmt.Printf("\nSelect a vulnerability (1-%d, or 'q' to quit): ", len(vulnerabilities))
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("❌ Error reading input: %v\n", err)
			continue
		}
		input = strings.TrimSpace(input)

		if input == "q" || input == "quit" {
			return nil, nil
		}

		if input == "" {
			fmt.Printf("❌ Please enter a number between 1 and %d, or 'q' to quit\n", len(vulnerabilities))
			continue
		}

		index, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf("❌ Invalid input '%s'. Please enter a number between 1 and %d, or 'q' to quit\n", input, len(vulnerabilities))
			continue
		}

		if index < 1 || index > len(vulnerabilities) {
			fmt.Printf("❌ Selection %d is out of range. Please enter a number between 1 and %d\n", index, len(vulnerabilities))
			continue
		}

		selected := &vulnerabilities[index-1]
		fmt.Printf("\n✅ Selected vulnerability: %s\n", selected.ID)
		fmt.Printf("   Package: %s %s\n", selected.Package, selected.Version)
		fmt.Printf("   Severity: %s\n", selected.Severity)
		fmt.Printf("   Title: %s\n", selected.Title)
		return selected, nil
	}
}

func (t *Trivexer) displayVulnerabilityDetails(vuln *Vulnerability) {
	fmt.Println("\n📋 Vulnerability Details:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("ID: %s\n", vuln.ID)
	fmt.Printf("Package: %s %s\n", vuln.Package, vuln.Version)
	fmt.Printf("Severity: %s\n", vuln.Severity)
	fmt.Printf("Title: %s\n", vuln.Title)
	fmt.Printf("Description: %s\n", vuln.Description)

	if len(vuln.References) > 0 {
		fmt.Println("References:")
		for i, ref := range vuln.References {
			if i >= 5 { // Show only first 5 references
				break
			}
			fmt.Printf("  - %s\n", ref)
		}
	}
	fmt.Println(strings.Repeat("=", 60))
}

func (t *Trivexer) getAuthor() string {
	// Check if we're in a non-interactive environment
	if !isTerminal() {
		return "Trivexer Automated"
	}

	for {
		fmt.Print("\nEnter author for VEX document: ")
		reader := bufio.NewReader(os.Stdin)
		author, _ := reader.ReadString('\n')
		author = strings.TrimSpace(author)

		if author != "" {
			return author
		}
		fmt.Println("❌ Author cannot be empty")
	}
}

func (t *Trivexer) generateVEXDocument(vuln *Vulnerability) (*OpenVEXDocument, error) {
	// Get status
	status, err := t.getStatus()
	if err != nil {
		return nil, err
	}

	// Get justification or action statement based on status
	var justification *string
	var actionStatement *string
	var actionStatementTime *time.Time

	if status == "not_affected" {
		just, err := t.getNotAffectedJustification()
		if err != nil {
			return nil, err
		}
		justification = &just
	} else if status == "affected" {
		action, err := t.getActionStatement()
		if err != nil {
			return nil, err
		}
		actionStatement = &action
		now := time.Now()
		actionStatementTime = &now
	}

	// Generate product ID (OCI format)
	productID := t.generateProductID()

	// Generate subcomponent ID (PURL format)
	subcomponentID := t.generateSubcomponentID(vuln)

	// Create VEX document
	vexDoc := &OpenVEXDocument{
		Context: "https://openvex.dev/ns/v0.2.0",
		ID:      fmt.Sprintf("https://openvex.dev/docs/public/vex-%s", generateID()),
		Author:  t.author,
		Time:    time.Now(),
		Version: 1,
		Statements: []VEXStatement{
			{
				Vulnerability: VEXVulnerability{
					Name: vuln.ID,
				},
				Time: time.Now(),
				Products: []VEXProduct{
					{
						ID: productID,
						Subcomponents: []VEXSubcomponent{
							{
								ID: subcomponentID,
							},
						},
					},
				},
				Status:              status,
				Justification:       justification,
				ActionStatement:     actionStatement,
				ActionStatementTime: actionStatementTime,
			},
		},
	}

	return vexDoc, nil
}

func (t *Trivexer) getStatus() (string, error) {
	// Check if we're in a non-interactive environment
	if !isTerminal() {
		fmt.Println("\n📋 Auto-selecting status: not_affected")
		return "not_affected", nil
	}

	fmt.Println("\n📋 Select VEX status:")
	for i, status := range statusOptions {
		fmt.Printf("%d. %s\n", i+1, status)
	}

	for {
		fmt.Print("Enter status (1-4): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		index, err := strconv.Atoi(input)
		if err != nil || index < 1 || index > len(statusOptions) {
			fmt.Printf("❌ Invalid selection. Please enter a number between 1 and %d\n", len(statusOptions))
			continue
		}

		return statusOptions[index-1], nil
	}
}

func (t *Trivexer) getNotAffectedJustification() (string, error) {
	// Check if we're in a non-interactive environment
	if !isTerminal() {
		fmt.Println("\n📋 Auto-selecting justification: component_not_present")
		return "component_not_present", nil
	}

	fmt.Println("\n📋 Select justification for 'not_affected' status:")
	for i, justification := range notAffectedJustifications {
		fmt.Printf("%d. %s\n", i+1, justification)
	}

	for {
		fmt.Print("Enter justification (1-5): ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		index, err := strconv.Atoi(input)
		if err != nil || index < 1 || index > len(notAffectedJustifications) {
			fmt.Printf("❌ Invalid selection. Please enter a number between 1 and %d\n", len(notAffectedJustifications))
			continue
		}

		return notAffectedJustifications[index-1], nil
	}
}

func (t *Trivexer) getActionStatement() (string, error) {
	// Check if we're in a non-interactive environment
	if !isTerminal() {
		return "Vulnerability requires attention and remediation", nil
	}

	for {
		fmt.Print("\nEnter action statement for 'affected' status: ")
		reader := bufio.NewReader(os.Stdin)
		action, _ := reader.ReadString('\n')
		action = strings.TrimSpace(action)

		if action != "" {
			return action, nil
		}
		fmt.Println("❌ Action statement cannot be empty")
	}
}

func (t *Trivexer) generateProductID() string {
	// Get the actual SHA256 digest of the image
	digest, err := t.getImageDigest()
	if err != nil {
		// Fallback to a placeholder if we can't get the digest
		return fmt.Sprintf("pkg:oci/%s@sha256:unknown", t.imageName)
	}

	// Generate OCI package URL for the container image with actual SHA256
	// Format: pkg:oci/name@sha256:digest?arch=arch&repository_url=registry
	return fmt.Sprintf("pkg:oci/%s@sha256:%s", t.imageName, digest)
}

func (t *Trivexer) getImageDigest() (string, error) {
	// Use docker inspect to get the SHA256 digest of the image
	cmd := exec.Command("docker", "inspect", "--format={{index .RepoDigests 0}}", t.imageName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get image digest: %w", err)
	}

	digest := strings.TrimSpace(string(output))
	if digest == "" {
		return "", fmt.Errorf("no digest found for image %s", t.imageName)
	}

	// Extract just the SHA256 part from the full digest
	// Format: registry/name@sha256:digest
	parts := strings.Split(digest, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid digest format: %s", digest)
	}

	sha256Part := parts[1]
	if !strings.HasPrefix(sha256Part, "sha256:") {
		return "", fmt.Errorf("invalid SHA256 format: %s", sha256Part)
	}

	// Return just the hash part without "sha256:" prefix
	return strings.TrimPrefix(sha256Part, "sha256:"), nil
}

func (t *Trivexer) generateSubcomponentID(vuln *Vulnerability) string {
	// Generate PURL for the vulnerable package
	// Format: pkg:type/namespace/name@version
	// We'll use a generic format for now
	return fmt.Sprintf("pkg:generic/%s@%s", vuln.Package, vuln.Version)
}

func (t *Trivexer) saveVEXDocument(vexDoc *OpenVEXDocument) error {
	vexJSON, err := json.MarshalIndent(vexDoc, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(t.outputFile, vexJSON, 0644)
}

// Helper functions
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func generateID() string {
	// Generate a simple ID based on current time
	return fmt.Sprintf("%d", time.Now().Unix())
}

func isTerminal() bool {
	// Check if we're in a non-interactive environment
	// This works better in Docker containers
	if os.Getenv("NON_INTERACTIVE") == "true" {
		return false
	}

	// Check if stdin is a terminal
	fileInfo, _ := os.Stdin.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
