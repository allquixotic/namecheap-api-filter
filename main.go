package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/namecheap/go-namecheap-sdk/v2/namecheap"
	"golang.org/x/term"
)

type Config struct {
	AuthToken      string
	APIUser        string
	APIKey         string
	ClientIP       string
	AllowedDomains []string
	AllowDelete    bool
	ListenAddr     string
}

var config Config
var namecheapClient *namecheap.Client

func loadConfig() {
	config = Config{
		AuthToken:      getEnv("AUTH_TOKEN", ""),
		APIUser:        getEnv("NAMECHEAP_API_USER", ""),
		APIKey:         getEnv("NAMECHEAP_API_KEY", ""),
		ClientIP:       getEnv("NAMECHEAP_CLIENT_IP", ""),
		AllowedDomains: parseAllowedDomains(getEnv("ALLOWED_DOMAINS", "")),
		AllowDelete:    getEnv("ALLOW_DELETE", "false") == "true",
		ListenAddr:     getEnv("LISTEN_ADDR", ":8080"),
	}
}

func validateConfig() error {
	if config.AuthToken == "" {
		return fmt.Errorf("AUTH_TOKEN environment variable is required")
	}
	if config.APIUser == "" {
		return fmt.Errorf("NAMECHEAP_API_USER environment variable is required")
	}
	if config.APIKey == "" {
		return fmt.Errorf("NAMECHEAP_API_KEY environment variable is required")
	}
	if config.ClientIP == "" {
		return fmt.Errorf("NAMECHEAP_CLIENT_IP environment variable is required")
	}
	return nil
}

func initNamecheapClient() {
	namecheapClient = namecheap.NewClient(&namecheap.ClientOptions{
		UserName:   config.APIUser,
		ApiUser:    config.APIUser,
		ApiKey:     config.APIKey,
		ClientIp:   config.ClientIP,
		UseSandbox: getEnv("NAMECHEAP_SANDBOX", "false") == "true",
	})
}

func main() {
	// Check if we should run setup
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := runInteractiveSetup(); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		return
	}
	
	// Check if .env exists
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		fmt.Println("No .env file found. Would you like to run the setup wizard?")
		fmt.Print("Run setup? (Y/n): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		
		if response == "" || response == "y" || response == "yes" {
			if err := runInteractiveSetup(); err != nil {
				log.Fatalf("Setup failed: %v", err)
			}
			return
		}
	}
	
	// Load configuration from environment
	loadConfig()
	
	// Validate configuration
	if err := validateConfig(); err != nil {
		log.Fatal(err)
	}
	
	// Initialize Namecheap client
	initNamecheapClient()
	
	log.Printf("namecheap-api-filter starting...")
	log.Printf("Allowed domains: %v", config.AllowedDomains)
	log.Printf("Allow delete operations: %v", config.AllowDelete)
	
	http.HandleFunc("/", handleRequest)
	
	log.Printf("Server listening on %s", config.ListenAddr)
	log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if !authenticate(r) {
		sendError(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	if r.Method != "GET" && r.Method != "POST" {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	command := getParameter(r, "Command")
	if command == "" {
		sendError(w, "Command parameter is required", http.StatusBadRequest)
		return
	}

	if !isAllowedCommand(command) {
		sendError(w, fmt.Sprintf("Command '%s' is not allowed", command), http.StatusForbidden)
		return
	}

	domain := getDomainFromRequest(r, command)
	if domain != "" && !isDomainAllowed(domain) {
		sendError(w, fmt.Sprintf("Domain '%s' is not allowed", domain), http.StatusForbidden)
		return
	}

	proxyToNamecheap(w, r)
}

func authenticate(r *http.Request) bool {
	token := getParameter(r, "ApiKey")
	if token == "" {
		token = r.Header.Get("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(config.AuthToken)) == 1
}

func isAllowedCommand(command string) bool {
	allowedCommands := []string{
		"namecheap.domains.dns.getList",
		"namecheap.domains.dns.getHosts",
		"namecheap.domains.dns.getEmailForwarding",
		"namecheap.domains.ns.getInfo",
	}

	for _, allowed := range allowedCommands {
		if command == allowed {
			return true
		}
	}

	if command == "namecheap.domains.dns.setHosts" {
		return true
	}

	return false
}

func getDomainFromRequest(r *http.Request, command string) string {
	sld := getParameter(r, "SLD")
	tld := getParameter(r, "TLD")
	domainName := getParameter(r, "DomainName")

	if sld != "" && tld != "" {
		return sld + "." + tld
	}
	return domainName
}

func isDomainAllowed(domain string) bool {
	if len(config.AllowedDomains) == 0 {
		return true
	}

	domain = strings.ToLower(domain)
	for _, allowed := range config.AllowedDomains {
		allowed = strings.ToLower(allowed)
		if domain == allowed || strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

func proxyToNamecheap(w http.ResponseWriter, r *http.Request) {
	params := make(url.Values)
	
	if r.Method == "GET" {
		for key, values := range r.URL.Query() {
			if key != "ApiKey" {
				params[key] = values
			}
		}
	} else if r.Method == "POST" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			sendError(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		
		parsedParams, err := url.ParseQuery(string(body))
		if err != nil {
			sendError(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}
		
		for key, values := range parsedParams {
			if key != "ApiKey" {
				params[key] = values
			}
		}
	}

	params.Set("ApiUser", config.APIUser)
	params.Set("ApiKey", config.APIKey)
	params.Set("UserName", config.APIUser)
	params.Set("ClientIp", config.ClientIP)

	apiURL := "https://api.namecheap.com/xml"
	if getEnv("NAMECHEAP_SANDBOX", "false") == "true" {
		apiURL = "https://api.sandbox.namecheap.com/xml"
	}

	var resp *http.Response
	var err error

	if r.Method == "GET" {
		fullURL := apiURL + "?" + params.Encode()
		resp, err = http.Get(fullURL)
	} else {
		resp, err = http.PostForm(apiURL, params)
	}

	if err != nil {
		sendError(w, fmt.Sprintf("Failed to call Namecheap API: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func getParameter(r *http.Request, key string) string {
	if r.Method == "POST" {
		return r.FormValue(key)
	}
	return r.URL.Query().Get(key)
}

func sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)
	
	errorResp := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml/response">
  <Errors>
    <Error Number="%d">%s</Error>
  </Errors>
  <Warnings />
  <RequestedCommand />
  <CommandResponse />
  <Server>Namecheap API Filter</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>0.001</ExecutionTime>
</ApiResponse>`, statusCode, message)

	w.Write([]byte(errorResp))
	log.Printf("Error: %s (Status: %d)", message, statusCode)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseAllowedDomains(domainsStr string) []string {
	if domainsStr == "" {
		return nil
	}
	
	domains := strings.Split(domainsStr, ",")
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			result = append(result, domain)
		}
	}
	return result
}

// Setup functions
func runInteractiveSetup() error {
	fmt.Println("\n======================================")
	fmt.Println("namecheap-api-filter Setup Wizard")
	fmt.Println("======================================\n")
	
	// Check dotenvx
	if err := checkDotenvx(); err != nil {
		return err
	}
	
	// Check if .env already exists
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println("⚠️  .env file already exists!")
		if !confirm("Do you want to overwrite it?") {
			fmt.Println("Setup cancelled")
			return nil
		}
		// Backup existing file
		backupFile(".env")
	}
	
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("Please provide the following information:\n")
	
	// AUTH_TOKEN
	fmt.Println("📝 AUTH_TOKEN - A secure token for client authentication")
	var authToken string
	if confirm("Generate a random token?") {
		authToken = generateToken()
		fmt.Printf("✅ Generated token: %s\n", authToken)
	} else {
		authToken = readLine(reader, "Enter your AUTH_TOKEN: ")
	}
	
	// Required fields
	fmt.Println()
	apiUser := readLine(reader, "Enter your Namecheap username: ")
	
	fmt.Println("\n💡 You can find your API key at: https://ap.www.namecheap.com/settings/tools/apiaccess/")
	apiKey := readPassword("Enter your Namecheap API key: ")
	
	fmt.Printf("\n🌐 Your current IP address is: %s\n", getCurrentIP())
	clientIP := readLine(reader, "Enter your whitelisted IP address: ")
	
	// Optional fields
	fmt.Println("\n📋 Optional configurations (press Enter to skip):\n")
	
	allowedDomains := readLine(reader, "Allowed domains (comma-separated, e.g., example.com,test.org): ")
	
	allowDelete := "false"
	if confirm("Allow delete operations?") {
		allowDelete = "true"
	}
	
	listenAddr := readLine(reader, "Listen address (default :8080): ")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	
	sandbox := "false"
	if confirm("Use Namecheap sandbox?") {
		sandbox = "true"
	}
	
	// Write .env file
	envContent := fmt.Sprintf(`# namecheap-api-filter environment variables

# Required: Static authentication token for clients
AUTH_TOKEN=%s

# Required: Your Namecheap API credentials
NAMECHEAP_API_USER=%s
NAMECHEAP_API_KEY=%s
NAMECHEAP_CLIENT_IP=%s

# Optional: Comma-separated list of allowed domains (leave empty to allow all)
ALLOWED_DOMAINS=%s

# Optional: Allow delete operations via setHosts (default: false)
ALLOW_DELETE=%s

# Optional: Server listen address (default: :8080)
LISTEN_ADDR=%s

# Optional: Use Namecheap sandbox API (default: false)
NAMECHEAP_SANDBOX=%s
`, authToken, apiUser, apiKey, clientIP, allowedDomains, allowDelete, listenAddr, sandbox)
	
	if err := os.WriteFile(".env", []byte(envContent), 0600); err != nil {
		return fmt.Errorf("failed to write .env: %v", err)
	}
	
	fmt.Println("\n✅ .env file created successfully!")
	
	// Encrypt with dotenvx
	fmt.Println("\n🔒 Encrypting .env file with dotenvx...")
	if err := runDotenvxEncrypt(); err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	
	fmt.Println("✅ Encryption successful!")
	fmt.Println("\n⚠️  IMPORTANT: Your .env.keys file contains the decryption key")
	fmt.Println("⚠️  Keep it safe and NEVER commit it to version control!")
	
	// Update .gitignore
	updateGitignore()
	
	// Show next steps
	fmt.Println("\n======================================")
	fmt.Println("Setup Complete! Next steps:")
	fmt.Println("======================================\n")
	fmt.Println("1. Run the filter:")
	fmt.Println("   dotenvx run -- go run main.go")
	fmt.Println("   or")
	fmt.Println("   go build && dotenvx run -- ./namecheap-api-filter\n")
	fmt.Println("2. Test the filter:")
	fmt.Printf("   curl 'http://localhost:8080/?Command=namecheap.domains.dns.getHosts&SLD=example&TLD=com&ApiKey=%s'\n\n", authToken)
	fmt.Printf("Your AUTH_TOKEN for clients is: %s\n\n", authToken)
	
	return nil
}

func checkDotenvx() error {
	if _, err := exec.LookPath("dotenvx"); err != nil {
		fmt.Println("❌ dotenvx is not installed!")
		fmt.Println("\nPlease install dotenvx first:")
		fmt.Println("  curl -sfS https://dotenvx.sh | sh")
		fmt.Println("  or")
		fmt.Println("  brew install dotenvx/brew/dotenvx")
		return fmt.Errorf("dotenvx not found")
	}
	fmt.Println("✅ dotenvx is installed")
	return nil
}

func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based token
		return fmt.Sprintf("token-%d", time.Now().Unix())
	}
	return hex.EncodeToString(bytes)
}

func getCurrentIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "unable to detect"
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unable to detect"
	}
	
	return string(body)
}

func readLine(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback to regular input
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}
	return string(password)
}

func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (y/N): ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func backupFile(filename string) {
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("%s.backup.%s", filename, timestamp)
	
	input, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	
	if err := os.WriteFile(backupName, input, 0600); err != nil {
		return
	}
	
	fmt.Printf("📁 Existing %s backed up to %s\n", filename, backupName)
}

func runDotenvxEncrypt() error {
	cmd := exec.Command("dotenvx", "encrypt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func updateGitignore() {
	// Check if .env.keys is already in .gitignore
	content, err := os.ReadFile(".gitignore")
	if err == nil && strings.Contains(string(content), ".env.keys") {
		return
	}
	
	// Add to .gitignore
	file, err := os.OpenFile(".gitignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	
	file.WriteString("\n# Dotenvx\n.env.keys\n*.env.keys\n")
	fmt.Println("📝 Added .env.keys to .gitignore")
}