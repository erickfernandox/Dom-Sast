package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type customheaders []string

func (h *customheaders) String() string {
	return "Custom headers"
}

func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

var (
	headers     customheaders
	paramFile   string
	paramCount  int
	proxy       string
	onlyPOC     bool
	paramList   []string
	concurrency int
	methodMode  string
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to use")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL (shorthand)")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output (shorthand)")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads (min 15)")
	flag.StringVar(&methodMode, "o", "", "Only run one method: get | post (if omitted, tests both)")
	flag.Usage = usage
}

func usage() {
	fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___=

EFX DOM XSS Scanner
Detects EFX in DOM XSS and Redirect sinks

Usage:
  -lp       List of parameters in txt file (required)
  -params   Number of parameters to inject (required)
  -proxy    Proxy address (or -x)
  -H        Headers
  -s        Show only PoC
  -t        Number of threads (default 50, minimum 15)
  -o        Only method: get | post (if omitted, tests both)
  `)
}

func main() {
	flag.Parse()

	if paramFile == "" || paramCount == 0 {
		fmt.Fprintln(os.Stderr, "Error: -lp and -params are required parameters")
		fmt.Fprintln(os.Stderr, "Example: cat urls.txt | ./program -lp params.txt -params 5")
		flag.Usage()
		os.Exit(1)
	}

	if concurrency < 15 {
		concurrency = 15
	}

	if methodMode != "" {
		m := strings.ToLower(methodMode)
		if m != "get" && m != "post" {
			fmt.Fprintln(os.Stderr, "Invalid -o value. Use 'get' or 'post'.")
			os.Exit(1)
		}
		methodMode = m
	}

	params, err := readParamFile(paramFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read param file:", err)
		os.Exit(1)
	}
	paramList = params

	fmt.Printf("[*] Starting EFX DOM XSS Scanner\n")
	fmt.Printf("[*] Parameters loaded: %d\n", len(paramList))
	fmt.Printf("[*] Parameters per request: %d\n", paramCount)

	stdin := bufio.NewScanner(os.Stdin)
	targets := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				result := testTarget(target, methodMode)
				if result != "" {
					fmt.Println(result)
				}
			}
		}()
	}

	for stdin.Scan() {
		u := strings.TrimSpace(stdin.Text())
		if u != "" {
			targets <- u
		}
	}

	close(targets)
	wg.Wait()
}

func readParamFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var params []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			params = append(params, line)
		}
	}
	return params, scanner.Err()
}

func getRandomParams(params []string, count int) []string {
	if count >= len(params) {
		return params
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

// ==================== NOVO ALGORITMO DE DETECÇÃO ====================

type DetectionResult struct {
	DirectMatches []string            // EFX direto em funções perigosas
	VariableFlows map[string][]string // Fluxos: variável -> usos perigosos
	Variables     map[string]string   // Variáveis que contém EFX
}

func NewDetectionResult() *DetectionResult {
	return &DetectionResult{
		DirectMatches: make([]string, 0),
		VariableFlows: make(map[string][]string),
		Variables:     make(map[string]string),
	}
}

func analyzeReflection(body string) (bool, string) {
	result := NewDetectionResult()
	lines := strings.Split(body, "\n")
	
	// FASE 1: Coletar todas as variáveis que recebem EFX
	collectEFXVariables(lines, result)
	
	// FASE 2: Buscar EFX direto em sinks perigosos
	findDirectEFXInSinks(lines, result)
	
	// FASE 3: Buscar usos de variáveis EFX em sinks perigosos
	findVariableUsageInSinks(lines, result)
	
	// FASE 4: Gerar resultado
	return generateResult(result)
}

// FASE 1: Coletar variáveis com EFX
func collectEFXVariables(lines []string, result *DetectionResult) {
	for i, line := range lines {
		line = normalizeLine(line)
		if line == "" {
			continue
		}
		
		// Padrões para atribuição de EFX a variáveis
		patterns := []struct {
			name string
			re   *regexp.Regexp
		}{
			// Atribuição direta com aspas duplas
			{"ASSIGN_DOUBLE", regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"EFX`)},
			// Atribuição direta com aspas simples
			{"ASSIGN_SINGLE", regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'EFX`)},
			// var/let/const com aspas duplas
			{"DECL_DOUBLE", regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"EFX`)},
			// var/let/const com aspas simples
			{"DECL_SINGLE", regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'EFX`)},
			// Atribuição de propriedade
			{"PROP_DOUBLE", regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*)\s*=\s*"EFX`)},
			// JSON/objeto
			{"JSON_DOUBLE", regexp.MustCompile(`"([^"]+)"\s*:\s*"EFX`)},
			{"JSON_SINGLE", regexp.MustCompile(`'([^']+)'\s*:\s*'EFX`)},
			// PHP array
			{"PHP_ARRAY", regexp.MustCompile(`"([^"]+)"\s*=>\s*"EFX`)},
		}
		
		for _, p := range patterns {
			matches := p.re.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					varName := ""
					
					if p.name == "DECL_DOUBLE" || p.name == "DECL_SINGLE" {
						if len(match) > 2 {
							varName = match[2]
						}
					} else {
						varName = match[1]
					}
					
					if varName != "" {
						context := fmt.Sprintf("L%d: %s", i+1, truncate(line, 50))
						result.Variables[varName] = context
					}
				}
			}
		}
	}
}

// FASE 2: Buscar EFX direto em sinks
func findDirectEFXInSinks(lines []string, result *DetectionResult) {
	sinkDefinitions := getSinkDefinitions()
	
	for i, line := range lines {
		line = normalizeLine(line)
		if line == "" {
			continue
		}
		
		for _, sink := range sinkDefinitions {
			// Verificar EFX direto
			if sink.directPattern != nil {
				matches := sink.directPattern.FindAllString(line, -1)
				for _, match := range matches {
					context := fmt.Sprintf("L%d: %s (%s)", i+1, truncate(match, 60), sink.name)
					result.DirectMatches = append(result.DirectMatches, context)
				}
			}
		}
	}
}

// FASE 3: Buscar usos de variáveis EFX em sinks
func findVariableUsageInSinks(lines []string, result *DetectionResult) {
	sinkDefinitions := getSinkDefinitions()
	
	for i, line := range lines {
		line = normalizeLine(line)
		if line == "" {
			continue
		}
		
		for _, sink := range sinkDefinitions {
			if sink.variablePattern != nil {
				matches := sink.variablePattern.FindAllStringSubmatch(line, -1)
				for _, match := range matches {
					if len(match) > 1 {
						varName := match[1]
						
						// Verificar se esta variável contém EFX
						if _, hasEFX := result.Variables[varName]; hasEFX {
							context := fmt.Sprintf("L%d: %s", i+1, truncate(match[0], 60))
							
							// Registrar o fluxo: variável -> sink
							flow := fmt.Sprintf("%s -> %s: %s", varName, sink.name, context)
							result.VariableFlows[varName] = append(result.VariableFlows[varName], flow)
						}
					}
				}
			}
		}
		
		// Buscar padrões especiais
		findSpecialPatterns(line, i, result)
	}
}

// Definir todos os sinks perigosos
type SinkDefinition struct {
	name           string
	directPattern  *regexp.Regexp  // Para EFX direto
	variablePattern *regexp.Regexp // Para variáveis
}

func getSinkDefinitions() []SinkDefinition {
	// Padrão para nomes de variáveis (inclui $ e propriedades)
	varPattern := `([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*)`
	
	return []SinkDefinition{
		// ========== EXECUÇÃO DE CÓDIGO ==========
		{
			name:           "eval",
			directPattern:  regexp.MustCompile(`eval\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`eval\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		{
			name:           "Function",
			directPattern:  regexp.MustCompile(`new\s+Function\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`new\s+Function\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		{
			name:           "setTimeout",
			directPattern:  regexp.MustCompile(`setTimeout\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`setTimeout\s*\(\s*(%s)\s*[,)]`, varPattern)),
		},
		{
			name:           "setInterval",
			directPattern:  regexp.MustCompile(`setInterval\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`setInterval\s*\(\s*(%s)\s*[,)]`, varPattern)),
		},
		
		// ========== REDIRECIONAMENTO ==========
		{
			name:           "location.href",
			directPattern:  regexp.MustCompile(`location\.href\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`location\.href\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "window.location.href",
			directPattern:  regexp.MustCompile(`window\.location\.href\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`window\.location\.href\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "window.location",
			directPattern:  regexp.MustCompile(`window\.location\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`window\.location\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "location",
			directPattern:  regexp.MustCompile(`location\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`location\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "location.assign",
			directPattern:  regexp.MustCompile(`location\.assign\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`location\.assign\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		{
			name:           "location.replace",
			directPattern:  regexp.MustCompile(`location\.replace\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`location\.replace\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		
		// ========== DOM MANIPULATION ==========
		{
			name:           "innerHTML",
			directPattern:  regexp.MustCompile(`innerHTML\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`innerHTML\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "outerHTML",
			directPattern:  regexp.MustCompile(`outerHTML\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`outerHTML\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           "document.write",
			directPattern:  regexp.MustCompile(`document\.write\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`document\.write\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		{
			name:           "document.writeln",
			directPattern:  regexp.MustCompile(`document\.writeln\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`document\.writeln\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		
		// ========== ATRIBUTOS ==========
		{
			name:           ".src",
			directPattern:  regexp.MustCompile(`\.src\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`\.src\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           ".href",
			directPattern:  regexp.MustCompile(`\.href\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`\.href\s*=\s*(%s)`, varPattern)),
		},
		{
			name:           ".action",
			directPattern:  regexp.MustCompile(`\.action\s*=\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`\.action\s*=\s*(%s)`, varPattern)),
		},
		
		// ========== JQUERY ==========
		{
			name:           "$().html",
			directPattern:  regexp.MustCompile(`\$\([^)]*\)\.html\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`\$\([^)]*\)\.html\s*\(\s*(%s)\s*\)`, varPattern)),
		},
		{
			name:           "$().append",
			directPattern:  regexp.MustCompile(`\$\([^)]*\)\.append\s*\(\s*"EFX`),
			variablePattern: regexp.MustCompile(fmt.Sprintf(`\$\([^)]*\)\.append\s*\(\s*(%s)\s*\)`, varPattern)),
		},
	}
}

// Buscar padrões especiais (como o seu exemplo)
func findSpecialPatterns(line string, lineNum int, result *DetectionResult) {
	specialPatterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		// Seu exemplo: ;handleAndCheckURLRedirect("EFX")?window.location.href="EFX":
		{"func_redirect", regexp.MustCompile(`[;]?\w+\s*\(\s*"EFX[^)]*\)\s*[?:]\s*window\.location\.href\s*=\s*"EFX`)},
		
		// Condicional com redirect
		{"cond_redirect", regexp.MustCompile(`"EFX"[^;]*\?[^:]*:\s*window\.location\.href\s*=`)},
		
		// EFX em parâmetro de função que leva a redirect
		{"param_redirect", regexp.MustCompile(`\w+\s*\(\s*"EFX[^)]*\)[^;]*\.(?:location|href|src)\s*=`)},
		
		// EFX concatenado em string
		{"concat_redirect", regexp.MustCompile(`"EFX[^"]*"\s*\+\s*\w+[^;]*\.href\s*=`)},
	}
	
	for _, sp := range specialPatterns {
		matches := sp.re.FindAllString(line, -1)
		for _, match := range matches {
			context := fmt.Sprintf("L%d: %s (%s)", lineNum+1, truncate(match, 60), sp.name)
			result.DirectMatches = append(result.DirectMatches, context)
		}
	}
}

// FASE 4: Gerar resultado final
func generateResult(result *DetectionResult) (bool, string) {
	var findings []string
	
	// 1. Matches diretos
	if len(result.DirectMatches) > 0 {
		findings = append(findings, "DIRECT: "+strings.Join(result.DirectMatches[:min(3, len(result.DirectMatches))], " | "))
	}
	
	// 2. Fluxos de variáveis
	for varName, flows := range result.VariableFlows {
		if len(flows) > 0 {
			varContext := result.Variables[varName]
			flowSummary := fmt.Sprintf("%s [%s] -> %s", varName, varContext, strings.Join(flows[:min(2, len(flows))], " | "))
			findings = append(findings, "FLOW: "+flowSummary)
		}
	}
	
	// 3. Apenas variáveis detectadas (para debug)
	if len(result.Variables) > 0 && len(findings) == 0 && !onlyPOC {
		var varList []string
		for varName, context := range result.Variables {
			varList = append(varList, fmt.Sprintf("%s(%s)", varName, context))
		}
		if len(varList) > 0 {
			findings = append(findings, "VARS: "+strings.Join(varList[:min(3, len(varList))], ", "))
		}
	}
	
	if len(findings) > 0 {
		return true, strings.Join(findings, " || ")
	}
	
	return false, ""
}

// Funções utilitárias
func normalizeLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.ReplaceAll(line, "\t", " ")
	line = strings.ReplaceAll(line, "\r", "")
	
	// Remover múltiplos espaços
	for strings.Contains(line, "  ") {
		line = strings.ReplaceAll(line, "  ", " ")
	}
	
	return line
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ==================== FIM DO NOVO ALGORITMO ====================

func testTarget(base string, methodMode string) string {
	selectedParams := getRandomParams(paramList, paramCount)
	client := buildClient()

	if methodMode == "" || methodMode == "get" {
		if result := testMethod("GET", base, selectedParams, client); result != "" {
			return result
		}
	}

	if methodMode == "" || methodMode == "post" {
		if result := testMethod("POST", base, selectedParams, client); result != "" {
			return result
		}
	}

	return ""
}

func testMethod(method, base string, params []string, client *http.Client) string {
	urlObj, err := url.Parse(base)
	if err != nil {
		return ""
	}

	var req *http.Request
	
	if method == "GET" {
		q := url.Values{}
		for _, p := range params {
			q.Set(p, "EFX")
		}
		urlObj.RawQuery = q.Encode()
		
		req, err = http.NewRequest("GET", urlObj.String(), nil)
		if err != nil {
			return ""
		}
	} else {
		postData := url.Values{}
		for _, p := range params {
			postData.Set(p, "EFX")
		}
		
		req, err = http.NewRequest("POST", urlObj.String(), strings.NewReader(postData.Encode()))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	req.Header.Set("Connection", "close")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	hasReflection, context := analyzeReflection(bodyStr)
	
	if hasReflection {
		color := "\033[1;31m"
		
		if method == "GET" {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s | %s\033[0m", color, urlObj.String(), context)
			}
			return fmt.Sprintf("%sGET REFLECTED - %s | %s\033[0m", color, urlObj.String(), context)
		} else {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s | %s\033[0m", color, urlObj.String(), context)
			}
			return fmt.Sprintf("%sPOST REFLECTED - %s | %s\033[0m", color, urlObj.String(), context)
		}
	} else if !onlyPOC {
		if method == "GET" {
			return fmt.Sprintf("\033[1;30mGET NOT_REFLECTED - %s\033[0m", urlObj.String())
		} else {
			return fmt.Sprintf("\033[1;30mPOST NOT_REFLECTED - %s\033[0m", urlObj.String())
		}
	}

	return ""
}

func buildClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	
	if proxy != "" {
		if parsedProxy, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(parsedProxy)
		}
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}
