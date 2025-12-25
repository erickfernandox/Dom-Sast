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

// Scanner principal refeito
type Scanner struct {
	variables      map[string]string  // variável -> valor atribuído
	dangerousCalls map[string][]string // função -> linhas perigosas
}

func NewScanner() *Scanner {
	return &Scanner{
		variables:      make(map[string]string),
		dangerousCalls: make(map[string][]string),
	}
}

// Analisa o corpo e retorna resultados
func (s *Scanner) Analyze(body string) (bool, string) {
	s.variables = make(map[string]string)
	s.dangerousCalls = make(map[string][]string)
	
	// 1. Normalizar o body (remover espaços desnecessários)
	normalized := normalizeSpaces(body)
	
	// 2. Encontrar todas as variáveis que recebem "EFX" (com aspas abertas)
	s.findEFXVariables(normalized)
	
	// 3. Encontrar todos os usos perigosos de "EFX" diretamente
	s.findDirectEFXUsage(normalized)
	
	// 4. Encontrar usos de variáveis que contém EFX em sinks perigosos
	s.findVariableEFXUsage(normalized)
	
	// 5. Gerar resultados
	return s.generateResults()
}

// Normaliza espaços para facilitar regex
func normalizeSpaces(text string) string {
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	
	// Remover múltiplos espaços
	for strings.Contains(text, "  ") {
		text = strings.ReplaceAll(text, "  ", " ")
	}
	
	return text
}

// Encontra variáveis que recebem EFX (com aspas abertas)
func (s *Scanner) findEFXVariables(text string) {
	// Padrões para atribuições com EFX
	patterns := []struct {
		name string
		re   string
	}{
		// Atribuição direta com aspas duplas (abertas)
		{"VAR_DOUBLE", `(\b\w+\b)\s*=\s*"EFX`},
		// Atribuição direta com aspas simples (abertas)
		{"VAR_SINGLE", `(\b\w+\b)\s*=\s*'EFX`},
		// var/let/const com aspas duplas
		{"DECL_DOUBLE", `\b(var|let|const)\s+(\w+)\s*=\s*"EFX`},
		// var/let/const com aspas simples
		{"DECL_SINGLE", `\b(var|let|const)\s+(\w+)\s*=\s*'EFX`},
		// Atribuição de propriedade
		{"PROP_DOUBLE", `(\b\w+(?:\.\w+)*)\s*=\s*"EFX`},
		// Objeto JSON/JS
		{"JSON_DOUBLE", `"(\w+)"\s*:\s*"EFX`},
		{"JSON_SINGLE", `'(\w+)'\s*:\s*'EFX`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		matches := re.FindAllStringSubmatch(text, -1)
		
		for _, match := range matches {
			if len(match) >= 2 {
				varName := ""
				value := match[0]
				
				if p.name == "DECL_DOUBLE" || p.name == "DECL_SINGLE" {
					if len(match) >= 3 {
						varName = match[2] // o nome da variável é o terceiro grupo
					}
				} else {
					varName = match[1] // o nome da variável é o segundo grupo
				}
				
				if varName != "" {
					s.variables[varName] = cleanMatch(value)
				}
			}
		}
	}
}

// Encontra usos diretos de EFX em funções perigosas
func (s *Scanner) findDirectEFXUsage(text string) {
	sinks := []struct {
		name string
		re   string
	}{
		// Execução de código
		{"eval", `eval\s*\(\s*"EFX`},
		{"Function", `new\s+Function\s*\(\s*"EFX`},
		{"setTimeout", `setTimeout\s*\(\s*"EFX`},
		{"setInterval", `setInterval\s*\(\s*"EFX`},
		
		// Redirecionamento
		{"location", `location\s*=\s*"EFX`},
		{"location.href", `location\.href\s*=\s*"EFX`},
		{"location.assign", `location\.assign\s*\(\s*"EFX`},
		{"location.replace", `location\.replace\s*\(\s*"EFX`},
		
		// Window redirection
		{"window.location", `window\.location\s*=\s*"EFX`},
		{"window.location.href", `window\.location\.href\s*=\s*"EFX`},
		{"window.navigate", `window\.navigate\s*\(\s*"EFX`},
		
		// DOM manipulation
		{"document.write", `document\.write\s*\(\s*"EFX`},
		{"document.writeln", `document\.writeln\s*\(\s*"EFX`},
		{"innerHTML", `innerHTML\s*=\s*"EFX`},
		{"outerHTML", `outerHTML\s*=\s*"EFX`},
		
		// Attributes
		{".src", `\.src\s*=\s*"EFX`},
		{".href", `\.href\s*=\s*"EFX`},
		{".action", `\.action\s*=\s*"EFX`},
		{".data", `\.data\s*=\s*"EFX`},
		
		// jQuery
		{"$.html", `\$\([^)]*\)\.html\s*\(\s*"EFX`},
		{"$.append", `\$\([^)]*\)\.append\s*\(\s*"EFX`},
		{"$.prepend", `\$\([^)]*\)\.prepend\s*\(\s*"EFX`},
		
		// React/Vue
		{"dangerouslySetInnerHTML", `dangerouslySetInnerHTML\s*:\s*\{[^}]*__html\s*:\s*"EFX`},
		{"v-html", `v-html\s*=\s*"EFX`},
		
		// Casos especiais (exemplo: "EFX")?window.location.href="EFX":)
		{"conditional_redirect", `"EFX"[^;]*window\.location\.href\s*=\s*"EFX`},
		{"func_param_redirect", `\w+\s*\(\s*"EFX[^)]*\)[^;]*window\.location\.href\s*=`},
	}
	
	for _, sink := range sinks {
		re := regexp.MustCompile(sink.re)
		matches := re.FindAllString(text, -1)
		
		for _, match := range matches {
			s.dangerousCalls[sink.name] = append(s.dangerousCalls[sink.name], cleanMatch(match))
		}
	}
}

// Encontra usos de variáveis que contém EFX em sinks perigosos
func (s *Scanner) findVariableEFXUsage(text string) {
	// Padrões para sinks que usam variáveis
	sinkPatterns := []struct {
		name string
		re   string
	}{
		// Execução de código com variável
		{"eval_var", `eval\s*\(\s*(\w+)\s*\)`},
		{"Function_var", `new\s+Function\s*\(\s*(\w+)\s*\)`},
		{"setTimeout_var", `setTimeout\s*\(\s*(\w+)\s*[,)]`},
		
		// Redirecionamento com variável
		{"location_var", `location\s*=\s*(\w+)`},
		{"location.href_var", `location\.href\s*=\s*(\w+)`},
		{"window.location_var", `window\.location\s*=\s*(\w+)`},
		{"window.location.href_var", `window\.location\.href\s*=\s*(\w+)`},
		
		// DOM com variável
		{"innerHTML_var", `innerHTML\s*=\s*(\w+)`},
		{"document.write_var", `document\.write\s*\(\s*(\w+)\s*\)`},
		
		// Atributos com variável
		{".src_var", `\.src\s*=\s*(\w+)`},
		{".href_var", `\.href\s*=\s*(\w+)`},
	}
	
	for _, sink := range sinkPatterns {
		re := regexp.MustCompile(sink.re)
		matches := re.FindAllStringSubmatch(text, -1)
		
		for _, match := range matches {
			if len(match) >= 2 {
				varName := match[1]
				
				// Verificar se esta variável contém EFX
				if _, hasEFX := s.variables[varName]; hasEFX {
					s.dangerousCalls[sink.name+"_via_"+varName] = append(
						s.dangerousCalls[sink.name+"_via_"+varName],
						fmt.Sprintf("%s: %s -> %s", sink.name, varName, cleanMatch(match[0])),
					)
				}
			}
		}
	}
}

// Gera os resultados
func (s *Scanner) generateResults() (bool, string) {
	var findings []string
	
	// 1. Direto EFX em sinks
	for sink, matches := range s.dangerousCalls {
		// Filtrar apenas as que começam com sink "puro" (não _via_)
		if !strings.Contains(sink, "_via_") && len(matches) > 0 {
			findings = append(findings, fmt.Sprintf("%s: %s", sink, strings.Join(matches[:min(2, len(matches))], " | ")))
		}
	}
	
	// 2. Fluxos de variáveis (variável → sink)
	for sink, matches := range s.dangerousCalls {
		if strings.Contains(sink, "_via_") && len(matches) > 0 {
			findings = append(findings, fmt.Sprintf("FLOW: %s", strings.Join(matches[:min(2, len(matches))], " | ")))
		}
	}
	
	// 3. Variáveis detectadas (para debug, se quiser)
	/*
	if len(s.variables) > 0 && !onlyPOC {
		var varList []string
		for varName, value := range s.variables {
			varList = append(varList, fmt.Sprintf("%s=%s", varName, value))
		}
		findings = append(findings, fmt.Sprintf("VARS: %s", strings.Join(varList, ", ")))
	}
	*/
	
	if len(findings) > 0 {
		return true, strings.Join(findings, " || ")
	}
	
	return false, ""
}

func cleanMatch(match string) string {
	match = strings.TrimSpace(match)
	
	// Limitar tamanho
	if len(match) > 70 {
		match = match[:67] + "..."
	}
	
	return match
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// analyzeReflection - wrapper para compatibilidade
func analyzeReflection(body string) (bool, string) {
	scanner := NewScanner()
	return scanner.Analyze(body)
}

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
