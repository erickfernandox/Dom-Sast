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

// ==================== ALGORITMO SIMPLIFICADO ====================

// Analisa reflexões EFX no corpo HTML
func analyzeReflection(body string) (bool, string) {
	// Normalizar o corpo
	normalized := normalizeBody(body)
	
	// 1. Encontrar variáveis que recebem EFX (apenas atribuição direta)
	variables := findEFXVariables(normalized)
	
	// 2. Encontrar EFX direto em funções perigosas
	directMatches := findDirectEFXInFunctions(normalized)
	
	// 3. Encontrar variáveis EFX usadas em funções perigosas
	variableFlows := findVariableFlows(normalized, variables)
	
	// Gerar resultado
	return generateAnalysisResult(directMatches, variableFlows)
}

// Normaliza o corpo HTML/JS
func normalizeBody(body string) string {
	body = strings.ReplaceAll(body, "\n", " ")
	body = strings.ReplaceAll(body, "\r", " ")
	body = strings.ReplaceAll(body, "\t", " ")
	
	// Remover múltiplos espaços
	for strings.Contains(body, "  ") {
		body = strings.ReplaceAll(body, "  ", " ")
	}
	
	return body
}

// Encontra variáveis que recebem EFX (apenas var = "EFX)
func findEFXVariables(text string) map[string]string {
	variables := make(map[string]string)
	
	// APENAS padrões de atribuição direta, NÃO objetos JSON
	patterns := []struct {
		name string
		re   string
	}{
		// var = "EFX (aspas duplas, abertas)
		{"VAR_ASSIGN_DOUBLE", `([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"EFX`},
		// var = 'EFX (aspas simples, abertas)
		{"VAR_ASSIGN_SINGLE", `([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'EFX`},
		// var url = "EFX
		{"VAR_DECL_DOUBLE", `\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"EFX`},
		// var url = 'EFX
		{"VAR_DECL_SINGLE", `\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'EFX`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		matches := re.FindAllStringSubmatch(text, -1)
		
		for _, match := range matches {
			varName := ""
			
			if p.name == "VAR_DECL_DOUBLE" || p.name == "VAR_DECL_SINGLE" {
				if len(match) >= 3 {
					varName = match[2] // nome da variável
				}
			} else if len(match) >= 2 {
				varName = match[1]
			}
			
			if varName != "" {
				context := truncate(match[0], 50)
				variables[varName] = context
			}
		}
	}
	
	return variables
}

// Encontra EFX direto em funções perigosas
func findDirectEFXInFunctions(text string) []string {
	var matches []string
	
	// Todas as funções perigosas que podem receber EFX diretamente
	patterns := []struct {
		name string
		re   string
	}{
		// Execução de código
		{"eval", `eval\s*\(\s*"EFX`},
		{"Function", `new\s+Function\s*\(\s*"EFX`},
		{"setTimeout", `setTimeout\s*\(\s*"EFX`},
		{"setInterval", `setInterval\s*\(\s*"EFX`},
		{"setImmediate", `setImmediate\s*\(\s*"EFX`},
		{"execScript", `execScript\s*\(\s*"EFX`},
		
		// Redirecionamento
		{"location", `location\s*=\s*"EFX`},
		{"location.href", `location\.href\s*=\s*"EFX`},
		{"location.assign", `location\.assign\s*\(\s*"EFX`},
		{"location.replace", `location\.replace\s*\(\s*"EFX`},
		{"window.location", `window\.location\s*=\s*"EFX`},
		{"window.location.href", `window\.location\.href\s*=\s*"EFX`},
		{"document.location", `document\.location\s*=\s*"EFX`},
		{"window.navigate", `window\.navigate\s*\(\s*"EFX`},
		{"redirect", `redirect\s*\(\s*"EFX`},
		
		// Manipulação DOM
		{"document.write", `document\.write\s*\(\s*"EFX`},
		{"document.writeln", `document\.writeln\s*\(\s*"EFX`},
		{"innerHTML", `innerHTML\s*=\s*"EFX`},
		{"outerHTML", `outerHTML\s*=\s*"EFX`},
		{"insertAdjacentHTML", `insertAdjacentHTML\s*\(\s*"EFX`},
		{"insertAdjacentText", `insertAdjacentText\s*\(\s*"EFX`},
		
		// Atributos
		{".src", `\.src\s*=\s*"EFX`},
		{".href", `\.href\s*=\s*"EFX`},
		{".action", `\.action\s*=\s*"EFX`},
		{".formaction", `\.formaction\s*=\s*"EFX`},
		{".data", `\.data\s*=\s*"EFX`},
		{".value", `\.value\s*=\s*"EFX`},
		
		// jQuery
		{"$.html", `\$\([^)]*\)\.html\s*\(\s*"EFX`},
		{"$.append", `\$\([^)]*\)\.append\s*\(\s*"EFX`},
		{"$.prepend", `\$\([^)]*\)\.prepend\s*\(\s*"EFX`},
		{"$.after", `\$\([^)]*\)\.after\s*\(\s*"EFX`},
		{"$.before", `\$\([^)]*\)\.before\s*\(\s*"EFX`},
		{"$.replaceWith", `\$\([^)]*\)\.replaceWith\s*\(\s*"EFX`},
		{"$.attr_src", `\.attr\s*\(\s*["']src["']\s*,\s*"EFX`},
		{"$.attr_href", `\.attr\s*\(\s*["']href["']\s*,\s*"EFX`},
		
		// Outras funções
		{"window.open", `window\.open\s*\(\s*"EFX`},
		{"document.domain", `document\.domain\s*=\s*"EFX`},
		{"postMessage", `postMessage\s*\(\s*"EFX`},
		{"importScripts", `importScripts\s*\(\s*"EFX`},
		
		// React/Vue
		{"dangerouslySetInnerHTML", `dangerouslySetInnerHTML\s*:\s*\{[^}]*__html\s*:\s*"EFX`},
		{"v-html", `v-html\s*=\s*"EFX`},
		
		// Decodificação
		{"decodeURI", `decodeURI\s*\(\s*"EFX`},
		{"decodeURIComponent", `decodeURIComponent\s*\(\s*"EFX`},
		
		// URL
		{"new URL", `new\s+URL\s*\(\s*"EFX`},
		
		// Padrões especiais (como seu exemplo)
		{"func_redirect_combo", `\w+\s*\(\s*"EFX[^)]*\)[^;]*window\.location\.href\s*=\s*"EFX`},
		{"conditional_redirect", `"EFX"[^;]*\?[^:]*window\.location\.href\s*=\s*"EFX`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		found := re.FindAllString(text, -1)
		for _, match := range found {
			matches = append(matches, fmt.Sprintf("%s: %s", p.name, truncate(match, 60)))
		}
	}
	
	return matches
}

// Encontra fluxos: variável EFX → função perigosa
func findVariableFlows(text string, variables map[string]string) []string {
	var flows []string
	
	if len(variables) == 0 {
		return flows
	}
	
	// Para cada variável que contém EFX
	for varName := range variables {
		// Buscar usos desta variável em funções perigosas
		variableUsagePatterns := []struct {
			name string
			re   string
		}{
			// Execução de código
			{"eval", fmt.Sprintf(`eval\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"Function", fmt.Sprintf(`new\s+Function\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"setTimeout", fmt.Sprintf(`setTimeout\s*\(\s*%s\s*[,)]`, regexp.QuoteMeta(varName))},
			{"setInterval", fmt.Sprintf(`setInterval\s*\(\s*%s\s*[,)]`, regexp.QuoteMeta(varName))},
			
			// Redirecionamento
			{"location", fmt.Sprintf(`location\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"location.href", fmt.Sprintf(`location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"window.location", fmt.Sprintf(`window\.location\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"window.location.href", fmt.Sprintf(`window\.location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"location.assign", fmt.Sprintf(`location\.assign\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"location.replace", fmt.Sprintf(`location\.replace\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			
			// Manipulação DOM
			{"innerHTML", fmt.Sprintf(`innerHTML\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"outerHTML", fmt.Sprintf(`outerHTML\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"document.write", fmt.Sprintf(`document\.write\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"document.writeln", fmt.Sprintf(`document\.writeln\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			
			// Atributos
			{".src", fmt.Sprintf(`\.src\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{".href", fmt.Sprintf(`\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{".action", fmt.Sprintf(`\.action\s*=\s*%s`, regexp.QuoteMeta(varName))},
			
			// jQuery
			{"$.html", fmt.Sprintf(`\$\([^)]*\)\.html\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"$.append", fmt.Sprintf(`\$\([^)]*\)\.append\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			
			// Outras
			{"window.open", fmt.Sprintf(`window\.open\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"decodeURIComponent", fmt.Sprintf(`decodeURIComponent\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
		}
		
		for _, pattern := range variableUsagePatterns {
			re := regexp.MustCompile(pattern.re)
			found := re.FindAllString(text, -1)
			
			for _, match := range found {
				flow := fmt.Sprintf("%s=%s → %s: %s", 
					varName, 
					variables[varName], 
					pattern.name, 
					truncate(match, 50))
				flows = append(flows, flow)
			}
		}
	}
	
	return flows
}

// Gera resultado da análise
func generateAnalysisResult(directMatches []string, variableFlows []string) (bool, string) {
	var findings []string
	
	// 1. Matches diretos
	if len(directMatches) > 0 {
		limitedMatches := directMatches
		if len(limitedMatches) > 3 {
			limitedMatches = limitedMatches[:3]
		}
		findings = append(findings, "DIRECT: "+strings.Join(limitedMatches, " | "))
	}
	
	// 2. Fluxos de variáveis
	if len(variableFlows) > 0 {
		limitedFlows := variableFlows
		if len(limitedFlows) > 3 {
			limitedFlows = limitedFlows[:3]
		}
		findings = append(findings, "FLOW: "+strings.Join(limitedFlows, " | "))
	}
	
	if len(findings) > 0 {
		return true, strings.Join(findings, " || ")
	}
	
	return false, ""
}

// Função utilitária para truncar strings
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ==================== FIM DO ALGORITMO ====================

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
