package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
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
	headers      customheaders
	paramCount   int
	proxy        string
	onlyPOC      bool
	concurrency  int
	methodMode   string
	extractMode  int
	debugMode    bool
	payload      string
	domain       string
)

func init() {
	// Usar https://efxtech.com como payload padrão
	payload = "https://efxtech.com"
	domain = "efxtech.com"
	
	flag.IntVar(&paramCount, "params", 30, "Number of parameters to use per request")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL (shorthand)")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output (shorthand)")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads")
	flag.StringVar(&methodMode, "o", "", "Only run one method: get | post (if omitted, tests both)")
	flag.IntVar(&extractMode, "mode", 1, "Parameter extraction mode: 1=JSON keys, 2=Input name, 3=ID, 4=Query params, 5=var x =")
	flag.BoolVar(&debugMode, "debug", false, "Show debug information (NO_PARAMS, etc)")
	flag.Usage = usage
}

func usage() {
	fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___=

EFX Open Redirect & DOM Reflection Scanner
Payload: https://efxtech.com
Target Domain: efxtech.com

Usage:
  cat urls.txt | ./program [options]
  
Options:
  -params    Number of parameters to inject per request (default: 30)
  -proxy     Proxy address (or -x)
  -H         Headers (ex: -H "Cookie: session=abc")
  -s         Show only PoC output (silent mode)
  -t         Number of threads (default 50)
  -o         Only method: get | post (if omitted, tests both)
  -mode      Parameter extraction mode (default 1):
              1 = JSON keys (['"](key)['"]?:)
              2 = Input name (name="(key)")
              3 = ID (id="(key)")
              4 = Query params ([?&](key)=)
              5 = var x = ((key) =)
  -debug     Show debug information like NO_PARAMS, NOT_REFLECTED
  `)
}

func main() {
	flag.Parse()

	if concurrency < 1 {
		concurrency = 50
	}

	if methodMode != "" {
		m := strings.ToLower(methodMode)
		if m != "get" && m != "post" {
			fmt.Fprintln(os.Stderr, "Invalid -o value. Use 'get' or 'post'.")
			os.Exit(1)
		}
		methodMode = m
	}

	if debugMode {
		fmt.Printf("[*] Starting EFX Scanner (Domain: %s)\n", domain)
		fmt.Printf("[*] Mode: %d, Threads: %d, Params/req: %d\n", extractMode, concurrency, paramCount)
	}

	// Canal para URLs de entrada
	urls := make(chan string, 1000)
	// Canal para resultados
	results := make(chan string, 1000)

	// WaitGroup para workers
	var wg sync.WaitGroup
	var resultWg sync.WaitGroup

	// Iniciar workers de processamento
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			processWorker(workerID, urls, results)
		}(i)
	}

	// Iniciar worker de output
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		outputWorker(results)
	}()

	// Ler URLs do stdin
	scanner := bufio.NewScanner(os.Stdin)
	urlCount := 0
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			urls <- u
			urlCount++
		}
	}

	close(urls)
	wg.Wait()
	close(results)
	resultWg.Wait()

	if debugMode {
		fmt.Printf("[*] Processed %d URLs\n", urlCount)
	}
}

// ==================== PARAMETER EXTRACTION ====================

func extractParameters(body string, mode int) []string {
	var regex *regexp.Regexp
	switch mode {
	case 1:
		// JSON keys: "key": or 'key':
		regex = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	case 2:
		// Input names: name="key"
		regex = regexp.MustCompile(`name=["']([a-zA-Z0-9_-]+)["']`)
	case 3:
		// IDs: id="key"
		regex = regexp.MustCompile(`id=["']([a-zA-Z0-9_-]+)["']`)
	case 4:
		// Query parameters: ?key= ou &key=
		regex = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	case 5:
		// JavaScript variables: key =
		regex = regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*['"]?[^'"]`)
	default:
		return []string{}
	}

	matches := regex.FindAllStringSubmatch(body, -1)
	unique := make(map[string]bool)
	
	for _, m := range matches {
		if len(m) > 1 {
			key := m[1]
			// Filtrar palavras comuns/chaves de sistema
			if !isCommonKey(key) && len(key) > 2 {
				unique[key] = true
			}
		}
	}

	var keys []string
	for k := range unique {
		keys = append(keys, k)
	}
	
	return keys
}

func isCommonKey(key string) bool {
	common := map[string]bool{
		// Palavras comuns em HTML/JS
		"id": true, "name": true, "class": true, "type": true, "value": true,
		"src": true, "href": true, "alt": true, "title": true, "style": true,
		"width": true, "height": true, "method": true, "action": true,
		"data": true, "role": true, "target": true, "rel": true,
		// JavaScript common
		"var": true, "let": true, "const": true, "function": true,
		"return": true, "if": true, "else": true, "for": true, "while": true,
		"true": true, "false": true, "null": true, "undefined": true,
		"this": true, "window": true, "document": true, "location": true,
		// HTTP/URL common
		"http": true, "https": true, "url": true, "uri": true, "path": true,
		"host": true, "port": true, "query": true, "param": true,
	}
	
	return common[strings.ToLower(key)]
}

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	if size <= 0 || len(slice) == 0 {
		return chunks
	}
	
	if size > len(slice) {
		return [][]string{slice}
	}
	
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// ==================== DETECTION ENGINE ====================

func analyzeResponse(resp *http.Response, bodyStr string, requestedURL string) (bool, string) {
	var findings []string
	
	// 1. Detectar Open Redirects (cabeçalhos HTTP)
	redirectFindings := detectHTTPRedirects(resp)
	if len(redirectFindings) > 0 {
		findings = append(findings, redirectFindings...)
	}
	
	// 2. Detectar Reflexões DOM em JavaScript
	domFindings := detectDOMReflections(bodyStr)
	if len(domFindings) > 0 {
		findings = append(findings, domFindings...)
	}
	
	// 3. Detectar HTML Redirects
	htmlFindings := detectHTMLRedirects(bodyStr)
	if len(htmlFindings) > 0 {
		findings = append(findings, htmlFindings...)
	}
	
	if len(findings) > 0 {
		limitedFindings := findings
		if len(limitedFindings) > 3 {
			limitedFindings = limitedFindings[:3]
		}
		return true, strings.Join(limitedFindings, " | ")
	}
	
	return false, ""
}

// ==================== HTTP REDIRECT DETECTION ====================

func detectHTTPRedirects(resp *http.Response) []string {
	var findings []string
	
	// Códigos de status que indicam redirecionamento
	redirectStatusCodes := map[int]bool{
		301: true, // Moved Permanently
		302: true, // Found
		303: true, // See Other
		307: true, // Temporary Redirect
		308: true, // Permanent Redirect
	}
	
	statusCode := resp.StatusCode
	if redirectStatusCodes[statusCode] {
		locationHeader := resp.Header.Get("Location")
		if isExactDomainMatch(locationHeader) {
			findings = append(findings, fmt.Sprintf("HTTP_%d: Location: %s", statusCode, locationHeader))
		}
	}
	
	// Verificar Refresh header
	refreshHeader := resp.Header.Get("Refresh")
	if refreshHeader != "" && containsExactDomain(refreshHeader) && isValidRefreshRedirect(refreshHeader) {
		findings = append(findings, fmt.Sprintf("HTTP_Refresh: %s", refreshHeader))
	}
	
	return findings
}

func isValidRefreshRedirect(refreshHeader string) bool {
	// Padrões válidos para refresh header
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)^\d+\s*;\s*(?:url|URL)\s*=\s*(?:https?://)?efxtech\.com`),
		regexp.MustCompile(`(?i)^(?:url|URL)\s*=\s*(?:https?://)?efxtech\.com`),
	}
	
	cleanHeader := strings.ReplaceAll(refreshHeader, " ", "")
	for _, pattern := range patterns {
		if pattern.MatchString(cleanHeader) {
			return true
		}
	}
	
	return false
}

func isExactDomainMatch(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	
	// Parse a URL para verificar componentes
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	// Verificar se o host é exatamente efxtech.com
	hostname := parsed.Hostname()
	if hostname == "" {
		return false
	}
	
	// Remover porta se existir
	if strings.Contains(hostname, ":") {
		hostname = strings.Split(hostname, ":")[0]
	}
	
	return hostname == "efxtech.com"
}

// ==================== DOM REFLECTION DETECTION ====================

func detectDOMReflections(bodyStr string) []string {
	var findings []string
	
	// Normalizar o corpo (remover espaços extras)
	normalized := normalizeSpaces(bodyStr)
	
	// 1. Detectar variáveis que recebem o payload
	variables := detectPayloadVariables(normalized)
	
	// 2. Detectar payload direto em funções/sinks
	directFindings := detectDirectPayloadUsage(normalized)
	findings = append(findings, directFindings...)
	
	// 3. Detectar fluxos de variáveis (variável -> sink)
	variableFlows := detectVariableFlows(normalized, variables)
	findings = append(findings, variableFlows...)
	
	return findings
}

func detectPayloadVariables(text string) map[string]string {
	variables := make(map[string]string)
	
	patterns := []struct {
		name string
		re   string
	}{
		// Atribuição direta com aspas duplas
		{"VAR_ASSIGN_DOUBLE", fmt.Sprintf(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		// Atribuição direta com aspas simples
		{"VAR_ASSIGN_SINGLE", fmt.Sprintf(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[']%s[']`, regexp.QuoteMeta(strings.TrimPrefix(payload, "https://")))},
		// var/let/const com aspas duplas
		{"VAR_DECL_DOUBLE", fmt.Sprintf(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		// Atribuição parcial (contém o domínio)
		{"VAR_PARTIAL", fmt.Sprintf(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["'][^"']*%s[^"']*["']`, regexp.QuoteMeta("efxtech.com"))},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		matches := re.FindAllStringSubmatch(text, -1)
		
		for _, match := range matches {
			varName := ""
			
			if p.name == "VAR_DECL_DOUBLE" {
				if len(match) >= 3 {
					varName = match[2]
				}
			} else if len(match) >= 2 {
				varName = match[1]
			}
			
			if varName != "" {
				context := truncate(match[0], 60)
				variables[varName] = context
			}
		}
	}
	
	return variables
}

func detectDirectPayloadUsage(text string) []string {
	var findings []string
	
	// Padrões para sinks perigosos que usam o payload diretamente
	sinks := []struct {
		name string
		re   string
	}{
		// Redirecionamento JavaScript
		{"JS_location_href", fmt.Sprintf(`location\.href\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"JS_window_location", fmt.Sprintf(`window\.location\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"JS_window_location_href", fmt.Sprintf(`window\.location\.href\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"JS_location_assign", fmt.Sprintf(`location\.assign\s*\(\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"JS_location_replace", fmt.Sprintf(`location\.replace\s*\(\s*["']%s["']`, regexp.QuoteMeta(payload))},
		
		// Execução de código
		{"JS_eval", fmt.Sprintf(`eval\s*\(\s*["']%s`, regexp.QuoteMeta(payload))},
		{"JS_setTimeout", fmt.Sprintf(`setTimeout\s*\(\s*["']%s`, regexp.QuoteMeta(payload))},
		{"JS_setInterval", fmt.Sprintf(`setInterval\s*\(\s*["']%s`, regexp.QuoteMeta(payload))},
		
		// Manipulação DOM
		{"DOM_innerHTML", fmt.Sprintf(`innerHTML\s*=\s*["']%s`, regexp.QuoteMeta(payload))},
		{"DOM_document_write", fmt.Sprintf(`document\.write\s*\(\s*["']%s`, regexp.QuoteMeta(payload))},
		{"DOM_outerHTML", fmt.Sprintf(`outerHTML\s*=\s*["']%s`, regexp.QuoteMeta(payload))},
		
		// Atributos perigosos
		{"ATTR_src", fmt.Sprintf(`\.src\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"ATTR_href", fmt.Sprintf(`\.href\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
		{"ATTR_action", fmt.Sprintf(`\.action\s*=\s*["']%s["']`, regexp.QuoteMeta(payload))},
	}
	
	for _, sink := range sinks {
		re := regexp.MustCompile(sink.re)
		matches := re.FindAllString(text, -1)
		
		for _, match := range matches {
			// Verificar se não é um falso positivo
			if !isFalsePositive(match) {
				finding := fmt.Sprintf("DOM_DIRECT: %s: %s", sink.name, truncate(match, 70))
				findings = append(findings, finding)
			}
		}
	}
	
	return findings
}

func detectVariableFlows(text string, variables map[string]string) []string {
	var findings []string
	
	if len(variables) == 0 {
		return findings
	}
	
	// Para cada variável que contém o payload
	for varName, varAssignment := range variables {
		// Buscar usos desta variável em sinks perigosos
		sinks := []struct {
			name string
			re   string
		}{
			// Redirecionamento
			{"location_href", fmt.Sprintf(`location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"window_location", fmt.Sprintf(`window\.location\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"window_location_href", fmt.Sprintf(`window\.location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"location_assign", fmt.Sprintf(`location\.assign\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"location_replace", fmt.Sprintf(`location\.replace\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			
			// Execução de código
			{"eval", fmt.Sprintf(`eval\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			{"setTimeout", fmt.Sprintf(`setTimeout\s*\(\s*%s\s*[,)]`, regexp.QuoteMeta(varName))},
			{"setInterval", fmt.Sprintf(`setInterval\s*\(\s*%s\s*[,)]`, regexp.QuoteMeta(varName))},
			
			// Manipulação DOM
			{"innerHTML", fmt.Sprintf(`innerHTML\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{"document_write", fmt.Sprintf(`document\.write\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
			
			// Atributos
			{".src", fmt.Sprintf(`\.src\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{".href", fmt.Sprintf(`\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
			{".action", fmt.Sprintf(`\.action\s*=\s*%s`, regexp.QuoteMeta(varName))},
		}
		
		for _, sink := range sinks {
			re := regexp.MustCompile(sink.re)
			matches := re.FindAllString(text, -1)
			
			for _, match := range matches {
				if !isFalsePositive(match) {
					finding := fmt.Sprintf("DOM_FLOW: %s=%s → %s: %s", 
						varName, truncate(varAssignment, 40), sink.name, truncate(match, 50))
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

// ==================== HTML REDIRECT DETECTION ====================

func detectHTMLRedirects(bodyStr string) []string {
	var findings []string
	
	// Remover conteúdo entre tags script e style
	cleanedBody := removeScriptAndStyle(bodyStr)
	
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		// Meta refresh
		{"HTML_meta_refresh", regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*(?:url|URL)\s*=\s*(?:https?://)?efxtech\.com`)},
		
		// Links que realmente redirecionam
		{"HTML_a_href", regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["'](?:https?://)?efxtech\.com[^>]*>`)},
		
		// Form actions
		{"HTML_form_action", regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["'](?:https?://)?efxtech\.com`)},
		
		// iframe src
		{"HTML_iframe_src", regexp.MustCompile(`(?i)<iframe[^>]+src\s*=\s*["'](?:https?://)?efxtech\.com`)},
	}
	
	for _, p := range patterns {
		matches := p.re.FindAllString(cleanedBody, -1)
		for _, match := range matches {
			if !isFalsePositive(match) {
				findings = append(findings, fmt.Sprintf("%s: %s", p.name, truncate(match, 70)))
			}
		}
	}
	
	return findings
}

// ==================== UTILITY FUNCTIONS ====================

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

func removeScriptAndStyle(html string) string {
	// Remover conteúdo entre <script> tags
	scriptPattern := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	html = scriptPattern.ReplaceAllString(html, "")
	
	// Remover conteúdo entre <style> tags
	stylePattern := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	html = stylePattern.ReplaceAllString(html, "")
	
	return html
}

func containsExactDomain(text string) bool {
	if text == "" {
		return false
	}
	
	// Padrões que indicam redirecionamento REAL (não parâmetros de query)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:url|URL)\s*=\s*(?:https?://)?efxtech\.com(?:[/?#]|$)`),
	}
	
	// Primeiro verificar se não é um parâmetro de query string
	queryParamPattern := regexp.MustCompile(`[?&][^=]+=(?:https?%3A%2F%2F|https?://)?efxtech\.com`)
	if queryParamPattern.MatchString(text) {
		return false
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	
	return false
}

func isFalsePositive(match string) bool {
	// Padrões que indicam provável falso positivo
	falsePositivePatterns := []*regexp.Regexp{
		// Parâmetros de query string
		regexp.MustCompile(`[?&][^=]+=https?://efxtech\.com`),
		// Atributos CSS
		regexp.MustCompile(`:\s*https?://efxtech\.com`),
		// Comentários HTML
		regexp.MustCompile(`<!--.*https?://efxtech\.com.*-->`),
		// Valores JSON
		regexp.MustCompile(`["']https?://efxtech\.com["']\s*:`),
		// URLs codificadas
		regexp.MustCompile(`https?%3A%2F%2Fefxtech\.com`),
	}
	
	for _, pattern := range falsePositivePatterns {
		if pattern.MatchString(match) {
			return true
		}
	}
	
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ==================== WORKERS ====================

func processWorker(workerID int, urls <-chan string, results chan<- string) {
	client := buildClient()
	
	for baseURL := range urls {
		result := processTarget(baseURL, client)
		if result != "" {
			results <- result
		}
	}
}

func outputWorker(results <-chan string) {
	for result := range results {
		fmt.Println(result)
	}
}

func processTarget(baseURL string, client *http.Client) string {
	// 1. Primeiro acessar a URL para extrair parâmetros
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		if debugMode {
			return fmt.Sprintf("\033[1;33mERROR - %s (%v)\033[0m", baseURL, err)
		}
		return ""
	}
	
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	
	resp, err := client.Do(req)
	if err != nil {
		// Não mostra erros a menos que em debug mode
		return ""
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)
	
	// 2. Extrair parâmetros do DOM
	allParams := extractParameters(bodyStr, extractMode)
	
	if len(allParams) == 0 {
		// Sem parâmetros encontrados - só mostra se estiver em debug mode
		if debugMode {
			return fmt.Sprintf("\033[1;33mNO_PARAMS - %s\033[0m", baseURL)
		}
		return ""
	}
	
	// 3. Dividir parâmetros em chunks
	paramChunks := chunkSlice(allParams, paramCount)
	
	var foundIssue bool
	var issueResults []string
	
	// 4. Testar cada chunk de parâmetros
	for _, chunk := range paramChunks {
		if len(chunk) == 0 {
			continue
		}
		
		// Testar com método GET
		if methodMode == "" || methodMode == "get" {
			if result := testMethod("GET", baseURL, chunk, client); result != "" {
				foundIssue = true
				issueResults = append(issueResults, result)
			}
		}
		
		// Testar com método POST
		if methodMode == "" || methodMode == "post" {
			if result := testMethod("POST", baseURL, chunk, client); result != "" {
				foundIssue = true
				issueResults = append(issueResults, result)
			}
		}
	}
	
	// 5. Retornar resultados
	if foundIssue {
		// Se onlyPOC, retornar apenas os que têm problemas
		if onlyPOC {
			var pocResults []string
			for _, r := range issueResults {
				if strings.Contains(r, "REDIRECT") || strings.Contains(r, "DOM_") {
					pocResults = append(pocResults, r)
				}
			}
			return strings.Join(pocResults, "\n")
		}
		return strings.Join(issueResults, "\n")
	}
	
	// Se não encontrou problema, mostra NOT_REFLECTED (sempre mostra)
	// Mas só mostra se não estiver em modo onlyPOC
	if !onlyPOC {
		return fmt.Sprintf("\033[1;30mNOT_REFLECTED - %s (tested %d params)\033[0m", baseURL, len(allParams))
	}
	
	return ""
}

func testMethod(method, base string, params []string, client *http.Client) string {
	urlObj, err := url.Parse(base)
	if err != nil {
		return ""
	}

	var req *http.Request
	var finalURL string
	
	if method == "GET" {
		q := urlObj.Query()
		for _, p := range params {
			q.Set(p, payload)
		}
		urlObj.RawQuery = q.Encode()
		finalURL = urlObj.String()
		
		req, err = http.NewRequest("GET", finalURL, nil)
		if err != nil {
			return ""
		}
	} else {
		postData := url.Values{}
		for _, p := range params {
			postData.Set(p, payload)
		}
		
		finalURL = base
		req, err = http.NewRequest("POST", base, strings.NewReader(postData.Encode()))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Fazer a requisição SEM seguir redirecionamentos
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// Analisar a resposta
	hasIssue, issueContext := analyzeResponse(resp, bodyStr, finalURL)
	
	if hasIssue {
		color := "\033[1;33m" // Amarelo para Open Redirect
		
		// Verificar se é DOM XSS (mais crítico)
		if strings.Contains(issueContext, "DOM_") {
			color = "\033[1;31m" // Vermelho para DOM XSS
		}
		
		paramInfo := fmt.Sprintf("(%d params)", len(params))
		
		if method == "GET" {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s %s | %s\033[0m", color, finalURL, paramInfo, issueContext)
			}
			return fmt.Sprintf("%sGET REFLECTED - %s %s | %s\033[0m", color, finalURL, paramInfo, issueContext)
		} else {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s %s | %s\033[0m", color, base, paramInfo, issueContext)
			}
			return fmt.Sprintf("%sPOST REFLECTED - %s %s | %s\033[0m", color, base, paramInfo, issueContext)
		}
	} else if debugMode && !onlyPOC {
		// Só mostra NOT_REFLECTED se estiver em debug mode
		if method == "GET" {
			return fmt.Sprintf("\033[1;30mGET NOT_REFLECTED - %s (%d params)\033[0m", finalURL, len(params))
		} else {
			return fmt.Sprintf("\033[1;30mPOST NOT_REFLECTED - %s (%d params)\033[0m", base, len(params))
		}
	}

	return ""
}

func buildClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
	}
	
	if proxy != "" {
		if parsedProxy, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(parsedProxy)
		}
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}
