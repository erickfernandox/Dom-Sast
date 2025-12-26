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

EFX Scanner - Open Redirect & DOM Reflection
Payload: https://efxtech.com

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
		fmt.Printf("[*] Starting EFX Scanner (Payload: %s)\n", payload)
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
		regex = regexp.MustCompile(`['"]?([a-zA-Z0-9_-]+)['"]?\s*:`)
	case 2:
		regex = regexp.MustCompile(`name=["']([a-zA-Z0-9_-]+)["']`)
	case 3:
		regex = regexp.MustCompile(`id=["']([a-zA-Z0-9_-]+)["']`)
	case 4:
		regex = regexp.MustCompile(`[?&]([a-zA-Z0-9_-]+)=`)
	case 5:
		regex = regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*['"]?[^'"]`)
	default:
		return []string{}
	}

	matches := regex.FindAllStringSubmatch(body, -1)
	unique := make(map[string]bool)
	
	for _, m := range matches {
		if len(m) > 1 {
			key := m[1]
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
		"id": true, "name": true, "class": true, "type": true, "value": true,
		"src": true, "href": true, "alt": true, "title": true, "style": true,
		"width": true, "height": true, "method": true, "action": true,
		"data": true, "role": true, "target": true, "rel": true,
		"var": true, "let": true, "const": true, "function": true,
		"return": true, "if": true, "else": true, "for": true, "while": true,
		"true": true, "false": true, "null": true, "undefined": true,
		"this": true, "window": true, "document": true, "location": true,
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

func analyzeResponse(resp *http.Response, bodyStr string) (bool, string) {
	// 1. Verificar Open Redirect via HTTP headers
	httpRedirect, httpContext := detectHTTPRedirect(resp)
	if httpRedirect {
		return true, "HTTP_REDIRECT: " + httpContext
	}
	
	// 2. Verificar reflexões DOM no corpo
	domReflection, domContext := detectDOMReflection(bodyStr)
	if domReflection {
		return true, "DOM_REFLECTION: " + domContext
	}
	
	// 3. Verificar HTML redirects
	htmlRedirect, htmlContext := detectHTMLRedirect(bodyStr)
	if htmlRedirect {
		return true, "HTML_REDIRECT: " + htmlContext
	}
	
	return false, ""
}

// ==================== HTTP REDIRECT DETECTION ====================

func detectHTTPRedirect(resp *http.Response) (bool, string) {
	// Verificar status codes de redirect
	redirectCodes := map[int]bool{
		301: true, 302: true, 303: true, 307: true, 308: true,
	}
	
	status := resp.StatusCode
	if redirectCodes[status] {
		location := resp.Header.Get("Location")
		if isExactRedirect(location) {
			return true, fmt.Sprintf("%d Location: %s", status, location)
		}
	}
	
	// Verificar Refresh header
	refresh := resp.Header.Get("Refresh")
	if refresh != "" && containsValidRedirect(refresh) {
		return true, fmt.Sprintf("Refresh: %s", refresh)
	}
	
	return false, ""
}

func isExactRedirect(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	
	// URLs exatas que redirecionam para efxtech.com
	exactURLs := []string{
		"https://efxtech.com",
		"http://efxtech.com",
		"https://efxtech.com/",
		"http://efxtech.com/",
	}
	
	for _, exact := range exactURLs {
		if urlStr == exact {
			return true
		}
	}
	
	// Verificar se começa com https://efxtech.com/ (com path)
	if strings.HasPrefix(urlStr, "https://efxtech.com/") || 
	   strings.HasPrefix(urlStr, "http://efxtech.com/") {
		return true
	}
	
	return false
}

func containsValidRedirect(text string) bool {
	// Padrões válidos para refresh
	patterns := []string{
		`url=https://efxtech.com`,
		`url=http://efxtech.com`,
		`URL=https://efxtech.com`,
		`URL=http://efxtech.com`,
	}
	
	text = strings.ToLower(strings.ReplaceAll(text, " ", ""))
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	
	return false
}

// ==================== DOM REFLECTION DETECTION ====================

func detectDOMReflection(body string) (bool, string) {
	// 1. Encontrar variáveis que recebem EXATAMENTE o payload
	variables := findExactPayloadVariables(body)
	
	// 2. Verificar uso dessas variáveis em sinks perigosos
	if len(variables) > 0 {
		for varName, assignment := range variables {
			if usedInSink(body, varName) {
				return true, fmt.Sprintf("%s = %s -> used in sink", varName, assignment)
			}
		}
	}
	
	// 3. Verificar payload direto em sinks
	directSinks := findDirectPayloadInSinks(body)
	if len(directSinks) > 0 {
		return true, strings.Join(directSinks[:min(2, len(directSinks))], " | ")
	}
	
	return false, ""
}

func findExactPayloadVariables(body string) map[string]string {
	variables := make(map[string]string)
	
	// Padrões EXATOS (deve fechar aspas!)
	patterns := []struct {
		re *regexp.Regexp
	}{
		// var url = "https://efxtech.com"
		{regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"https://efxtech\.com"`)},
		// var url = 'https://efxtech.com'
		{regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'https://efxtech\.com'`)},
		// var url = "https://efxtech.com";
		{regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"https://efxtech\.com";`)},
		// var url = 'https://efxtech.com';
		{regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'https://efxtech\.com';`)},
		// var url = "https://efxtech.com"
		{regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"https://efxtech\.com"`)},
		// var url = 'https://efxtech.com'
		{regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*'https://efxtech\.com'`)},
	}
	
	for _, p := range patterns {
		matches := p.re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			varName := ""
			if len(match) >= 3 && (match[1] == "var" || match[1] == "let" || match[1] == "const") {
				// var url = "https://efxtech.com"
				varName = match[2]
			} else if len(match) >= 2 {
				// url = "https://efxtech.com"
				varName = match[1]
			}
			
			if varName != "" && !strings.Contains(varName, "://") {
				variables[varName] = truncate(match[0], 50)
			}
		}
	}
	
	return variables
}

func usedInSink(body string, varName string) bool {
	// Sinks perigosos que podem usar a variável
	sinks := []struct {
		pattern string
	}{
		// location.href = url
		{fmt.Sprintf(`location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
		// window.location.href = url
		{fmt.Sprintf(`window\.location\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
		// window.location = url
		{fmt.Sprintf(`window\.location\s*=\s*%s`, regexp.QuoteMeta(varName))},
		// location.assign(url)
		{fmt.Sprintf(`location\.assign\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
		// location.replace(url)
		{fmt.Sprintf(`location\.replace\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
		// eval(url)
		{fmt.Sprintf(`eval\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
		// setTimeout(url)
		{fmt.Sprintf(`setTimeout\s*\(\s*%s\s*[,)]`, regexp.QuoteMeta(varName))},
		// innerHTML = url
		{fmt.Sprintf(`innerHTML\s*=\s*%s`, regexp.QuoteMeta(varName))},
		// document.write(url)
		{fmt.Sprintf(`document\.write\s*\(\s*%s\s*\)`, regexp.QuoteMeta(varName))},
		// .src = url
		{fmt.Sprintf(`\.src\s*=\s*%s`, regexp.QuoteMeta(varName))},
		// .href = url
		{fmt.Sprintf(`\.href\s*=\s*%s`, regexp.QuoteMeta(varName))},
	}
	
	for _, sink := range sinks {
		re := regexp.MustCompile(sink.pattern)
		if re.MatchString(body) {
			return true
		}
	}
	
	return false
}

func findDirectPayloadInSinks(body string) []string {
	var findings []string
	
	// Payload direto em sinks
	patterns := []struct {
		name string
		re   string
	}{
		// location.href = "https://efxtech.com"
		{"location.href", `location\.href\s*=\s*["']https://efxtech\.com["']`},
		// window.location.href = "https://efxtech.com"
		{"window.location.href", `window\.location\.href\s*=\s*["']https://efxtech\.com["']`},
		// window.location = "https://efxtech.com"
		{"window.location", `window\.location\s*=\s*["']https://efxtech\.com["']`},
		// location.assign("https://efxtech.com")
		{"location.assign", `location\.assign\s*\(\s*["']https://efxtech\.com["']`},
		// location.replace("https://efxtech.com")
		{"location.replace", `location\.replace\s*\(\s*["']https://efxtech\.com["']`},
		// eval("https://efxtech.com")
		{"eval", `eval\s*\(\s*["']https://efxtech\.com["']`},
		// setTimeout("https://efxtech.com")
		{"setTimeout", `setTimeout\s*\(\s*["']https://efxtech\.com["']`},
		// innerHTML = "https://efxtech.com"
		{"innerHTML", `innerHTML\s*=\s*["']https://efxtech\.com["']`},
		// document.write("https://efxtech.com")
		{"document.write", `document\.write\s*\(\s*["']https://efxtech\.com["']`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			if !isFalsePositive(match) {
				findings = append(findings, fmt.Sprintf("%s: %s", p.name, truncate(match, 60)))
			}
		}
	}
	
	return findings
}

// ==================== HTML REDIRECT DETECTION ====================

func detectHTMLRedirect(body string) (bool, string) {
	// Remover scripts e styles para evitar falsos positivos
	cleaned := removeScriptsAndStyles(body)
	
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		// <meta http-equiv="refresh" content="0;url=https://efxtech.com">
		{"meta_refresh", regexp.MustCompile(`<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=https://efxtech\.com`)},
		// <a href="https://efxtech.com">
		{"a_href", regexp.MustCompile(`<a[^>]+href=["']https://efxtech\.com["'][^>]*>`)},
		// <form action="https://efxtech.com">
		{"form_action", regexp.MustCompile(`<form[^>]+action=["']https://efxtech\.com["'][^>]*>`)},
		// <iframe src="https://efxtech.com">
		{"iframe_src", regexp.MustCompile(`<iframe[^>]+src=["']https://efxtech\.com["'][^>]*>`)},
	}
	
	for _, p := range patterns {
		matches := p.re.FindAllString(cleaned, -1)
		for _, match := range matches {
			if !isFalsePositive(match) {
				return true, fmt.Sprintf("%s: %s", p.name, truncate(match, 60))
			}
		}
	}
	
	return false, ""
}

func removeScriptsAndStyles(html string) string {
	// Remover scripts
	reScript := regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	html = reScript.ReplaceAllString(html, "")
	
	// Remover styles
	reStyle := regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	html = reStyle.ReplaceAllString(html, "")
	
	return html
}

func isFalsePositive(match string) bool {
	// Falsos positivos comuns
	falsePositives := []*regexp.Regexp{
		// Parâmetros de query string: ?url=https://efxtech.com
		regexp.MustCompile(`[?&][^=]+=https://efxtech\.com`),
		// URLs codificadas: https%3A%2F%2Fefxtech.com
		regexp.MustCompile(`https%3A%2F%2Fefxtech\.com`),
		// Comentários: <!-- https://efxtech.com -->
		regexp.MustCompile(`<!--.*https://efxtech\.com.*-->`),
		// JSON values: "url": "https://efxtech.com"
		regexp.MustCompile(`["']https://efxtech\.com["']\s*:`),
		// CSS properties: url(https://efxtech.com)
		regexp.MustCompile(`url\s*\(\s*https://efxtech\.com\s*\)`),
		// Atributos CSS: --color: https://efxtech.com
		regexp.MustCompile(`--[a-z-]+:\s*https://efxtech\.com`),
	}
	
	for _, fp := range falsePositives {
		if fp.MatchString(match) {
			return true
		}
	}
	
	return false
}

// ==================== UTILITY FUNCTIONS ====================

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
	// 1. Acessar URL para extrair parâmetros
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
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
		return ""
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)
	
	// 2. Extrair parâmetros
	allParams := extractParameters(bodyStr, extractMode)
	
	if len(allParams) == 0 {
		if debugMode {
			return fmt.Sprintf("\033[1;33mNO_PARAMS - %s\033[0m", baseURL)
		}
		return ""
	}
	
	// 3. Dividir em chunks e testar
	paramChunks := chunkSlice(allParams, paramCount)
	
	var foundIssues bool
	var issueResults []string
	
	for _, chunk := range paramChunks {
		if len(chunk) == 0 {
			continue
		}
		
		// Testar GET
		if methodMode == "" || methodMode == "get" {
			if result := testMethod("GET", baseURL, chunk, client); result != "" {
				foundIssues = true
				issueResults = append(issueResults, result)
			}
		}
		
		// Testar POST
		if methodMode == "" || methodMode == "post" {
			if result := testMethod("POST", baseURL, chunk, client); result != "" {
				foundIssues = true
				issueResults = append(issueResults, result)
			}
		}
	}
	
	// 4. Retornar resultados
	if foundIssues {
		if onlyPOC {
			var pocResults []string
			for _, r := range issueResults {
				if strings.Contains(r, "REFLECTED") {
					pocResults = append(pocResults, r)
				}
			}
			return strings.Join(pocResults, "\n")
		}
		return strings.Join(issueResults, "\n")
	}
	
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

	// Analisar resposta
	hasReflection, context := analyzeResponse(resp, bodyStr)
	
	if hasReflection {
		color := "\033[1;33m" // Amarelo padrão
		
		// DOM reflection é mais crítico
		if strings.Contains(context, "DOM_REFLECTION") {
			color = "\033[1;31m" // Vermelho
		}
		
		paramInfo := fmt.Sprintf("(%d params)", len(params))
		
		if method == "GET" {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s %s | %s\033[0m", color, finalURL, paramInfo, context)
			}
			return fmt.Sprintf("%sGET REFLECTED - %s %s | %s\033[0m", color, finalURL, paramInfo, context)
		} else {
			if onlyPOC {
				return fmt.Sprintf("%sREFLECTED - %s %s | %s\033[0m", color, base, paramInfo, context)
			}
			return fmt.Sprintf("%sPOST REFLECTED - %s %s | %s\033[0m", color, base, paramInfo, context)
		}
	} else if debugMode && !onlyPOC {
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
