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

EFX Open Redirect Scanner with Auto-Parameter Extraction
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

// ==================== OPEN REDIRECT DETECTION ====================

func detectOpenRedirects(resp *http.Response, bodyStr string) (bool, string) {
	var findings []string
	
	// 1. Verificar cabeçalhos HTTP
	locationHeader := resp.Header.Get("Location")
	if isExactDomainMatch(locationHeader) {
		findings = append(findings, fmt.Sprintf("HTTP_Location: %s", locationHeader))
	}
	
	refreshHeader := resp.Header.Get("Refresh")
	if containsExactDomain(refreshHeader) {
		findings = append(findings, fmt.Sprintf("HTTP_Refresh: %s", refreshHeader))
	}
	
	// 2. Verificar corpo HTML
	htmlFindings := detectHTMLRedirects(bodyStr)
	if len(htmlFindings) > 0 {
		findings = append(findings, htmlFindings...)
	}
	
	if len(findings) > 0 {
		limitedFindings := findings
		if len(limitedFindings) > 3 {
			limitedFindings = limitedFindings[:3]
		}
		return true, "OPEN_REDIRECT: " + strings.Join(limitedFindings, " | ")
	}
	
	return false, ""
}

func isExactDomainMatch(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	
	// Verificar URLs exatas
	exactMatches := []string{
		"https://efxtech.com",
		"http://efxtech.com",
		"https://efxtech.com/",
		"http://efxtech.com/",
	}
	
	for _, match := range exactMatches {
		if urlStr == match {
			return true
		}
	}
	
	// Verificar se começa com o domínio
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^https?://efxtech\.com(/|$)`),
		regexp.MustCompile(`^//efxtech\.com(/|$)`),
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(urlStr) {
			return true
		}
	}
	
	return false
}

func containsExactDomain(text string) bool {
	if text == "" {
		return false
	}
	
	patterns := []*regexp.Regexp{
		// Meta refresh patterns
		regexp.MustCompile(`url\s*=\s*(?:['"])?(?:https?://)?efxtech\.com(?:['"])?`),
		regexp.MustCompile(`URL\s*=\s*(?:['"])?(?:https?://)?efxtech\.com(?:['"])?`),
		// Location patterns in JavaScript
		regexp.MustCompile(`location\s*\.\s*(?:href|assign|replace)\s*=\s*(?:['"])?(?:https?://)?efxtech\.com(?:['"])?`),
		regexp.MustCompile(`window\s*\.\s*location\s*=\s*(?:['"])?(?:https?://)?efxtech\.com(?:['"])?`),
	}
	
	for _, pattern := range patterns {
		if pattern.MatchString(strings.ToLower(text)) {
			return true
		}
	}
	
	return false
}

func detectHTMLRedirects(bodyStr string) []string {
	var findings []string
	
	// Normalizar o corpo
	normalized := strings.ToLower(bodyStr)
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "\n", "")
	normalized = strings.ReplaceAll(normalized, "\r", "")
	normalized = strings.ReplaceAll(normalized, "\t", "")
	
	// Padrões exatos para procurar
	patterns := []struct {
		name string
		re   string
	}{
		// Meta refresh
		{"meta_refresh", `http-equiv=["']refresh["'][^>]*content=["'][^"']*url\s*=\s*(?:https?://)?efxtech\.com`},
		{"meta_refresh_short", `content=["'][^"']*url\s*=\s*(?:https?://)?efxtech\.com`},
		
		// JavaScript redirects
		{"js_location_href", `location\.href\s*=\s*(?:['"])?(?:https?://)?efxtech\.com`},
		{"js_window_location", `window\.location\s*=\s*(?:['"])?(?:https?://)?efxtech\.com`},
		{"js_location_assign", `location\.assign\s*\(\s*(?:['"])?(?:https?://)?efxtech\.com`},
		{"js_location_replace", `location\.replace\s*\(\s*(?:['"])?(?:https?://)?efxtech\.com`},
		
		// Links e forms
		{"a_href", `<a[^>]*href=["'](?:https?://)?efxtech\.com`},
		{"form_action", `<form[^>]*action=["'](?:https?://)?efxtech\.com`},
		{"iframe_src", `<iframe[^>]*src=["'](?:https?://)?efxtech\.com`},
		
		// Outras formas
		{"window_open", `window\.open\s*\(\s*(?:['"])?(?:https?://)?efxtech\.com`},
		{"window_navigate", `window\.navigate\s*\(\s*(?:['"])?(?:https?://)?efxtech\.com`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.re)
		matches := re.FindAllString(normalized, -1)
		
		for _, match := range matches {
			// Limitar o tamanho do match para exibição
			if len(match) > 80 {
				match = match[:77] + "..."
			}
			findings = append(findings, fmt.Sprintf("%s: %s", p.name, match))
		}
	}
	
	return findings
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
	
	var foundRedirect bool
	var redirectResults []string
	
	// 4. Testar cada chunk de parâmetros
	for _, chunk := range paramChunks {
		if len(chunk) == 0 {
			continue
		}
		
		// Testar com método GET
		if methodMode == "" || methodMode == "get" {
			if result := testMethod("GET", baseURL, chunk, client); result != "" {
				foundRedirect = true
				redirectResults = append(redirectResults, result)
			}
		}
		
		// Testar com método POST
		if methodMode == "" || methodMode == "post" {
			if result := testMethod("POST", baseURL, chunk, client); result != "" {
				foundRedirect = true
				redirectResults = append(redirectResults, result)
			}
		}
	}
	
	// 5. Retornar resultados
	if foundRedirect {
		// Se onlyPOC, retornar apenas os que têm redirect
		if onlyPOC {
			var pocResults []string
			for _, r := range redirectResults {
				if strings.Contains(r, "REDIRECT") {
					pocResults = append(pocResults, r)
				}
			}
			return strings.Join(pocResults, "\n")
		}
		return strings.Join(redirectResults, "\n")
	}
	
	// Se não encontrou redirect, mostra NOT_REFLECTED (sempre mostra)
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

	// Verificar por Open Redirect
	hasRedirect, redirectContext := detectOpenRedirects(resp, bodyStr)
	
	if hasRedirect {
		color := "\033[1;33m" // Amarelo para Open Redirect
		paramInfo := fmt.Sprintf("(%d params)", len(params))
		
		if method == "GET" {
			if onlyPOC {
				return fmt.Sprintf("%sREDIRECT - %s %s | %s\033[0m", color, finalURL, paramInfo, redirectContext)
			}
			return fmt.Sprintf("%sGET REDIRECT - %s %s | %s\033[0m", color, finalURL, paramInfo, redirectContext)
		} else {
			if onlyPOC {
				return fmt.Sprintf("%sREDIRECT - %s %s | %s\033[0m", color, base, paramInfo, redirectContext)
			}
			return fmt.Sprintf("%sPOST REDIRECT - %s %s | %s\033[0m", color, base, paramInfo, redirectContext)
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
