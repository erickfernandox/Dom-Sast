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

// getAllDangerousFunctions retorna todas as funções perigosas DOM XSS/Redirect
func getAllDangerousFunctions() []struct {
	name    string
	pattern string
} {
	return []struct {
		name    string
		pattern string
	}{
		// ========== EXECUÇÃO DE CÓDIGO (CRÍTICO) ==========
		// eval()
		{"EVAL", `eval\s*\(\s*["']EFX`},
		{"EVAL_SINGLE", `eval\s*\(\s*[']EFX`},
		{"EVAL_VAR", `eval\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// Function()
		{"FUNCTION", `new\s+Function\s*\(\s*["']EFX`},
		{"FUNCTION_SINGLE", `new\s+Function\s*\(\s*[']EFX`},
		{"FUNCTION_VAR", `new\s+Function\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// setTimeout()
		{"SETTIMEOUT", `setTimeout\s*\(\s*["']EFX`},
		{"SETTIMEOUT_SINGLE", `setTimeout\s*\(\s*[']EFX[']`},
		{"SETTIMEOUT_VAR", `setTimeout\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// setInterval()
		{"SETINTERVAL", `setInterval\s*\(\s*["']EFX`},
		{"SETINTERVAL_SINGLE", `setInterval\s*\(\s*[']EFX[']`},
		{"SETINTERVAL_VAR", `setInterval\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// setImmediate()
		{"SETIMMEDIATE", `setImmediate\s*\(\s*["']EFX`},
		{"SETIMMEDIATE_SINGLE", `setImmediate\s*\(\s*[']EFX[']`},
		{"SETIMMEDIATE_VAR", `setImmediate\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// execScript() (IE)
		{"EXECSCRIPT", `execScript\s*\(\s*["']EFX`},
		{"EXECSCRIPT_SINGLE", `execScript\s*\(\s*[']EFX[']`},
		{"EXECSCRIPT_VAR", `execScript\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== REDIRECIONAMENTO (ALTO) ==========
		// location
		{"LOCATION", `location\s*=\s*["']EFX`},
		{"LOCATION_SINGLE", `location\s*=\s*[']EFX[']`},
		{"LOCATION_VAR", `location\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// location.href
		{"LOCATION_HREF", `location\.href\s*=\s*["']EFX`},
		{"LOCATION_HREF_SINGLE", `location\.href\s*=\s*[']EFX[']`},
		{"LOCATION_HREF_VAR", `location\.href\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// location.assign()
		{"LOCATION_ASSIGN", `location\.assign\s*\(\s*["']EFX`},
		{"LOCATION_ASSIGN_SINGLE", `location\.assign\s*\(\s*[']EFX`},
		{"LOCATION_ASSIGN_VAR", `location\.assign\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// location.replace()
		{"LOCATION_REPLACE", `location\.replace\s*\(\s*["']EFX`},
		{"LOCATION_REPLACE_SINGLE", `location\.replace\s*\(\s*[']EFX`},
		{"LOCATION_REPLACE_VAR", `location\.replace\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// window.location
		{"WINDOW_LOCATION", `window\.location\s*=\s*["']EFX`},
		{"WINDOW_LOCATION_SINGLE", `window\.location\s*=\s*[']EFX[']`},
		{"WINDOW_LOCATION_VAR", `window\.location\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// window.location.href
		{"WINDOW_HREF", `window\.location\.href\s*=\s*["']EFX`},
		{"WINDOW_HREF_SINGLE", `window\.location\.href\s*=\s*[']EFX[']`},
		{"WINDOW_HREF_VAR", `window\.location\.href\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// document.location
		{"DOCUMENT_LOCATION", `document\.location\s*=\s*["']EFX`},
		{"DOCUMENT_LOCATION_SINGLE", `document\.location\s*=\s*[']EFX[']`},
		{"DOCUMENT_LOCATION_VAR", `document\.location\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// redirect()
		{"REDIRECT", `redirect\s*\(\s*["']EFX`},
		{"REDIRECT_SINGLE", `redirect\s*\(\s*[']EFX`},
		{"REDIRECT_VAR", `redirect\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// window.navigate() (IE)
		{"WINDOW_NAVIGATE", `window\.navigate\s*\(\s*["']EFX`},
		{"WINDOW_NAVIGATE_SINGLE", `window\.navigate\s*\(\s*[']EFX`},
		{"WINDOW_NAVIGATE_VAR", `window\.navigate\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== MANIPULAÇÃO DOM (ALTO) ==========
		// document.write()
		{"DOCUMENT_WRITE", `document\.write\s*\(\s*["']EFX`},
		{"DOCUMENT_WRITE_SINGLE", `document\.write\s*\(\s*[']EFX`},
		{"DOCUMENT_WRITE_VAR", `document\.write\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// document.writeln()
		{"DOCUMENT_WRITELN", `document\.writeln\s*\(\s*["']EFX`},
		{"DOCUMENT_WRITELN_SINGLE", `document\.writeln\s*\(\s*[']EFX`},
		{"DOCUMENT_WRITELN_VAR", `document\.writeln\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// innerHTML
		{"INNERHTML", `innerHTML\s*=\s*["']EFX`},
		{"INNERHTML_SINGLE", `innerHTML\s*=\s*[']EFX[']`},
		{"INNERHTML_VAR", `innerHTML\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// outerHTML
		{"OUTERHTML", `outerHTML\s*=\s*["']EFX`},
		{"OUTERHTML_SINGLE", `outerHTML\s*=\s*[']EFX[']`},
		{"OUTERHTML_VAR", `outerHTML\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// insertAdjacentHTML()
		{"INSERT_ADJACENT", `insertAdjacentHTML\s*\(\s*["']EFX`},
		{"INSERT_ADJACENT_SINGLE", `insertAdjacentHTML\s*\(\s*[']EFX[']`},
		{"INSERT_ADJACENT_VAR", `insertAdjacentHTML\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// insertAdjacentText()
		{"INSERT_ADJACENT_TEXT", `insertAdjacentText\s*\(\s*["']EFX`},
		{"INSERT_ADJACENT_TEXT_SINGLE", `insertAdjacentText\s*\(\s*[']EFX[']`},
		{"INSERT_ADJACENT_TEXT_VAR", `insertAdjacentText\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== ATRIBUTOS PERIGOSOS (MÉDIO) ==========
		// src
		{"SRC", `\.src\s*=\s*["']EFX`},
		{"SRC_SINGLE", `\.src\s*=\s*[']EFX[']`},
		{"SRC_VAR", `\.src\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// href
		{"HREF", `\.href\s*=\s*["']EFX`},
		{"HREF_SINGLE", `\.href\s*=\s*[']EFX[']`},
		{"HREF_VAR", `\.href\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// action
		{"ACTION", `\.action\s*=\s*["']EFX`},
		{"ACTION_SINGLE", `\.action\s*=\s*[']EFX[']`},
		{"ACTION_VAR", `\.action\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// formaction
		{"FORMACTION", `\.formaction\s*=\s*["']EFX`},
		{"FORMACTION_SINGLE", `\.formaction\s*=\s*[']EFX[']`},
		{"FORMACTION_VAR", `\.formaction\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// data
		{"DATA", `\.data\s*=\s*["']EFX`},
		{"DATA_SINGLE", `\.data\s*=\s*[']EFX[']`},
		{"DATA_VAR", `\.data\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// value (em contexto específico)
		{"VALUE", `\.value\s*=\s*["']EFX`},
		{"VALUE_SINGLE", `\.value\s*=\s*[']EFX[']`},
		{"VALUE_VAR", `\.value\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== JQUERY (MÉDIO) ==========
		// $().html()
		{"JQUERY_HTML", `\$\([^)]*\)\.html\s*\(\s*["']EFX`},
		{"JQUERY_HTML_SINGLE", `\$\([^)]*\)\.html\s*\(\s*[']EFX`},
		{"JQUERY_HTML_VAR", `\$\([^)]*\)\.html\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().append()
		{"JQUERY_APPEND", `\$\([^)]*\)\.append\s*\(\s*["']EFX`},
		{"JQUERY_APPEND_SINGLE", `\$\([^)]*\)\.append\s*\(\s*[']EFX`},
		{"JQUERY_APPEND_VAR", `\$\([^)]*\)\.append\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().prepend()
		{"JQUERY_PREPEND", `\$\([^)]*\)\.prepend\s*\(\s*["']EFX`},
		{"JQUERY_PREPEND_SINGLE", `\$\([^)]*\)\.prepend\s*\(\s*[']EFX`},
		{"JQUERY_PREPEND_VAR", `\$\([^)]*\)\.prepend\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().after()
		{"JQUERY_AFTER", `\$\([^)]*\)\.after\s*\(\s*["']EFX`},
		{"JQUERY_AFTER_SINGLE", `\$\([^)]*\)\.after\s*\(\s*[']EFX`},
		{"JQUERY_AFTER_VAR", `\$\([^)]*\)\.after\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().before()
		{"JQUERY_BEFORE", `\$\([^)]*\)\.before\s*\(\s*["']EFX`},
		{"JQUERY_BEFORE_SINGLE", `\$\([^)]*\)\.before\s*\(\s*[']EFX`},
		{"JQUERY_BEFORE_VAR", `\$\([^)]*\)\.before\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().replaceWith()
		{"JQUERY_REPLACE", `\$\([^)]*\)\.replaceWith\s*\(\s*["']EFX`},
		{"JQUERY_REPLACE_SINGLE", `\$\([^)]*\)\.replaceWith\s*\(\s*[']EFX`},
		{"JQUERY_REPLACE_VAR", `\$\([^)]*\)\.replaceWith\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// $().attr() perigoso
		{"JQUERY_ATTR_SRC", `\.attr\s*\(\s*["']src["']\s*,\s*["']EFX`},
		{"JQUERY_ATTR_HREF", `\.attr\s*\(\s*["']href["']\s*,\s*["']EFX`},
		{"JQUERY_ATTR_VAR", `\.attr\s*\(\s*["'](?:src|href|action)["']\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== OUTRAS FUNÇÕES PERIGOSAS ==========
		// window.open()
		{"WINDOW_OPEN", `window\.open\s*\(\s*["']EFX`},
		{"WINDOW_OPEN_SINGLE", `window\.open\s*\(\s*[']EFX[']`},
		{"WINDOW_OPEN_VAR", `window\.open\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// document.domain (em contexto)
		{"DOCUMENT_DOMAIN", `document\.domain\s*=\s*["']EFX`},
		{"DOCUMENT_DOMAIN_SINGLE", `document\.domain\s*=\s*[']EFX[']`},
		{"DOCUMENT_DOMAIN_VAR", `document\.domain\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// postMessage() (em contexto)
		{"POSTMESSAGE", `postMessage\s*\(\s*["']EFX`},
		{"POSTMESSAGE_SINGLE", `postMessage\s*\(\s*[']EFX[']`},
		{"POSTMESSAGE_VAR", `postMessage\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// importScripts() (Web Workers)
		{"IMPORT_SCRIPTS", `importScripts\s*\(\s*["']EFX`},
		{"IMPORT_SCRIPTS_SINGLE", `importScripts\s*\(\s*[']EFX`},
		{"IMPORT_SCRIPTS_VAR", `importScripts\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== FUNÇÕES DE SANITIZAÇÃO FRACA ==========
		// dangerouslySetInnerHTML (React)
		{"REACT_DANGEROUS", `dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*["']EFX`},
		{"REACT_DANGEROUS_SINGLE", `dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*[']EFX[']`},
		{"REACT_DANGEROUS_VAR", `dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// v-html (Vue.js)
		{"VUE_HTML", `v-html\s*=\s*["']EFX`},
		{"VUE_HTML_SINGLE", `v-html\s*=\s*[']EFX[']`},
		{"VUE_HTML_VAR", `v-html\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== FUNÇÕES DE CODIFICAÇÃO/DECODIFICAÇÃO ==========
		// decodeURI()
		{"DECODEURI", `decodeURI\s*\(\s*["']EFX`},
		{"DECODEURI_SINGLE", `decodeURI\s*\(\s*[']EFX`},
		{"DECODEURI_VAR", `decodeURI\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// decodeURIComponent()
		{"DECODEURICOMPONENT", `decodeURIComponent\s*\(\s*["']EFX`},
		{"DECODEURICOMPONENT_SINGLE", `decodeURIComponent\s*\(\s*[']EFX`},
		{"DECODEURICOMPONENT_VAR", `decodeURIComponent\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
		
		// ========== FUNÇÕES DE CONSTRUÇÃO DE URL ==========
		// new URL()
		{"NEW_URL", `new\s+URL\s*\(\s*["']EFX`},
		{"NEW_URL_SINGLE", `new\s+URL\s*\(\s*[']EFX[']`},
		{"NEW_URL_VAR", `new\s+URL\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)`},
	}
}

// findVariablesWithEFX encontra variáveis que recebem "EFX" ou 'EFX'
func findVariablesWithEFX(body string) map[string]string {
	variables := make(map[string]string)
	
	patterns := []struct {
		name    string
		pattern string
	}{
		{"JSON_KEY", `["']([^"']+)["']\s*:\s*["']EFX["']`},
		{"JSON_KEY_SINGLE", `["']([^"']+)["']\s*:\s*[']EFX[']`},
		{"PHP_ARRAY", `["']([^"']+)["']\s*=>\s*["']EFX["']`},
		{"VAR_DECL_DOUBLE", `(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["']EFX["']`},
		{"VAR_DECL_SINGLE", `(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[']EFX[']`},
		{"ASSIGN_DOUBLE", `([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["']EFX["']`},
		{"ASSIGN_SINGLE", `([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[']EFX[']`},
		{"PROP_DOUBLE", `([a-zA-Z_$][.a-zA-Z0-9_$]*)\s*=\s*["']EFX["']`},
		{"PROP_SINGLE", `([a-zA-Z_$][.a-zA-Z0-9_$]*)\s*=\s*[']EFX[']`},
	}
	
	for _, p := range patterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				varName := match[1]
				fullMatch := cleanMatch(match[0])
				variables[varName] = fmt.Sprintf("%s: %s", p.name, fullMatch)
			}
		}
	}
	
	return variables
}

// scanForAllDangerousFunctions verifica EFX em todas as funções perigosas
func scanForAllDangerousFunctions(body string) ([]string, map[string][]string) {
	var directMatches []string
	variableUsage := make(map[string][]string)
	
	// Primeiro, encontrar todas as variáveis que recebem EFX
	variables := findVariablesWithEFX(body)
	
	// Para cada função perigosa
	for _, funcDef := range getAllDangerousFunctions() {
		re := regexp.MustCompile(funcDef.pattern)
		
		// Procurar matches diretos com EFX
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 0 {
				fullMatch := cleanMatch(match[0])
				
				// Verificar se é match direto com EFX ou variável
				if strings.Contains(funcDef.pattern, `["']EFX["']`) || 
				   strings.Contains(funcDef.pattern, `[']EFX[']`) {
					// É match direto com EFX
					directMatches = append(directMatches, fmt.Sprintf("%s: %s", funcDef.name, fullMatch))
				} else if strings.Contains(funcDef.pattern, `[a-zA-Z_$][a-zA-Z0-9_$]*\)`) && len(match) > 1 {
					// É match com variável
					varName := match[1]
					
					// Verificar se esta variável recebeu EFX
					if _, exists := variables[varName]; exists {
						usage := fmt.Sprintf("%s: %s", funcDef.name, fullMatch)
						key := fmt.Sprintf("%s->%s", varName, funcDef.name)
						if _, exists := variableUsage[key]; !exists {
							variableUsage[key] = []string{usage}
						}
					}
				}
			}
		}
	}
	
	return directMatches, variableUsage
}

// analyzeReflection analisa todas as reflexões
func analyzeReflection(body string) (bool, string) {
	// 1. Verificar funções perigosas com EFX direto ou variáveis
	directMatches, variableUsage := scanForAllDangerousFunctions(body)
	
	var findings []string
	
	// Adicionar matches diretos
	if len(directMatches) > 0 {
		findings = append(findings, "DIRECT: "+strings.Join(directMatches[:min(3, len(directMatches))], " | "))
	}
	
	// Adicionar usos de variáveis
	if len(variableUsage) > 0 {
		var flows []string
		for key, usages := range variableUsage {
			if len(usages) > 0 {
				// Extrair nome da variável da chave
				parts := strings.Split(key, "->")
				if len(parts) == 2 {
					varName := parts[0]
					funcName := parts[1]
					
					// Buscar como a variável recebeu EFX
					variables := findVariablesWithEFX(body)
					if assignment, exists := variables[varName]; exists {
						flow := fmt.Sprintf("%s -> %s: %s", assignment, funcName, strings.Join(usages, ", "))
						flows = append(flows, flow)
					}
				}
			}
		}
		
		if len(flows) > 0 {
			findings = append(findings, "FLOW: "+strings.Join(flows[:min(3, len(flows))], " || "))
		}
	}
	
	if len(findings) > 0 {
		return true, strings.Join(findings, " || ")
	}
	
	return false, ""
}

func cleanMatch(match string) string {
	match = strings.ReplaceAll(match, "\n", " ")
	match = strings.ReplaceAll(match, "\r", " ")
	match = strings.ReplaceAll(match, "\t", " ")
	
	for strings.Contains(match, "  ") {
		match = strings.ReplaceAll(match, "  ", " ")
	}
	
	if len(match) > 70 {
		match = match[:67] + "..."
	}
	
	return strings.TrimSpace(match)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
