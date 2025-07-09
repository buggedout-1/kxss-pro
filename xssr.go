package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	RedColor   = "\033[91m"
	ResetColor = "\033[0m"
)

var (
	totalTargets  int
	loadedTargets int
	counterMutex  sync.Mutex
	domainList    string
	scanType      string
)

func main() {
	flag.StringVar(&domainList, "l", "", "Path to the file containing the list of URLs.")
	flag.StringVar(&scanType, "t", "", "Scan type: 'xss', 'op' (open redirect), 'path', 'ssti', 'input', or 'script'")
	flag.Parse()

	if domainList == "" || (scanType != "xss" && scanType != "op" && scanType != "path" && scanType != "ssti" && scanType != "input" && scanType != "script") {
		fmt.Println("Usage: go run tool.go -l <file_path> -t <scan_type>")
		fmt.Println("Scan types:")
		fmt.Println("  -t xss    : Test for XSS vulnerabilities")
		fmt.Println("  -t op     : Test for Open Redirect vulnerabilities")
		fmt.Println("  -t path   : Test for reflection in path segments")
		fmt.Println("  -t ssti   : Test for Server-Side Template Injection")
		fmt.Println("  -t input  : Test for reflection inside <input> tags (possible XSS)")
		fmt.Println("  -t script : Test for reflection inside <script> tag variable assignments")
		os.Exit(1)
	}

	urls, err := readURLsFromFile(domainList)
	if err != nil {
		fmt.Println("Error reading URLs from the file:", err)
		os.Exit(1)
	}

	totalTargets = len(urls)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // SSL Bypass
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow redirects
		},
	}

	urlsChannel := make(chan string, totalTargets)
	resultsChannel := make(chan string, totalTargets)
	done := make(chan bool)

	go startWorkerPool(urlsChannel, resultsChannel, 50, client)
	go processResults(resultsChannel, done)

	for _, url := range urls {
		incrementCounter()
		urlsChannel <- url
	}
	close(urlsChannel)

	<-done
}

func startWorkerPool(urls <-chan string, results chan<- string, numWorkers int, client *http.Client) {
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processURLs(urls, results, client)
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()
}

func processURLs(urls <-chan string, results chan<- string, client *http.Client) {
	for rawURL := range urls {
		switch scanType {
		case "xss":
			modifiedURL := replaceURLParams(rawURL, `</buggedou>`)
			testString := `</buggedou>`
			successCondition := func(body string) bool {
				return strings.Contains(body, testString)
			}

			req, err := http.NewRequest("GET", modifiedURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if !isXSSContentType(resp.Header.Get("Content-Type")) {
				continue
			}

			body, readErr := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
			if readErr != nil {
				continue
			}

			if successCondition(string(body)) {
				results <- modifiedURL + "\n"
			}

		case "op":
			modifiedURL := replaceURLParams(rawURL, `https://example.com`)
			testString := `<h1>Example Domain</h1>`
			successCondition := func(body string) bool {
				return strings.Contains(body, testString)
			}

			req, err := http.NewRequest("GET", modifiedURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if !isXSSContentType(resp.Header.Get("Content-Type")) {
				continue
			}

			body, readErr := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
			if readErr != nil {
				continue
			}

			if successCondition(string(body)) {
				results <- modifiedURL + "\n"
			}

		case "path":
			parsedURL, err := url.Parse(rawURL)
			if err != nil {
				continue
			}

			originalParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")
			if len(originalParts) == 0 || originalParts[0] == "" {
				originalParts = []string{}
			}

			for i := 0; i < len(originalParts); i++ {
				modified := make([]string, len(originalParts))
				copy(modified, originalParts)
				modified[i] = "<buggedout>"

				parsedURL.Path = "/" + strings.Join(modified, "/")
				testedURL := parsedURL.String()

				req, err := http.NewRequest("GET", testedURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				if !isXSSContentType(resp.Header.Get("Content-Type")) {
					resp.Body.Close()
					continue
				}

				body, readErr := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
				resp.Body.Close()
				if readErr != nil {
					continue
				}

				if strings.Contains(string(body), "<buggedout>") {
					results <- testedURL + "\n"
					break // move to next base URL
				}
			}

		case "ssti":
			modifiedURL := replaceURLParams(rawURL, `buggedout{{7*7}}`)
			testString := "buggedout49"

			req, err := http.NewRequest("GET", modifiedURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if !isXSSContentType(resp.Header.Get("Content-Type")) {
				continue
			}

			body, readErr := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
			if readErr != nil {
				continue
			}

			if strings.Contains(string(body), testString) {
				results <- modifiedURL + "\n"
			}

		case "input":
			basePayload := "buggedout"
			modifiedURL := replaceURLParams(rawURL, basePayload)

			// Request with base payload to check reflection inside input value attribute
			if reflectedInputValue(client, modifiedURL, basePayload) {
				// Try with double quote injection
				doubleQuotePayload := `"buggedout`
				modifiedURLDouble := replaceURLParams(rawURL, doubleQuotePayload)
				if reflectedInputValue(client, modifiedURLDouble, doubleQuotePayload) {
					results <- modifiedURLDouble + "\n"
					continue
				}

				// Try with single quote injection
				singleQuotePayload := `'buggedout`
				modifiedURLSingle := replaceURLParams(rawURL, singleQuotePayload)
				if reflectedInputValue(client, modifiedURLSingle, singleQuotePayload) {
					results <- modifiedURLSingle + " (Possible XSS via single quote reflection)\n"
					continue
				}
			}

		case "script":
			basePayload := "buggedout"
			modifiedURL := replaceURLParams(rawURL, basePayload)

			body, contentType, err := fetchResponseBody(client, modifiedURL)
			if err != nil || !isXSSContentType(contentType) {
				continue
			}

			if !scriptVarReflectsPayload(body, basePayload) {
				continue
			}

			// Try double quote injection
			doubleQuotePayload := `";buggedout`
			modifiedDouble := replaceURLParams(rawURL, doubleQuotePayload)
			bodyDouble, contentTypeDouble, err := fetchResponseBody(client, modifiedDouble)
			if err == nil && isXSSContentType(contentTypeDouble) && scriptVarReflectsPayload(bodyDouble, doubleQuotePayload) {
				results <- modifiedDouble
				continue
			}

			// Try single quote injection
			singleQuotePayload := `';buggedout`
			modifiedSingle := replaceURLParams(rawURL, singleQuotePayload)
			bodySingle, contentTypeSingle, err := fetchResponseBody(client, modifiedSingle)
			if err == nil && isXSSContentType(contentTypeSingle) && scriptVarReflectsPayload(bodySingle, singleQuotePayload) {
				results <- modifiedSingle + " (Possible XSS via single quote var reflection)\n"
				continue
			}
		}
	}
}

func fetchResponseBody(client *http.Client, targetURL string) (string, string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
	if err != nil {
		return "", "", err
	}
	return string(bodyBytes), resp.Header.Get("Content-Type"), nil
}

// scriptVarReflectsPayload checks if body contains a <script> tag with a JS var assigned a string
// that contains the payload inside the quotes (only considers vars like var someVar = "...payload...")
func scriptVarReflectsPayload(body, payload string) bool {
	// Regex to find JS var assignments inside script tags:
	// This looks for patterns like var foo = "some string here";
	// capturing quote style and content inside.

	// Fixed regex pattern - removed the invalid backreference
	varRe := regexp.MustCompile(`(?i)var\s+\w+\s*=\s*['"][^'"]*` + regexp.QuoteMeta(payload) + `[^'"]*['"]`)
	return varRe.MatchString(body)
}

func isXSSContentType(contentType string) bool {
	contentTypes := []string{
		"text/html",
		"application/xhtml+xml",
		"application/xml",
		"text/xml",
		"image/svg+xml",
	}

	for _, ct := range contentTypes {
		if strings.HasPrefix(contentType, ct) {
			return true
		}
	}
	return false
}

func replaceURLParams(rawURL string, replacement string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	queryParams := parsedURL.Query()
	for key := range queryParams {
		queryParams.Set(key, replacement)
	}
	parsedURL.RawQuery = queryParams.Encode()

	return parsedURL.String()
}

func processResults(results <-chan string, done chan<- bool) {
	for result := range results {
		fmt.Print(result)
	}
	done <- true
}

func readURLsFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		urlsInLine := strings.FieldsFunc(line, func(r rune) bool {
			return r == '\r' || r == '\n' || r == '\t'
		})
		urls = append(urls, urlsInLine...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func incrementCounter() {
	counterMutex.Lock()
	loadedTargets++
	counterMutex.Unlock()
}

func readResponseBodyWithTimeout(body io.Reader, timeout time.Duration) ([]byte, error) {
	done := make(chan struct{})
	var result []byte
	var err error

	go func() {
		defer close(done)
		result, err = io.ReadAll(body)
	}()

	select {
	case <-done:
		return result, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout while reading body")
	}
}

// reflectedInputValue sends a GET request to the URL and checks if the given payload
// is reflected inside the value attribute of an input tag in the response body.
func reflectedInputValue(client *http.Client, testURL, payload string) bool {
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if !isXSSContentType(resp.Header.Get("Content-Type")) {
		return false
	}

	bodyBytes, err := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
	if err != nil {
		return false
	}

	body := string(bodyBytes)
	return inputValueReflected(body, payload)
}

// inputValueReflected checks if the payload is reflected inside any <input ... value="...payload..." ...> or value='...payload...'>
func inputValueReflected(body, payload string) bool {
	// Check if payload is inside value="...payload..." or value='...payload...'
	if strings.Contains(body, `value="`+payload) || strings.Contains(body, `value='`+payload) {
		return true
	}

	return false
}
