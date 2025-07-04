package main

import (
    "bufio"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
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
    flag.StringVar(&scanType, "t", "", "Scan type: 'xss' or 'op' (open redirect)")
    flag.Parse()

    if domainList == "" || (scanType != "xss" && scanType != "op") {
        fmt.Println("Usage: go run tool.go -l <file_path> -t <scan_type>")
        fmt.Println("Scan types:")
        fmt.Println("  -t xss   : Test for XSS vulnerabilities")
        fmt.Println("  -t op    : Test for Open Redirect vulnerabilities")
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
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Don't follow redirects
        },
    }

    urlsChannel := make(chan string, totalTargets)
    resultsChannel := make(chan string, totalTargets)
    done := make(chan bool)

    go startWorkerPool(urlsChannel, resultsChannel, 10, client)
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
    for url := range urls {
        var modifiedURL string
        var testString string
        var successCondition func(string) bool

        switch scanType {
        case "xss":
            modifiedURL = replaceURLParams(url, `</buggedou>`)
            testString = `</buggedou>`
            successCondition = func(body string) bool {
                return strings.Contains(body, testString)
            }
        case "op":
            modifiedURL = replaceURLParams(url, `https://example.com`)
            testString = `https://example.com`
            successCondition = func(body string) bool {
                // Check for redirect location header or example.com in body
                resp, err := client.Get(modifiedURL)
                if err != nil {
                    return false
                }
                defer resp.Body.Close()

                // Check Location header for open redirect
                if loc, err := resp.Location(); err == nil && strings.Contains(loc.String(), "example.com") {
                    return true
                }

                // Check body for example.com content
                bodyBytes, err := io.ReadAll(resp.Body)
                if err != nil {
                    return false
                }
                return strings.Contains(string(bodyBytes), `<h1>Example Domain</h1>`)
            }
        default:
            continue
        }

        resp, err := client.Get(modifiedURL)
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
            results <- fmt.Sprintf("%s\n", modifiedURL)
        }
    }
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
        if strings.Contains(contentType, ct) {
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
        return nil, fmt.Errorf("context deadline exceeded (Client.Timeout or context cancellation while reading body)")
    }
}
