package main

import (
    "bufio"
    "fmt"
    "io"
    "net/http"
    "flag"
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
    baseURL       string
    domainList    string
)

func main() {
    flag.StringVar(&baseURL, "u", "", "URL")
    flag.StringVar(&domainList, "l", "", "Path to the file containing the list of URLs.")
    flag.Parse()

    if domainList == "" {
        fmt.Println("Usage: go run kxss-pro -l <file_path>")
        os.Exit(1)
    }

    urls, err := readURLsFromFile(domainList)
    if err != nil {
        fmt.Println("Error reading URLs from the file:", err)
        os.Exit(1)
    }

    totalTargets = len(urls)
    client := &http.Client{Timeout: 10 * time.Second}

    // Create channels for communication between main and worker goroutines
    urlsChannel := make(chan string, totalTargets)
    resultsChannel := make(chan string, totalTargets)
    done := make(chan bool)

    // Start the worker pool with 10 goroutines
    go startWorkerPool(urlsChannel, resultsChannel, 10, client)

    // Start the results processor
    go processResults(resultsChannel, done)

    // Feed URLs to the worker pool
    for _, url := range urls {
        incrementCounter()
        urlsChannel <- url
    }
    close(urlsChannel)

    // Wait for all workers to finish
    <-done
}

func startWorkerPool(urls <-chan string, results chan<- string, numWorkers int, client *http.Client) {
    var wg sync.WaitGroup

    // Create worker goroutines
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            processURLs(urls, results, client)
        }()
    }

    // Close the results channel when all workers are done
    go func() {
        wg.Wait()
        close(results)
    }()
}

func processURLs(urls <-chan string, results chan<- string, client *http.Client) {
    for url := range urls {
        // Replace parameters with "></buggedout>"
        modifiedURL := replaceURLParams(url)

        resp, err := client.Get(modifiedURL)
        if err != nil {
            // Handle errors
            continue
        }
        defer resp.Body.Close()

        // Check if content type is suitable for XSS
        contentType := resp.Header.Get("Content-Type")
        if !isXSSContentType(contentType) {
            continue
        }

        // Read the response body with a timeout
        body, readErr := readResponseBodyWithTimeout(resp.Body, 2*time.Second)
        if readErr != nil {
            // Handle read errors
            continue
        }

        // Check if the body contains the reflected string
        if strings.Contains(string(body), `"></buggedout>`) {
            // Only print the URL without extra information
            results <- fmt.Sprintf("%s\n", modifiedURL)
        }
    }
}

// Helper function to check if content type is suitable for XSS
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

// Function to replace all URL parameters with "><buggedout>"
func replaceURLParams(rawURL string) string {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return rawURL // If URL parsing fails, return the original URL
    }

    // Modify query parameters
    queryParams := parsedURL.Query()
    for key := range queryParams {
        queryParams.Set(key, `"></buggedout>`)
    }

    // Rebuild the URL with modified parameters
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
