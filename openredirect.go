package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI color codes for formatting
const (
	RedColor   = "\033[91m"
	ResetColor = "\033[0m"
)

var (
	totalTargets  int
	loadedTargets int
	counterMutex  sync.Mutex
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <file_path>")
		os.Exit(1)
	}

	filePath := os.Args[1]

	// Read URLs from the text file
	urls, err := readURLsFromFile(filePath)
	if err != nil {
		fmt.Println("Error reading URLs from the file:", err)
		os.Exit(1)
	}

	// Set the totalTargets variable
	totalTargets = len(urls)

	// Create an HTTP client with a timeout of 5 seconds
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create channels for communication between main and worker goroutines
	jobs := make(chan string, totalTargets)
	results := make(chan string, totalTargets)

	// Start worker pool with 40 workers
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(client, jobs, results)
		}()
	}

	// Start a goroutine to print the live counter
	go liveCounter()

	// Feed jobs to the workers
	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()

	// Process results
	close(results)
	for res := range results {
		fmt.Print(res)
	}

	// Print the final counter
	counterMutex.Lock()
	fmt.Printf("\rTargets Loaded: [%d/%d] #\n", loadedTargets, totalTargets)
	counterMutex.Unlock()
}

func worker(client *http.Client, jobs <-chan string, results chan<- string) {
	for url := range jobs {
		// Increment the loaded targets counter
		incrementCounter()

		// Make an HTTP GET request with the custom timeout
		resp, err := client.Get(url)
		if err != nil {
			// Check for timeout error and skip silently
			if strings.Contains(err.Error(), "Client.Timeout exceeded while awaiting headers") {
				continue
			}
			// Skip silently for other errors
			continue
		}
		defer resp.Body.Close()

		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// Skip silently if there is an error reading the response body
			continue
		}

		// Check if the response body contains the phrase "Example Domain"
		if strings.Contains(string(body), "Example Domain") {
			results <- fmt.Sprintf("[*][%s]%s[ OPEN-REDIRECT found!]%s\n", url, RedColor, ResetColor)
		}
	}
}

// readURLsFromFile reads URLs from a text file and returns a slice of URLs
func readURLsFromFile(filePath string) ([]string, error) {
	var urls []string

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// liveCounter prints the live counter periodically
func liveCounter() {
	for {
		time.Sleep(1 * time.Second)
		counterMutex.Lock()
		fmt.Printf("\rTargets Loaded: [%d/%d]", loadedTargets, totalTargets)
		counterMutex.Unlock()
	}
}

// incrementCounter increments the loaded targets counter
func incrementCounter() {
	counterMutex.Lock()
	loadedTargets++
	counterMutex.Unlock()
}
