```
# KXSS-Pro

**KXSS-Pro** is a powerful security testing tool that detects two common web vulnerabilities:
1. Reflected XSS (Cross-Site Scripting) by testing parameter reflection
2. Open Redirect vulnerabilities by testing URL redirection

## Features

### XSS Detection
- Automatically replaces URL parameters with `"><buggedout>`
- Detects reflection in response bodies
- Identifies potential XSS vulnerabilities

### Open Redirect Detection
- Replaces URL parameters with `https://example.com`
- Verifies redirects to external domains
- Checks both Location headers and response bodies

### Core Features
- Supports bulk URL testing via input files
- Multi-threaded for fast scanning
- Simple CLI interface
- Configurable timeout settings
- Smart content-type filtering

## Installation

```bash
git clone https://github.com/buggedout-1/kxss-pro.git
cd kxss-pro
go build xssr.go

# Install system-wide (optional)
sudo mv xssr /usr/local/bin/
```

## Usage

### Basic XSS Scanning
```bash
xssr -l urls.txt -t xss
```

### Open Redirect Testing
```bash
xssr -l urls.txt -t op
```

### Options
```
-l string    Path to file containing URLs to test
-t string    Scan type: 'xss' or 'op' (required)
```

## Output
The tool outputs vulnerable URLs where:
- For XSS: The payload is reflected in the response
- For Open Redirect: The site redirects to example.com

## Examples

Test a list of URLs for XSS:
```bash
xssr -l urls.txt -t xss > xss_results.txt
```

Check for open redirects:
```bash
xssr -l urls.txt -t op > redirects.txt
```
