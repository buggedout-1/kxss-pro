# kxss-pro
**KXSS-Pro** is a tool designed to automatically detect potential reflected XSS vulnerabilities by replacing URL parameters with `"><buggedout>` and checking if this is reflected in the response body.
## Features

- Automatically replaces URL parameters with `"><buggedout>`.
- Sends HTTP requests to modified URLs.
- Detects if `"><buggedout>` is reflected in the response, indicating potential XSS vulnerabilities.
- Supports bulk URL testing via a list.
- Fast

## Installation

   ```bash
   git clone https://github.com/buggedout-1/kxss-pro.git
   cd kxss-pro
   go build kxss-pro.go
   sudo cp kxss-pro /usr/local/bin #to run it every where
   ```
## Usage
```bash
kxss-pro -l [ list of urls path ]
or from directory
go run kxss-pro.go -l [ list of urls path ]
```
