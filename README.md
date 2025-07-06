# 🧪 xssr — XSS Reflector

**xssr** is a fast and simple Go tool built for bug bounty hunters and web security researchers.

It helps you detect:

🔹 Reflected **XSS** via query parameters  
🔹 **Open Redirects**  
🔹 Reflected strings in **path segments**
🔹 Reflected SSTI

---

## 💡 Why `<buggedout>`?

Instead of injecting raw XSS payloads, `xssr` uses a harmless test string:

```html
<buggedout>
````

### 🔒 Why not use real payloads?

* 🚫 Real payloads often get blocked by WAFs
* ✅ `<buggedout>` is typically **whitelisted** and safe
* 🔍 Helps detect **reflections without being filtered**
* 🧠 Once reflection is found, **manual payload testing** gives you the edge

> 💥 **The real challenge in XSS is bypassing the WAF — not injecting `<script>`.**

---

## 🚀 Usage

```bash
go run xssr.go -l urls.txt -t [xss | op | path]
```

### 📘 Options

| Flag | Description                       |
| ---- | --------------------------------- |
| `-l` | Path to file with target URLs     |
| `-t` | Scan type: `xss`, `op`, `ssti`, or `path` |

---

## 🔍 Examples

Test for path-based reflection:

```bash
go run xssr.go -l urls.txt -t path
```

Test for reflected XSS via query:

```bash
go run xssr.go -l urls.txt -t xss
```

Test for open redirects:

```bash
go run xssr.go -l urls.txt -t op
```

Test for SSTI:

```bash
go run xssr.go -l urls.txt -t ssti
```

