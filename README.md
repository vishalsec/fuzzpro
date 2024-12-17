# FuzzPro

**FuzzPro** is a powerful, multi-threaded brute-forcing tool for discovering hidden files and directories on web servers. It includes WAF detection, response code filtering, request throttling, and real-time progress indicators.

---

## Features

- **Custom WAF Detection:** Detects blocking patterns like 403/429, captchas, or access denial text and waits for a user-defined duration.
- **Response Code Filtering:** Suppress specified HTTP response codes in the output.
- **Request Throttling:** Control the number of requests sent per second.
- **Progress Indicator:** Displays the completion progress in percentage.

---


## Usage

To run the tool:

```bash
python fuzzpro.py -u <url> -w <wordlist> [options]

```

---

## Requirements

Python 3.7+

Install dependencies using:

```bash
pip install -r requirements.txt
```

---

## Options

| Option | Description | Default |
|---|---|---|
| `-u`, `--urlTarget` | URL with `FUZZ` as the placeholder for brute-forcing. Required. | N/A |
| `-w`, `--wordlistPath` | Path to the wordlist file containing potential directory/file names. Required. | N/A |
| `-t`, `--time` | Time (in seconds) to wait after detecting a potential Web Application Firewall (WAF). | 320 |
| `-s`, `--silent` | Suppress output for specified HTTP response codes (comma-separated). | None |
| `-th`, `--threads` | Number of requests to send per second (throttling). | 50 |
| `-h`, `--help` | Show help message and usage instructions. | N/A |


---

## Examples
1. Basic Usage
- Run a brute-force attack using a wordlist:


```bash
python fuzzpro.py -u https://example.com/FUZZ -w ./wordlist.txt
```

2. Suppress Specific Response Codes
- Hide responses with HTTP status codes 403, 503, and 421:


```bash
python fuzzpro.py -u https://example.com/FUZZ -w ./wordlist.txt -s 403,503,421
```

3. Limit Requests Per Second
- Throttle the tool to send 20 requests per second:


```bash
python fuzzpro.py -u https://example.com/FUZZ -w ./wordlist.txt -th 20
```

4. Custom WAF Wait Time
- Set the WAF detection wait time to 120 seconds:


```bash
python fuzzpro.py -u https://example.com/FUZZ -w ./wordlist.txt -t 120
```

5. Combined Options
- Run the tool with throttling, WAF detection time, and suppress specified response codes:


```bash
python fuzzpro.py -u https://example.com/FUZZ -w ./wordlist.txt -s 403,404 -t 120 -th 30
```

---

### Notes
**Placeholder:** The target URL must include FUZZ where the wordlist values will be substituted.

**Error Handling:** Invalid URLs, SSL issues, and connection timeouts are gracefully ignored.

**Rate Limiting:** Use -th to avoid server rate-limiting issues.

---

#### License
Copyright (C) Vishal (vishalatinfosec@gmail.com)

This project is licensed under the MIT License.

---

#### Author
Developed by [Vishal].

---

### Contributing
Contributions, feature requests, and bug reports are welcome! Submit a pull request or open an issue.

---
