# Web Application Fuzzer

This is a Python-based web application fuzzer designed to assist security researchers in automating the process of identifying vulnerabilities. It is important to note that the fuzzer is not capable of finding or exploiting vulnerabilities on its own, but rather helps researchers identify potential vulnerabilities that may require further investigation. The fuzzer currently supports the following types of vulnerabilities: 

- SQL injection
- Cross-site scripting (XSS)
- Path traversal

## Usage

To use the fuzzer, provide the URL you want to test as an argument, along with the types of vulnerabilities you want to test for. You can also provide the body of a POST request if you want to fuzz the parameters in the request body.

python fuzzer.py --url "http://example.com" -s -x -p 

python fuzzer.py --url "http://example.com/login" -s --post <request body>


## Features

- Can test for multiple types of vulnerabilities at once
- Can test both URL parameters and HTTP headers for vulnerabilities
- Can test the body of POST requests for vulnerabilities
- Allows customization of payloads and vulnerability indicators
- Prints out details of any vulnerabilities found, including the location of the vulnerability, the payload used, the status code of the response, the length of the response, and the elapsed time

## Limitations

- Currently only fuzzes the provided URL instead of the entire website
- Only supports GET and POST requests
- Does not support testing for other types of vulnerabilities beyond SQL injection, XSS, and path traversal
