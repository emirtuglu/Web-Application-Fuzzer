import requests
import argparse
from urllib.parse import urlparse, parse_qs, quote
from sys import exit
from termcolor import colored

# Vulnerability types
PARAMETER_VULNERABILITY = 1
HEADER_VULNERABILITY = 2
POST_BODY_VULNERABILITY = 3
# Specific types
SQL_INJECTION = 4
XSS = 5
PATH_TRAVERSAL = 6
# POST body parameters not to be fuzzed
IGNORED_POST_BODY_PARAMETERS = ["csrf", "xsrf"]   

def main():
    # Parsing command line arguments
    arguments = parse_arguments() 

    # Getting a fuzzer iterator from generator function
    fuzzer = create_fuzzer(arguments)
    print("Fuzzing starts...")

    # For each possible bug yielded by fuzzer, print it on the terminal
    try:
        for (vuln_location, payload, vuln_type, vuln) in fuzzer:
            print( colored(alert_vulnerability(vuln_location, payload, vuln_type, vuln), "green", attrs=["bold"]))
    except KeyboardInterrupt:
        exit()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Provide URL and specify vulnerabilities to be probed. Optionally, enter POST parameters to probe.")
    parser.add_argument("--url", help="URL", required=True)
    parser.add_argument("-s", help="SQL injection", action="store_true")
    parser.add_argument("-x", help="XSS", action="store_true")
    parser.add_argument("-p", help="Path traversal", action="store_true")
    parser.add_argument("--post", help="Copy and paste POST request body here (inside quotes) to fuzz body parameters", type=str)

    # Parsing arguments and turning them to a dictionary
    args = vars(parser.parse_args()) 

    # Validate URL argument
    try:
        parsed_url = urlparse(args["url"])
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError("Invalid URL scheme. Must be http or https.")
    except ValueError as err:
        parser.error(str(err))

    # Ensure at least one vulnerability type is entered
    if not args["s"] and not args["x"] and not args["p"]: 
        parser.error("At least one vulnerability type must be specified.")
    
    return args

def create_fuzzer(args): # Generator function
    # Getting URL from args list
    url = args["url"]

    # Getting POST request body parameters if there are any
    post_parameters = get_post_parameters(args)

    # Reading vulnerability payloads and indicators from txt files
    SQL_payloads, XSS_payloads, PT_payloads, SQL_indicators, XSS_indicators, PT_indicators = generate_payloads_and_indicators(args)

    # Checking whether page already contains any of the indicators. If so, remove that indicator from list to prevent false positives
    check_existing_indicators(url, SQL_indicators, XSS_indicators, PT_indicators)

    # Fuzzing URL parameters
    print(colored("***************************** FUZZING URL PARAMETERS *****************************", "blue", attrs=["bold"]))
    print("{:20}{:40}{:<10}{:<15}{:<20}".format("parameter", "payload", "status", "length", "elapsed time"))
    for (parameter, payload) in fuzz_parameters(url, SQL_payloads, SQL_indicators):
        yield parameter, payload, PARAMETER_VULNERABILITY, SQL_INJECTION
    for (parameter, payload) in fuzz_parameters(url, XSS_payloads, XSS_indicators):
        yield parameter, payload, PARAMETER_VULNERABILITY, XSS
    for (parameter, payload) in fuzz_parameters(url, PT_payloads, PT_indicators):
        yield parameter, payload, PARAMETER_VULNERABILITY, PATH_TRAVERSAL

    # Fuzzing HTTP headers
    print(colored("****************************** FUZZING HTTP HEADERS ******************************", "blue", attrs=["bold"]))
    print("{:20}{:40}{:<10}{:<15}{:<20}".format("header", "payload", "status", "length", "elapsed time"))
    for (header, payload) in fuzz_headers(url, SQL_payloads, SQL_indicators):
        yield header, payload, HEADER_VULNERABILITY, SQL_INJECTION
    for (header, payload) in fuzz_headers(url, XSS_payloads, XSS_indicators):
        yield header, payload, HEADER_VULNERABILITY, XSS
    for (header, payload) in fuzz_headers(url, PT_payloads, PT_indicators):
        yield header, payload, HEADER_VULNERABILITY, PATH_TRAVERSAL

    # Fuzzing POST request body parameters
    if len(post_parameters) > 0:
        print(colored("************************** POST REQUEST BODY PARAMETERS **************************", "blue", attrs=["bold"]))
        print("{:20}{:40}{:<10}{:<15}{:<20}".format("parameter", "payload", "status", "length", "elapsed time"))
        for (post_parameter, payload) in fuzz_post_parameters(url, post_parameters, SQL_payloads, SQL_indicators):
            yield post_parameter, payload, POST_BODY_VULNERABILITY, SQL_INJECTION
        for (post_parameter, payload) in fuzz_post_parameters(url, post_parameters, XSS_payloads, XSS_indicators):
            yield post_parameter, payload, POST_BODY_VULNERABILITY, XSS
        for (post_parameter, payload) in fuzz_post_parameters(url, post_parameters, PT_payloads, PT_indicators):
            yield post_parameter, payload, POST_BODY_VULNERABILITY, PATH_TRAVERSAL



def fuzz_parameters(url, payloads, indicators):
    # Parsing parameters from url
    parameters = parse_url_parameters(url)

    # One by one, replace each parameter with each payload
    for parameter in parameters:
        vulnFound = False
        for payload in payloads:
            # Replacing old parameter with URL encoded payload
            transformed_url = url.replace( (parameter+"="+parameters[parameter]), (parameter+"="+quote(payload.strip())) )

            # Sending request with crafted URL
            response = requests.get(transformed_url)
            print("{:20}{:40}{:<10}{:<15}{:<15}".format(parameter, payload[:39], response.status_code, len(response.content), response.elapsed.microseconds))

            # Checking if response contains any vulnerability indicator
            for indicator in indicators:
                try:
                    if indicator.strip().lower() in str(response.content).lower():
                        yield parameter, payload  # Alerting possible vulnerability
                        vulnFound = True
                        break
                except:
                    continue
            if vulnFound:  # Avoiding unnecessary payload trials after vuln found in current parameter
                break

def parse_url_parameters(url):
    parsed_url = urlparse(url)
    parameters = {}
    if len(parsed_url.query) > 0:   # Check if there is any parameter
        for param in parsed_url.query.split("&"):   # Split parameters
            try:
                parameters[param.split("=")[0]] = param.split("=")[1]   #Store parameters in a dict
            except:
                print( colored("URL parameters were not entered correctly.", "red", attrs=["bold"]))
                exit()
    return parameters


def fuzz_headers(url, payloads, indicators):
    # Sending a request with given url
    default_response = requests.get(url)

    # Getting headers from request to manipulate them 
    headers = default_response.request.headers

    # One by one, replace each header with each payload
    for header in headers:
        vulnFound = False
        for payload in payloads:
            headers[header] = payload.strip().encode("utf-8")
            response = requests.get(url, headers=headers)  # Replacing old header with payload
            print("{:20}{:40}{:<10}{:<15}{:<15}".format(header, payload[:39], response.status_code, len(response.content), response.elapsed.microseconds))

            # Checking if response contains any vulnerability indicator
            for indicator in indicators: 
                try:
                    if indicator.strip().lower() in str(response.content).lower():
                        yield header, payload   # Alerting possible vulnerability
                        vulnFound = True
                        break
                except:
                    continue
            if vulnFound:       # Avoiding unnecessary payload trials after vuln found in current header
                break

def fuzz_post_parameters(url, parameters, payloads, indicators):
    # One by one, replace each parameter's value with each payload
    for parameter in parameters:

        # Passing ignored parameters
        if parameter in IGNORED_POST_BODY_PARAMETERS:
            continue

         # Storing defaut value of parameter to assign it back to parameter while fuzzing other parameters
        default_value_of_parameter = parameters[parameter]
        vulnFound = False

        for payload in payloads:
            parameters[parameter] = payload
            response = requests.post(url, data=parameters)
            print("{:20}{:40}{:<10}{:<15}{:<15}".format(parameter, payload[:39], response.status_code, len(response.content), response.elapsed.microseconds))

            # Checking if response contains any vulnerability indicator
            for indicator in indicators:
                try:
                    if indicator.strip().lower() in str(response.content).lower():
                        yield parameter, payload    # Alerting possible vulnerability
                        vulnFound = True
                        break
                except:
                    continue
            if vulnFound:       # Avoiding unnecessary payload trials after vuln found in current body parameter
                parameters[parameter] = default_value_of_parameter
                break
            parameters[parameter] = default_value_of_parameter


def generate_payloads_and_indicators(args):
    SQL_payloads = []
    XSS_payloads = []
    PT_payloads = []
    SQL_indicators = []
    XSS_indicators = []
    PT_indicators = []
    
    # If arguments contain -s, load SQL injection parameters and indicators
    if args["s"]:
        with open("SQLinjection/payloads.txt") as file:
            SQL_payloads += [line.rstrip() for line in file.readlines()]
        with open("SQLinjection/indicators.txt") as file:
            SQL_indicators += [line.rstrip() for line in file.readlines()]

    # If arguments contain -x, load XSS parameters and indicators
    if args["x"]:
        with open("XSS/payloads.txt") as file:
            XSS_payloads += [line.rstrip() for line in file.readlines()]
        with open("XSS/indicators.txt") as file:
            XSS_indicators += [line.rstrip() for line in file.readlines()]

    # If arguments contain -p, load Path Traversal parameters and indicators
    if args["p"]:
        with open("PathTraversal/payloads.txt") as file:
            PT_payloads += [line.rstrip() for line in file.readlines()]
        with open("PathTraversal/indicators.txt") as file:
            PT_indicators += [line.rstrip() for line in file.readlines()]

    return SQL_payloads, XSS_payloads, PT_payloads, SQL_indicators, XSS_indicators, PT_indicators


def get_post_parameters(args):
    # Converting POST body into a dict and returning it
    post_parameters = {}
    if args["post"] != None:
        try:
            params = args["post"].split("&")
            for param in params:
                param_name = param.split("=")[0]
                param_value = param.split("=")[1]
                if param_value.isnumeric():  # if value of the parameter is int, convert its type to int
                    param_value = int(param_value)
                post_parameters[param_name] = param_value
        except:
            print("Please enter POST body parameters correctly. Usage: \"<parameter>=<value>&<parameter>=<value>...\"")
            exit()
    return post_parameters


def check_existing_indicators(url, SQL_indicators, XSS_indicators, PT_indicators):
    # Sending a request with given URL and check if response contains any of the indicators. If contains, remove that indicator
    try:
        for indicators in [SQL_indicators, XSS_indicators, PT_indicators]:
            for indicator in indicators:
                resp = requests.get(url)
                if indicator.strip().lower() in str(resp.content).lower():
                    indicators.remove(indicator)
    except:
        print("Cannot connect to the URL, make sure you entered URL correctly.")
        exit()


def alert_vulnerability(vuln_location, payload, vuln_type, vuln):
    if vuln == SQL_INJECTION:
        specificVulnType = "SQL injection"
    elif vuln == XSS:
        specificVulnType = "XSS"
    else:
        specificVulnType = "Path Traversal"
    
    if vuln_type == PARAMETER_VULNERABILITY:
        return "Potential " + specificVulnType + " vulnerability at URL parameter: \"" + vuln_location + "\", Payload: " + payload.strip()
    if vuln_type == HEADER_VULNERABILITY:
        return "Potential " + specificVulnType + " vulnerability at HTTP header: \"" + vuln_location + "\", Payload: " + payload.strip()
    if vuln_type == POST_BODY_VULNERABILITY:
        return "Potential " + specificVulnType + " vulnerability at POST request body parameter: \"" + vuln_location + "\", Payload: " + payload.strip()


if __name__ == "__main__":
    main()

