from Fuzzer import alert_vulnerability
from Fuzzer import get_post_parameters
from Fuzzer import parse_url_parameters

def main():
    test_alert_vulnerability()
    test_get_post_parameters()
    test_parse_url_parameters

def test_alert_vulnerability():
    assert alert_vulnerability("username", "'or1=1;--", 3, 4) == "Potential SQL injection vulnerability at POST request body parameter: \"username\", Payload: 'or1=1;--"
    assert alert_vulnerability("User-Agent", "<script>alert(\"xss\")</script>", 2, 5) == "Potential XSS vulnerability at HTTP header: \"User-Agent\", Payload: <script>alert(\"xss\")</script>"
    assert alert_vulnerability("file", "../../../../etc/passwd", 1, 6) == "Potential Path Traversal vulnerability at URL parameter: \"file\", Payload: ../../../../etc/passwd"

def test_get_post_parameters():
    assert get_post_parameters({"post": "username=user16&password=pass123&action=login"}) == {"username":"user16", "password":"pass123", "action":"login"}
    assert get_post_parameters({"post": "csrf=999888777&id=8"}) == {"csrf":999888777, "id":8}
    assert get_post_parameters({"post": "p1=999888777&p2=abc&p3=abc123-*/"}) == {"p1":999888777, "p2":"abc", "p3":"abc123-*/"}

def test_parse_url_parameters():
    assert parse_url_parameters("https://www.google.com/search?q=cs50") == {"q":"cs50"}
    assert parse_url_parameters("https://www.website.com/?pageId=5&lang=EN") == {"pageId":"5", "lang":"EN"}
    assert parse_url_parameters("https://www.some123other+*-website.com/search?p1=abc&p2=123&p3=+*-") == {"p1":"abc", "p2":"123", "p3":"+*-"}


if __name__ == "__main__":
    main()