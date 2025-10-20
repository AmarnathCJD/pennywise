import requests
import json

API_BASE = "http://127.0.0.1:8080"

def test_vuln_info():
    payload = {
        "type": "cookie-security",
        "subtype": "js-cookie-set",
        "url": "http://127.0.0.1:5000/comments",
        "match": "+document.cookie"
    }
    print("\n=== Testing /vuln-info ===")
    r = requests.post(f"{API_BASE}/vuln-info", json=payload)
    if r.status_code == 200:
        print(json.dumps(r.json(), indent=2))
        with open("vuln_info.json", "w") as f:
            f.write(r.json().get("analysis", {}).get("raw", ""))
    else:
        print(f"Error: {r.status_code} -> {r.text}")

def test_analyze_site():
    payload = {"url": "http://testphp.vulnweb.com/"}
    print("\n=== Testing /analyze-site ===")
    r = requests.post(f"{API_BASE}/analyze-site", json=payload)
    if r.status_code == 200:
        print(json.dumps(r.json(), indent=2))
        with open("site_analysis.json", "w") as f:
            f.write(r.json().get("analysis", "").get("raw", ""))
    else:
        print(f"Error: {r.status_code} -> {r.text}")

if __name__ == "__main__":
    print("=== Client Test Script ===")
    test_vuln_info()
    test_analyze_site()
