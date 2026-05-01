import json
import time
import requests


BASE_URL = "http://127.0.0.1:8000"

REFLECT_ENDPOINT = "/reflect"
STORED_ENDPOINT = "/comment"


XSS_PAYLOADS = [
    {
        "name": "Basic Script Tag",
        "payload": "<script>alert('XSS')</script>"
    },
    {
        "name": "Image OnError",
        "payload": "<img src=x onerror=alert('XSS')>"
    },
    {
        "name": "SVG OnLoad",
        "payload": "<svg onload=alert('XSS')>"
    },
    {
        "name": "Iframe Injection",
        "payload": "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    },
    {
        "name": "JS Protocol",
        "payload": "javascript:alert('XSS')"
    },
    {
        "name": "Script With DOM Change",
        "payload": "<script>document.body.innerHTML='XSS Triggered'</script>"
    },
    {
        "name": "Uppercase Script",
        "payload": "<SCRIPT>alert('XSS')</SCRIPT>"
    },
    {
        "name": "Broken Image With Text",
        "payload": "<img src=1 onerror=alert('Stored XSS')>"
    }
]


def print_divider():
    print("=" * 80)


def safe_json(response):
    try:
        return response.json()
    except Exception:
        return {
            "raw_text": response.text
        }


def test_reflected_xss(payload_name, payload):
    url = BASE_URL + REFLECT_ENDPOINT
    params = {"msg": payload}

    result = {
        "test_type": "Reflected XSS",
        "payload_name": payload_name,
        "payload": payload,
        "connected": False,
        "http_status": None,
        "attack_detected": False,
        "vulnerability": False,
        "detail": None,
        "success": False
    }

    try:
        response = requests.get(url, params=params, timeout=5)
        data = safe_json(response)

        result["connected"] = True
        result["http_status"] = response.status_code
        result["attack_detected"] = data.get("attack_detected", False)
        result["vulnerability"] = data.get("vulnerability", False)
        result["detail"] = data.get("detail", "No detail returned.")
        result["success"] = bool(result["attack_detected"] or result["vulnerability"])

    except requests.RequestException as exc:
        result["detail"] = f"Connection failed: {exc}"

    return result


def test_stored_xss(payload_name, payload):
    url = BASE_URL + STORED_ENDPOINT
    body = {"content": payload}

    result = {
        "test_type": "Stored XSS",
        "payload_name": payload_name,
        "payload": payload,
        "connected": False,
        "http_status": None,
        "attack_detected": False,
        "vulnerability": False,
        "detail": None,
        "success": False
    }

    try:
        response = requests.post(url, json=body, timeout=5)
        data = safe_json(response)

        result["connected"] = True
        result["http_status"] = response.status_code
        result["attack_detected"] = data.get("attack_detected", False)
        result["vulnerability"] = data.get("vulnerability", False)
        result["detail"] = data.get("detail", "No detail returned.")
        result["success"] = bool(result["attack_detected"] or result["vulnerability"])

    except requests.RequestException as exc:
        result["detail"] = f"Connection failed: {exc}"

    return result


def print_result(result):
    print_divider()
    print(f"Test Type     : {result['test_type']}")
    print(f"Payload Name  : {result['payload_name']}")
    print(f"Payload       : {result['payload']}")
    print(f"Connected     : {result['connected']}")
    print(f"HTTP Status   : {result['http_status']}")
    print(f"Detected      : {result['attack_detected']}")
    print(f"Vulnerable    : {result['vulnerability']}")
    print(f"Success       : {result['success']}")
    print(f"Detail        : {result['detail']}")


def summary_report(results):
    reflected_total = sum(1 for r in results if r["test_type"] == "Reflected XSS")
    stored_total = sum(1 for r in results if r["test_type"] == "Stored XSS")

    reflected_success = sum(
        1 for r in results
        if r["test_type"] == "Reflected XSS" and r["success"]
    )

    stored_success = sum(
        1 for r in results
        if r["test_type"] == "Stored XSS" and r["success"]
    )

    print_divider()
    print("XSS TEST SUMMARY")
    print_divider()
    print(f"Reflected XSS Passed : {reflected_success}/{reflected_total}")
    print(f"Stored XSS Passed    : {stored_success}/{stored_total}")
    print(f"Total Tests Run      : {len(results)}")
    print_divider()


def save_results(results, filename="xss_results.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)
    print(f"Results saved to {filename}")


def run_reflected_tests():
    results = []
    print_divider()
    print("RUNNING REFLECTED XSS TESTS")
    print_divider()

    for item in XSS_PAYLOADS:
        result = test_reflected_xss(item["name"], item["payload"])
        print_result(result)
        results.append(result)
        time.sleep(0.2)

    return results


def run_stored_tests():
    results = []
    print_divider()
    print("RUNNING STORED XSS TESTS")
    print_divider()

    for item in XSS_PAYLOADS:
        result = test_stored_xss(item["name"], item["payload"])
        print_result(result)
        results.append(result)
        time.sleep(0.2)

    return results


def menu():
    print_divider()
    print("CAST XSS VERIFICATION TOOL")
    print_divider()
    print("1. Run Reflected XSS Tests")
    print("2. Run Stored XSS Tests")
    print("3. Run All XSS Tests")
    print("4. Exit")
    print_divider()


def main():
    all_results = []

    while True:
        menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            results = run_reflected_tests()
            all_results.extend(results)
            summary_report(results)
            save_results(results, "reflected_xss_results.json")

        elif choice == "2":
            results = run_stored_tests()
            all_results.extend(results)
            summary_report(results)
            save_results(results, "stored_xss_results.json")

        elif choice == "3":
            reflected = run_reflected_tests()
            stored = run_stored_tests()

            results = reflected + stored
            all_results.extend(results)

            summary_report(results)
            save_results(results, "all_xss_results.json")

        elif choice == "4":
            print("Exiting XSS verification tool.")
            break

        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()