#simple test file for start of xss logic

from xss_logic import xss_attack

#xss target test
# target = {
#     "sanitizes_input": False,
#     "stores_input": True,
#     "output_escaped": False,
#     "content_security_on": False
# }

#xss config test
# xss_config = {
#         "xss_type": "stored",
#         "payloads": ["javascript:", "<script>alert('test')</script>", 
#             "<script>alert('XSS')</script>", 
#             "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
#             "javascript:alert('XSS')"]
# }

target = {
    "url": "http://testphp.vulnweb.com/search.php",
    "param": "search"
}

xss_config = {
    "xss_type": "reflected",
    "payloads": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    "attempts": 3,
    "rate_limit": 1,
    "dry_run": True   
}

#gets xss test result
result = xss_attack(target, xss_config)

#prints the results and the logs of the test
print("Attack Result:")
print(result["vulnerability"])
print("Attempts:", result["attempts"])
print("Successful:", result["successful_count"])
print("Time:", result["xss_time"])

print("\nAttack Log:")
for part in result["xss_log"]:
    print(" - ", part)


#python3 xss_attack/test_xss_cli.py