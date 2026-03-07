#simple test file for start of xss logic

from xss_logic import xss_attack

#xss target test
target = {
    "sanitizes_input": False,
    "stores_input": True,
    "output_escaped": False,
    "content_security_on": False
}

#xss config test
xss_config = {
        "xss_type": "stored",
        "payloads": ["javascript:", "<script>alert('test')</script>", 
            "<script>alert('XSS')</script>", 
            "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
            "javascript:alert('XSS')"]
}

#gets xss test result
result = xss_attack(target, xss_config)

#prints the results and the logs of the test
print("Attack Result:")
print(result)

print("\nAttack Log:")
for part in result["xss_log"]:
    print(" - ", part)


#python3 xss_attack/test_xss_cli.py