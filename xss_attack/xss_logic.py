import time

#list of base payloads for the xss testing for cli
payload_list = ["<script", "onerror", "onload[]", 
                 "javascript:", "<script>alert('test')</script>", 
                 "<img", "<svg", "<script>alert('XSS')</script>", 
                "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
                "javascript:alert('XSS')"]

#def xss_attack(xss_payload, target, xss_config):

#xss attack function to get base logic done and to see if it works using cli
def xss_attack(target, xss_config):
    
    #xss info for the attack 
    xss_log = []
    attack_timer = time.time()
    xss_payload = xss_config.get("payloads", payload_list)
    xss_type = xss_config.get("xss_type", "reflected")
    
    #
    xss_log.append(f'XSS type: {xss_type}')
    xss_attempt = 0
    xss_success_num = 0

    #loop to go through the target and see if there are any attack vulnerabilities for the target
    for payload in xss_payload:
        #updates logs based on information about the xss attack
        xss_log.append(f"XSS Payload for Attack using {payload}")
        xss_attempt += 1

        if target.get("sanitizes_input"):
            xss_log.append("Target sanitized XSS input.")
            continue

        xss_log.append("Target did not sanitize XSS input.")

        if xss_type == "stored":
            if target.get("stores_input"):
                xss_log.append("XSS Payload for attack stored.")
    
        if target.get("output_escaped"):
            xss_log.append("Output escaped before rendering via payload information.")

        xss_log.append("Ouput from XSS payload was not escaped.")

        if target.get("content_security_on"):
            xss_log.append("Content security policy is on and stopped XSS payload and attack.")
            continue
        
        xss_log.append("XSS attack went through in the browser.")
        xss_success_num += 1

    #end of attack information for the xss info
    time_done = time.time()
    xss_time = time_done - attack_timer

    if xss_success_num > 0:
        vulnerability = True
        payload_check = "Successful payload."
    else:
        vulnerability = False
        payload_check = "Payload failed."

    #returns relevant information from the attack to see the vulnerbility, logs, and other important information
    return {
        "vulnerability": vulnerability,
        "xss_attempt": xss_attempt,
        "xss_successful": payload_check,
        "xss_time": xss_time,
        "xss_log": xss_log
    }