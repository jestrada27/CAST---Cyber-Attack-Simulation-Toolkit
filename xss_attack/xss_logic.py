
def xss_attack(xss_payload, target):
    
    xss_log = []
    # payload_check = ["<script", "onerror", "onload[]", "javascript:", "<img", "<svg"]
    payload_check = ["<script", "onerror", "onload[]", "javascript:"]
    
    xss_working = any(check in xss_payload.lower() for check in payload_check)
    if not xss_working:
        return {
            "vulnerability": False,
            "xss_log": ["No xss attack was done."]
        }
    
    xss_log.append("XSS Payload for Attack.")

    if target.get("sanitizes_input"):
        xss_log.append("Target sanitized XSS input.")
        return {
            "vulnerability": False,
            "xss_log": xss_log
        }

    xss_log.append("Target did not sanitize XSS input.")

    if target.get("stores_input"):
        xss_log.append("XSS Payload for attack stored.")

    if target.get("ouput_escaped"):
        xss_log.append("Output escaped before rendering via payload information.")
        return {
            "vulnerability": False,
            "xss_log": xss_log
        }

    xss_log.append("Ouput from XSS payload was not escaped.")

    if target.get("content_security_on"):
        xss_log.append("Content security policy is on and stopped XSS payload and attack.")
        return {
            "vulnerability": False,
            "xss_log": xss_log
        }
    
    xss_log.append("XSS attack went through in the browser.")

    return {
        "vulnerability": True,
        "xss_log": xss_log
    }