"""
AI-Powered Credential Matcher

Intelligently matches discovered credentials to target API services
using file proximity, naming conventions, domain matching, and LLM inference.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


# Service detection patterns
SERVICE_PATTERNS = {
    'Azure': {
        'keywords': ['azure', 'ocp-apim', 'subscription', 'microsoft'],
        'domains': ['azure-api.net', 'azure.com', 'microsoft.com', 'windows.net'],
        'secret_types': ['azure_key', 'azure_endpoint', 'subscription_key']
    },
    'AWS': {
        'keywords': ['aws', 'amazon', 'cognito', 's3', 'lambda', 'dynamodb'],
        'domains': ['amazonaws.com', 'aws.amazon.com'],
        'secret_types': ['cognito_client_id', 'aws_access_key', 'aws_secret']
    },
    'Mixpanel': {
        'keywords': ['mixpanel'],
        'domains': ['mixpanel.com', 'api.mixpanel.com'],
        'secret_types': ['mixpanel_token', 'mixpanel_key']
    },
    'Instabug': {
        'keywords': ['instabug'],
        'domains': ['instabug.com'],
        'secret_types': ['instabug_key', 'instabug_token']
    },
    'Firebase': {
        'keywords': ['firebase', 'fcm', 'google'],
        'domains': ['firebase.google.com', 'firebaseio.com', 'googleapis.com'],
        'secret_types': ['firebase_key', 'google_api_key']
    },
    'Stripe': {
        'keywords': ['stripe', 'payment'],
        'domains': ['stripe.com', 'api.stripe.com'],
        'secret_types': ['stripe_key', 'stripe_secret']
    },
    'SleepIQ': {
        'keywords': ['sleepiq', 'sleepnumber', 'siq'],
        'domains': ['sleepiq.sleepnumber.com', 'sleepnumber.com'],
        'secret_types': ['api_key', 'x-api-key']
    }
}

# Type normalization
TYPE_DISPLAY_NAMES = {
    'api_key': 'API Key',
    'azure_key': 'API Key',
    'azure_endpoint': 'Endpoint',
    'subscription_key': 'Subscription Key',
    'cognito_client_id': 'Client ID',
    'client_secret': 'Client Secret',
    'mixpanel_token': 'API Token',
    'instabug_key': 'App Key',
    'hex_key': 'Hex Key',
    'signature': 'Signature',
    'x-api-key': 'API Key',
    'bearer_token': 'Bearer Token',
    'basic_auth': 'Basic Auth'
}


def detect_service_from_credential(credential: Dict) -> tuple[str, int]:
    """
    Detect the likely service for a credential based on patterns.
    Returns (service_name, base_certainty_score).
    """
    secret_type = credential.get('metadata', {}).get('secret_type', '')
    code = credential.get('code', '')
    path = credential.get('path', '')
    endpoint = credential.get('endpoint_path', '')
    message = credential.get('message', '')
    
    combined_text = f"{secret_type} {code} {path} {endpoint} {message}".lower()
    
    best_match = ('Unknown', 30)
    
    for service, patterns in SERVICE_PATTERNS.items():
        score = 0
        
        # Check secret_type match (strongest signal)
        if secret_type in patterns.get('secret_types', []):
            score += 50
        
        # Check keywords
        for keyword in patterns.get('keywords', []):
            if keyword in combined_text:
                score += 20
                break
        
        # Check domain patterns in endpoint
        for domain in patterns.get('domains', []):
            if domain in endpoint.lower() or domain in code.lower():
                score += 25
                break
        
        if score > best_match[1]:
            best_match = (service, min(score, 98))
    
    return best_match


def match_credential_to_server(credential: Dict, servers: List[str]) -> tuple[str, int]:
    """
    Match a credential to a specific server URL.
    Returns (server_url, certainty_boost).
    """
    code = credential.get('code', '')
    path = credential.get('path', '')
    environment = credential.get('metadata', {}).get('environment', '')
    
    for server in servers:
        parsed = urlparse(server)
        domain = parsed.netloc.lower()
        
        # Direct domain match in code
        if domain in code.lower():
            return (server, 30)
        
        # Environment match (prod/stage/test)
        if environment:
            if 'prod' in environment.lower() and 'prod' in server.lower():
                return (server, 20)
            if 'stage' in environment.lower() and 'stage' in server.lower():
                return (server, 20)
            if 'test' in environment.lower() and 'test' in server.lower():
                return (server, 20)
        
        # Keyword matching
        server_keywords = set(re.findall(r'\w+', domain))
        path_keywords = set(re.findall(r'\w+', path.lower()))
        code_keywords = set(re.findall(r'\w+', code.lower()))
        
        overlap = server_keywords & (path_keywords | code_keywords)
        if len(overlap) >= 2:
            return (server, 15)
    
    return (servers[0] if servers else '', 0)


def extract_credential_value(credential: Dict) -> str:
    """Extract the actual credential value from the code."""
    code = credential.get('code', '')
    
    # Try common patterns
    patterns = [
        r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted long strings
        r'=\s*([A-Za-z0-9+/=_-]{20,})',  # After equals
        r':\s*([A-Za-z0-9+/=_-]{20,})',  # After colon
    ]
    
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    
    # Fallback: extract from code after = or :
    if '=' in code:
        parts = code.split('=', 1)
        if len(parts) > 1:
            return parts[1].strip().strip('"\'')
    
    return code


def match_credentials(
    project_name: str,
    server_url: Optional[str] = None,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    Match credentials to services with certainty scores.
    
    Args:
        project_name: Name of the project
        server_url: Optional filter for specific server
        reports_dir: Directory containing vulnerability reports
    
    Returns:
        List of matched credentials with service, type, value, certainty
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI if available
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            servers = [s.get('url', '') for s in spec.get('servers', [])]
        except:
            pass
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append(ep)
    
    # Match each credential
    matched = []
    for cred in credentials:
        service, base_score = detect_service_from_credential(cred)
        
        # Match to server if available
        matched_server = ''
        server_boost = 0
        if servers:
            matched_server, server_boost = match_credential_to_server(cred, servers)
        
        # Calculate final certainty
        certainty = min(base_score + server_boost, 99)
        
        # Get type display name
        secret_type = cred.get('metadata', {}).get('secret_type', 'unknown')
        type_display = TYPE_DISPLAY_NAMES.get(secret_type, secret_type.replace('_', ' ').title())
        
        # Extract value
        value = extract_credential_value(cred)
        
        matched.append({
            'service': service,
            'type': type_display,
            'value': value,
            'certainty': certainty,
            'server_url': matched_server,
            'file_path': cred.get('path', ''),
            'line': cred.get('line', 0),
            'environment': cred.get('metadata', {}).get('environment', ''),
            'raw_type': secret_type
        })
    
    # Sort by certainty descending
    matched.sort(key=lambda x: x['certainty'], reverse=True)
    
    # Filter by server if specified
    if server_url:
        matched = [m for m in matched if server_url in m.get('server_url', '')]
    
    return matched


async def match_credentials_with_llm(
    project_name: str,
    server_url: Optional[str] = None,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    Enhanced credential matching using Claude LLM for better certainty.
    Falls back to pattern matching if LLM unavailable.
    """
    # First get pattern-based matches
    matched = match_credentials(project_name, server_url, reports_dir)
    
    # Try LLM enhancement
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key or not matched:
        return matched
    
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        
        # Prepare context for LLM
        cred_summary = []
        for m in matched[:20]:  # Limit to 20 for context
            cred_summary.append({
                'service_guess': m['service'],
                'type': m['type'],
                'value_preview': m['value'][:30] + '...' if len(m['value']) > 30 else m['value'],
                'file': m['file_path'],
                'environment': m['environment']
            })
        
        prompt = f"""Analyze these discovered API credentials and refine the service attribution.

Credentials found:
{json.dumps(cred_summary, indent=2)}

For each credential, confirm or correct the service name and provide a certainty score (0-100).
Consider:
- File location patterns
- Naming conventions  
- Credential format/structure
- Environment indicators

Return a JSON array with objects containing:
- index (0-based position in input)
- service (confirmed/corrected service name)
- certainty (0-100 score)

Only return the JSON array, no other text."""

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Parse LLM response
        result_text = response.content[0].text.strip()
        if result_text.startswith('['):
            llm_results = json.loads(result_text)
            
            # Apply LLM refinements
            for llm_item in llm_results:
                idx = llm_item.get('index', -1)
                if 0 <= idx < len(matched):
                    matched[idx]['service'] = llm_item.get('service', matched[idx]['service'])
                    matched[idx]['certainty'] = llm_item.get('certainty', matched[idx]['certainty'])
            
            # Re-sort after LLM refinement
            matched.sort(key=lambda x: x['certainty'], reverse=True)
    
    except Exception as e:
        # LLM failed, return pattern-based matches
        print(f"LLM credential matching failed: {e}")
    
    return matched
