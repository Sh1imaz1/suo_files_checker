import requests
import hashlib
import time
import argparse
import re
import yara
import os
import tempfile

def parse_github_url(url):
    """Extract owner and repository name from GitHub URL"""
    pattern = r'github\.com/([^/]+)/([^/]+)'
    match = re.search(pattern, url)
    if not match:
        raise ValueError("Invalid GitHub URL format. Use: https://github.com/owner/repo")
    owner, repo = match.groups()
    if repo.endswith('.git'):
        repo = repo[:-4]
    return owner, repo

def get_repo_contents(owner, repo, token=None):
    """Get all files in a GitHub repository with their download URLs"""
    headers = {'Authorization': f'token {token}'} if token else {}
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        # Try 'master' branch if 'main' fails
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to get repo contents: {response.status_code} - {response.json().get('message')}")
    
    tree = response.json().get('tree', [])
    return [item for item in tree if item['type'] == 'blob']

def find_suo_files(contents):
    """Filter files to find .suo files"""
    return [item for item in contents if item['path'].lower().endswith('.suo')]

def download_file(url, token=None):
    """Download file content from GitHub"""
    headers = {'Authorization': f'token {token}'} if token else {}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.content
    raise Exception(f"Download failed: {response.status_code}")

def get_sha256(content):
    """Calculate SHA-256 hash of file content"""
    return hashlib.sha256(content).hexdigest()

def load_yara_rules(rules_dir):
    """Compile YARA rules from a directory"""
    rules = {}
    if not rules_dir or not os.path.exists(rules_dir):
        return None
        
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            path = os.path.join(rules_dir, filename)
            try:
                rules[filename] = yara.compile(filepath=path)
            except yara.SyntaxError as e:
                print(f"⚠️ YARA syntax error in {filename}: {str(e)}")
            except Exception as e:
                print(f"⚠️ Failed to compile YARA rule {filename}: {str(e)}")
    
    return rules if rules else None

def yara_scan(content, rules):
    """Scan file content with YARA rules"""
    if not rules:
        return []
    
    matches = []
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(content)
        tmp_path = tmpfile.name
    
    try:
        for rule_name, rule in rules.items():
            try:
                rule_matches = rule.match(tmp_path)
                for match in rule_matches:
                    matches.append({
                        'rule': rule_name,
                        'tags': match.tags,
                        'meta': match.meta,
                        'strings': [str(s) for s in match.strings]
                    })
            except Exception as e:
                print(f"⚠️ YARA scan error with {rule_name}: {str(e)}")
    finally:
        os.unlink(tmp_path)
    
    return matches

def upload_to_virustotal(file_content, api_key):
    """Upload file to VirusTotal for analysis"""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    files = {'file': ('file.suo', file_content)}
    
    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()['data']['id']
    raise Exception(f"VirusTotal upload failed: {response.status_code} - {response.text}")

def get_virustotal_report(file_hash, api_key):
    """Get VirusTotal report for a file hash"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def analyze_with_virustotal(content, api_key):
    """Analyze file content with VirusTotal"""
    file_hash = get_sha256(content)
    
    # First try to get existing report
    report = get_virustotal_report(file_hash, api_key)
    if report:
        return report
    
    # Upload if no report exists
    analysis_id = upload_to_virustotal(content, api_key)
    return {"status": "uploaded", "analysis_id": analysis_id, "file_hash": file_hash}

def print_virustotal_report(report):
    """Format and print VirusTotal results"""
    if 'data' in report:
        attributes = report['data']['attributes']
        stats = attributes['last_analysis_stats']
        malicious = stats['malicious']
        total = sum(stats.values())
        
        print(f"\n🔍 VirusTotal Scan Results:")
        print(f"  SHA-256: {attributes['sha256']}")
        print(f"  Detection: {malicious}/{total} security vendors flagged this as malicious")
        
        if malicious > 0:
            print("\n🚨 Malicious Indicators:")
            for engine, result in attributes['last_analysis_results'].items():
                if result['category'] == 'malicious':
                    print(f"  - {engine}: {result['result']}")
        
        print(f"\nView full report: https://www.virustotal.com/gui/file/{attributes['sha256']}")
    else:
        print(f"\n⚠️ File submitted to VirusTotal for analysis")
        print(f"  Analysis ID: {report['analysis_id']}")
        print(f"  File Hash: {report['file_hash']}")
        print(f"  Check report later: https://www.virustotal.com/gui/file/{report['file_hash']}")

def print_yara_results(matches):
    """Format and print YARA rule matches"""
    if not matches:
        print("  ✅ No YARA rule matches")
        return
    
    print("\n🚨 YARA Rule Matches:")
    for match in matches:
        print(f"  🔍 Rule: {match['rule']}")
        print(f"     - Tags: {', '.join(match['tags'])}")
        if 'description' in match['meta']:
            print(f"     - Description: {match['meta']['description']}")
        if match['strings']:
            print(f"     - Detected Strings: {', '.join(match['strings'][:3])}")

def main(github_url, github_token, vt_api_key, yara_rules_dir):
    """Main scanning workflow"""
    try:
        # Load YARA rules
        yara_rules = load_yara_rules(yara_rules_dir)
        if yara_rules_dir and not yara_rules:
            print(f"⚠️ No valid YARA rules found in {yara_rules_dir}")
        elif yara_rules:
            print(f"✅ Loaded {len(yara_rules)} YARA rules")
        
        # Parse GitHub URL
        owner, repo = parse_github_url(github_url)
        print(f"🔍 Scanning repository: {owner}/{repo}")
        
        # Get repository contents
        contents = get_repo_contents(owner, repo, github_token)
        print(f"  Found {len(contents)} files in repository")
        
        # Find .suo files
        suo_files = find_suo_files(contents)
        if not suo_files:
            print("\n❌ No .suo files found in repository")
            return
        
        print(f"\n🔎 Found {len(suo_files)} .suo files:")
        for i, file in enumerate(suo_files, 1):
            print(f"  {i}. {file['path']} ({file['size']} bytes)")
        
        # Process each .suo file
        for file in suo_files:
            print(f"\n🚀 Analyzing: {file['path']}")
            
            try:
                # Download file
                download_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{file['path']}"
                content = download_file(download_url, github_token)
                print(f"  ✅ Downloaded ({len(content)} bytes)")
                
                # YARA scanning
                if yara_rules:
                    print("  🔍 Running YARA rules...")
                    yara_matches = yara_scan(content, yara_rules)
                    print_yara_results(yara_matches)
                
                # Analyze with VirusTotal
                print("  ⏳ Scanning with VirusTotal...")
                report = analyze_with_virustotal(content, vt_api_key)
                print_virustotal_report(report)
                
                # Respect VirusTotal rate limits (4 requests/minute)
                time.sleep(20)  # Sleep 20 seconds between scans
                
            except Exception as e:
                print(f"  ❌ Error processing file: {str(e)}")
    
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='GitHub .suo File Scanner with YARA and VirusTotal')
    parser.add_argument('--github-url', required=True, help='GitHub repository URL')
    parser.add_argument('--github-token', help='GitHub Personal Access Token (optional)')
    parser.add_argument('--vt-key', required=True, help='VirusTotal API Key')
    parser.add_argument('--yara-rules', help='Path to directory containing YARA rules')
    args = parser.parse_args()
    
    main(github_url=args.github_url, 
         github_token=args.github_token,
         vt_api_key=args.vt_key,
         yara_rules_dir=args.yara_rules)