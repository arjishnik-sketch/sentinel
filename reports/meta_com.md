# Sentinel Report

Target: **meta.com**

Generated: 2026-08-07T14:39:17.331303+00:00

---

## Statistics

- **target** : meta.com
- **subdomains** : 259
- **alive** : 92
- **crawl** : 119
- **login_pages** : 12
- **admin_pages** : 1
- **api_endpoints** : 0
- **graphql** : 0
- **swagger** : 0
- **uploads** : 2
- **javascript** : 0
- **parameters** : 4

---

# AI Analysis

# Executive Summary  
- **259 subdomains** discovered, with **92 alive hosts** and **119 crawled URLs**.  
- **12 login pages** identified across multiple subdomains (e.g., `auth.meta.com`, `accountscenter.meta.com`).  
- **1 admin page** found at `devicemanager.meta.com`.  
- **2 upload endpoints** detected (`media.meta.com`, `rupload.ar.meta.com`).  
- **4 parameters** observed: `next`, `next_uri`, `utm_medium`, `utm_source`.  
- No API endpoints, GraphQL, or Swagger detected.  

---

# High Priority Manual Tests  
- Test **login pages** for:  
  - CSRF vulnerabilities.  
  - XSS in form fields.  
  - Insecure password policies (e.g., weak encryption, rate limiting).  
- Validate **upload endpoints** for:  
  - File type restrictions (e.g., allowing `.php` or `.exe`).  
  - Path traversal attempts (e.g., `../../etc/passwd`).  
- Check **admin page** (`devicemanager.meta.com`) for:  
  - Authentication bypass.  
  - Weak access controls (e.g., IDOR/BOLA).  
- Inspect **parameters** (`next`, `next_uri`) for:  
  - Open redirect vulnerabilities.  
  - Parameter pollution.  

---

# Interesting Endpoints  
- **Login pages**:  
  - `https://auth.meta.com/`, `https://accountscenter.meta.com/login/...`  
- **Admin page**:  
  - `https://devicemanager.meta.com`  
- **Upload endpoints**:  
  - `https://media.meta.com`, `https://rupload.ar.meta.com`  
- **Parameter endpoints**:  
  - Any URL containing `next`, `next_uri`, `utm_medium`, or `utm_source`.  

---

# Authentication Review  
- **Multiple login systems** (e.g., `auth.meta.com`, `accountscenter.meta.com`).  
- No evidence of single sign-on (SSO) or federated authentication.  
- **No API endpoints** or OAuth flows detected.  
- **No CSRF tokens** observed in login forms (requires manual inspection).  

---

# Authorization (IDOR/BOLA) Ideas  
- Test **admin page** for:  
  - Accessing other users' data (e.g., `devicemanager.meta.com/user/123` vs. `user/456`).  
  - BOLA: Check if `devicemanager.meta.com` allows access to non-admin resources.  
- Monitor **upload endpoints** for:  
  - IDOR: Uploading files to arbitrary user directories (e.g., `media/meta.com/user/123/`).  

---

# File Upload Review  
- **Upload endpoints**:  
  - `https://media.meta.com` (likely media storage).  
  - `https://rupload.ar.meta.com` (possibly regional upload).  
- **Risk**:  
  - No evidence of file type validation or sanitization.  
  - Potential for arbitrary file upload (e.g., `.php` or `.exe`).  

---

# GraphQL Review  
- **Not observed**: No GraphQL endpoints detected.  

---

# API Review  
- **Not observed**: No API endpoints, Swagger, or OpenAPI detected.  

---

# Suggested nuclei Commands  
```bash
nuclei -t templates/scan.yaml -u https://auth.meta.com -u https://devicemanager.meta.com -u https://media.meta.com
nuclei -t templates/xss.yaml -u https://accountscenter.meta.com
nuclei -t templates/csrf.yaml -u https://auth.meta.com
nuclei -t templates/open-redirect.yaml -u https://threatexchange.meta.com
```  

---

# Suggested ffuf Commands  
```bash
ffuf -u https://trunkstable.auth.meta.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
ffuf -u https://media.meta.com/upload/FUZZ -w /usr/share/wordlists/common.txt
ffuf -u https://rupload.ar.meta.com/FUZZ -w /usr/share/wordlists/params.txt
```  

---

# Suggested curl Commands  
```bash
curl -I https://auth.meta.com/login
curl -I https://devicemanager.meta.com
curl -I https://media.meta.com/upload
curl -I "https://threatexchange.meta.com/login/?next=https%3A%2F%2Fthreatexchange.meta.com%2F"
```  

---

# Confidence  
- **High** for login pages, upload endpoints, and parameter analysis.  
- **Medium** for admin page and authorization testing.  
- **Not observed** for GraphQL, API, and Swagger.