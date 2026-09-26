from __future__ import annotations
import asyncio, hashlib, logging, re, socket, ssl, time, xml.etree.ElementTree as ET
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag

# IMPORTANT: import the top-level dns package once. This prevents the old
# UnboundLocalError caused by nested `import dns.query` / `import dns.zone`.
import dns
import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

logger=logging.getLogger("security-auditor.analyzer")
WEIGHTS={"critical":25,"high":15,"medium":8,"low":3,"info":0}
ORDER={"critical":0,"high":1,"medium":2,"low":3,"info":4}
CATEGORIES=["ssl_tls","security_headers","cookies","cors","dns_email","server_disclosure","http_behavior","public_resources","technology_exposure","information_exposure","website_recon"]

@dataclass
class Finding:
    id:str; title:str; severity:str; category:str; description:str; evidence:str=""; impact:str=""; remediation:str=""; reference:str=""; confidence:str="high"; active_check:bool=False
    def to_dict(self):return asdict(self)

@dataclass
class Config:
    timeout:float=10; max_redirects:int=10; verify_tls:bool=True; dns_timeout:float=5; enable_active_checks:bool=False; max_body_bytes:int=524288; max_crawl_depth:int=2; max_crawl_urls:int=200; crawl_concurrency:int=8; user_agent:str="SecureLens/2.1 (authorized passive security assessment)"

class SecurityAnalyzer:
    SECURITY_FILES=("/robots.txt","/sitemap.xml","/.well-known/security.txt")
    SENSITIVE=("/.env","/.git/HEAD","/config.php","/wp-config.php","/server-status","/phpinfo.php","/debug","/debug/","/admin/","/administrator/","/backup/","/backups/","/private/","/internal/","/staging/","/test/","/.DS_Store")
    TECH={
        "WordPress":[r"wp-content/",r"wp-includes/",r"wordpress"],"WooCommerce":[r"woocommerce"],"Drupal":[r"drupalSettings",r"/sites/default/"],"Joomla":[r"joomla",r"/media/system/"],"React":[r"react(?:\.production|\.development)?\.min?\.js",r"data-reactroot"],"Next.js":[r"/_next/static/",r"__NEXT_DATA__"],"Vue":[r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js",r"data-v-[a-f0-9]+"],"Angular":[r"ng-version"],"Bootstrap":[r"bootstrap(?:\.min)?\.css",r"bootstrap(?:\.bundle)?(?:\.min)?\.js"],"jQuery":[r"jquery(?:\.min)?\.js"],"Google Analytics":[r"google-analytics\.com",r"googletagmanager\.com",r"gtag\("],"Cloudflare":[r"cf-ray",r"cloudflare"],"Shopify":[r"cdn\.shopify\.com",r"shopify"]}

    def __init__(self,target:str,timeout=10,max_redirects=10,verify_tls=True,dns_timeout=5,enable_active_checks=False,max_body_bytes=524288,max_crawl_depth=2,max_crawl_urls=200,crawl_concurrency=8):
        self.raw_target=target
        self.target=self.normalize(target)
        p=urlparse(self.target)
        if not p.hostname:raise ValueError("Target URL must contain a valid hostname.")
        self.parsed=p; self.domain=p.hostname.lower(); self.port=p.port or (443 if p.scheme=="https" else 80)
        self.cfg=Config(float(timeout),int(max_redirects),bool(verify_tls),float(dns_timeout),bool(enable_active_checks),max(16384,int(max_body_bytes)),max(0,int(max_crawl_depth)),max(1,int(max_crawl_urls)),max(1,min(32,int(crawl_concurrency))))
        self.findings=[]; self.finding_ids=set()

    @staticmethod
    def normalize(url:str)->str:
        url=url.strip()
        if not url:raise ValueError("A target URL is required.")
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://",url):url="https://"+url
        p=urlparse(url)
        if p.scheme not in {"http","https"}:raise ValueError("Only HTTP and HTTPS targets are supported.")
        if not p.hostname:raise ValueError("Invalid target hostname.")
        return urlunparse((p.scheme.lower(),p.netloc,p.path or "/",p.params,p.query,""))

    @staticmethod
    def norm_url(url:str)->Optional[str]:
        try:
            p=urlparse(url.strip())
            if p.scheme not in {"http","https"} or not p.hostname:return None
            return urlunparse((p.scheme.lower(),p.netloc.lower(),p.path or "/","",p.query,""))
        except Exception:return None

    @staticmethod
    def same_origin(a:str,b:str)->bool:
        x,y=urlparse(a),urlparse(b)
        return (x.scheme.lower(),(x.hostname or "").lower(),x.port or (443 if x.scheme=="https" else 80))==(y.scheme.lower(),(y.hostname or "").lower(),y.port or (443 if y.scheme=="https" else 80))

    def add(self,id,title,severity,category,description,evidence="",impact="",remediation="",reference="",confidence="high",active_check=False):
        if id in self.finding_ids:return
        self.finding_ids.add(id); self.findings.append(Finding(id,title,severity if severity in ORDER else "info",category,description,evidence,impact,remediation,reference,confidence,active_check))

    async def request(self,client,method,url,follow=True,**kwargs):
        t=time.perf_counter()
        try:
            r=await client.request(method,url,follow_redirects=follow,**kwargs)
            return r,{"elapsed_ms":round((time.perf_counter()-t)*1000,2),"error":None}
        except Exception as e:return None,{"elapsed_ms":round((time.perf_counter()-t)*1000,2),"error":f"{type(e).__name__}: {e}"}

    async def tls(self):
        out={"scheme":self.parsed.scheme,"status":"not_applicable","certificate":{},"protocol":None,"cipher":None,"error":None}
        if self.parsed.scheme!="https":
            out["status"]="insecure_http"; self.add("tls.http","HTTPS is not used","high","ssl_tls","The target uses plain HTTP.",self.target,"Traffic can be intercepted or modified.","Serve the application over HTTPS."); return out
        def inspect():
            c=ssl.create_default_context(); c.check_hostname=self.cfg.verify_tls; c.verify_mode=ssl.CERT_REQUIRED if self.cfg.verify_tls else ssl.CERT_NONE
            with socket.create_connection((self.domain,self.port),timeout=self.cfg.timeout) as s:
                with c.wrap_socket(s,server_hostname=self.domain) as ss:return ss.getpeercert(),ss.version(),ss.cipher()
        try:
            cert,proto,cipher=await asyncio.to_thread(inspect); out.update({"status":"valid","protocol":proto,"cipher":{"name":cipher[0] if cipher else None,"protocol":cipher[1] if cipher else None,"bits":cipher[2] if cipher else None}})
            na=cert.get("notAfter"); days=None
            if na:
                dt=datetime.strptime(na,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc); days=int((dt-datetime.now(timezone.utc)).total_seconds()//86400)
            out["certificate"]={"valid":True,"issuer":dict(x[0] for x in cert.get("issuer",[])),"subject":dict(x[0] for x in cert.get("subject",[])),"not_before":cert.get("notBefore"),"not_after":na,"days_left":days,"subject_alt_names":[v for k,v in cert.get("subjectAltName",[]) if k=="DNS"]}
            if days is not None and days<0:self.add("tls.expired","TLS certificate is expired","critical","ssl_tls","The presented certificate has expired.",na,"Clients may reject the connection.","Renew and deploy a valid certificate.")
            elif days is not None and days<=14:self.add("tls.expiring","TLS certificate expires soon","medium","ssl_tls","The certificate is close to expiry.",f"{days} days remaining","Expiry can cause service interruption.","Renew before expiry.")
            if proto in {"TLSv1","TLSv1.1"}:self.add("tls.legacy","Legacy TLS protocol negotiated","high","ssl_tls","An obsolete TLS protocol was negotiated.",proto,"Legacy protocols weaken transport security.","Disable TLS 1.0/1.1.")
        except ssl.SSLCertVerificationError as e:
            out.update({"status":"certificate_verification_failed","error":str(e)}); self.add("tls.verify","TLS certificate verification failed","high","ssl_tls","Certificate verification failed.",str(e),"Clients may not establish a trusted connection.","Deploy a valid certificate chain.")
        except Exception as e:out.update({"status":"error","error":f"{type(e).__name__}: {e}"})
        return out

    def headers(self,h):
        expected={"strict-transport-security":"HSTS","content-security-policy":"CSP","x-frame-options":"X-Frame-Options","x-content-type-options":"X-Content-Type-Options","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy","cross-origin-opener-policy":"COOP","cross-origin-resource-policy":"CORP","cross-origin-embedder-policy":"COEP"}
        out={k:{"name":v,"present":k in h,"value":h.get(k)} for k,v in expected.items()}
        if self.parsed.scheme=="https" and "strict-transport-security" not in h:self.add("headers.hsts","HSTS header is missing","medium","security_headers","Strict-Transport-Security was not detected.","Header absent","Browsers may not enforce HTTPS on future visits.","Configure HSTS after validating HTTPS.")
        if "content-security-policy" not in h:self.add("headers.csp","Content-Security-Policy is missing","medium","security_headers","CSP was not detected.","Header absent","Fewer browser restrictions protect against injection.","Deploy an appropriate CSP.")
        if "x-content-type-options" not in h:self.add("headers.nosniff","X-Content-Type-Options is missing","low","security_headers","X-Content-Type-Options was not detected.","Header absent","MIME sniffing protections are reduced.","Set X-Content-Type-Options: nosniff.")
        csp=h.get("content-security-policy","")
        out["csp"]={"value":csp or None,"frame_ancestors_present":bool(re.search(r"(?:^|;)\s*frame-ancestors\\b",csp,re.I))}
        if csp and "'unsafe-inline'" in csp.lower():self.add("headers.csp.inline","CSP permits unsafe-inline","medium","security_headers","CSP contains unsafe-inline.",csp,"CSP effectiveness is reduced.","Prefer nonces/hashes.")
        if csp and "'unsafe-eval'" in csp.lower():self.add("headers.csp.eval","CSP permits unsafe-eval","medium","security_headers","CSP contains unsafe-eval.",csp,"Dynamic evaluation weakens CSP.","Remove unsafe-eval where practical.")
        if "x-frame-options" not in h and not out["csp"]["frame_ancestors_present"]:self.add("headers.frame","No obvious clickjacking protection detected","medium","security_headers","Neither X-Frame-Options nor CSP frame-ancestors was detected.","Headers absent","The page may be embeddable.","Configure frame-ancestors and/or X-Frame-Options.",confidence="medium")
        return out

    def cookies(self,set_cookies):
        out=[]
        for raw in set_cookies:
            parts=[p.strip() for p in raw.split(";")]
            if not parts or "=" not in parts[0]:continue
            name,_=parts[0].split("=",1); attrs={}
            for p in parts[1:]:
                if "=" in p:k,v=p.split("=",1);attrs[k.lower().strip()]=v.strip()
                else:attrs[p.lower()]=True
            c={"name":name.strip(),"secure":"secure" in attrs,"http_only":"httponly" in attrs,"same_site":attrs.get("samesite"),"path":attrs.get("path"),"domain":attrs.get("domain"),"max_age":attrs.get("max-age"),"expires":attrs.get("expires")};out.append(c)
            sensitive=bool(re.search(r"(session|sess|auth|token|jwt|sid|login|csrf|xsrf)",name,re.I)); d=hashlib.sha1(name.encode()).hexdigest()[:10]
            if self.parsed.scheme=="https" and not c["secure"]:self.add(f"cookie.secure.{d}",f"Cookie '{name}' lacks Secure","medium" if sensitive else "low","cookies","Cookie has no Secure flag.",raw,"It may be sent over HTTP.","Set Secure for HTTPS-only cookies.")
            if sensitive and not c["http_only"]:self.add(f"cookie.http.{d}",f"Sensitive cookie '{name}' lacks HttpOnly","medium","cookies","Likely session/auth cookie is script-readable.",raw,"Injected scripts could access it.","Set HttpOnly unless JS access is required.")
            if not c["same_site"]:self.add(f"cookie.same.{d}",f"Cookie '{name}' lacks SameSite","low","cookies","Cookie has no explicit SameSite policy.",raw,"Cross-site behavior is less explicit.","Use SameSite=Lax or Strict where compatible.")
        return {"count":len(out),"cookies":out}

    def cors(self,h):
        o=h.get("access-control-allow-origin",""); c=h.get("access-control-allow-credentials","");m=h.get("access-control-allow-methods","");ah=h.get("access-control-allow-headers","")
        if o=="*" and c.lower()=="true":self.add("cors.wildcard_credentials","CORS wildcard combined with credentials","high","cors","Wildcard origin and credentials are advertised.",f"origin={o}; credentials={c}","Depending on application behavior, credentialed cross-origin access may expose data.","Use an explicit trusted-origin allowlist.")
        elif o=="*":self.add("cors.wildcard","CORS allows all origins","low","cors","Wildcard CORS is advertised.",o,"Public responses can be read cross-origin.","Restrict sensitive APIs to trusted origins.")
        return {"allow_origin":o,"allow_credentials":c,"allow_methods":m,"allow_headers":ah,"wildcard":o=="*","credentials_true":c.lower()=="true"}

    async def http(self,client):
        r,meta=await self.request(client,"GET",self.target,True)
        out={"status_code":None,"final_url":None,"response_time_ms":meta["elapsed_ms"],"http_version":None,"headers":{},"compression":None,"content_type":None,"content_length":None,"redirect_chain":[],"body":"","error":meta["error"]}
        if not r:return out
        h={k.lower():v for k,v in r.headers.items()}; body=r.content[:self.cfg.max_body_bytes].decode(r.encoding or "utf-8",errors="replace")
        out.update({"status_code":r.status_code,"final_url":str(r.url),"http_version":r.http_version,"headers":h,"compression":h.get("content-encoding"),"content_type":h.get("content-type"),"content_length":h.get("content-length"),"body":body,"error":None,"redirect_chain":[{"status_code":x.status_code,"url":str(x.url),"location":x.headers.get("location")} for x in r.history]})
        return out

    def technology(self,h,body):
        text = body or ""; headers = {str(k).lower(): str(v) for k,v in h.items()}; signals=[]; rank={"high":3,"medium":2,"low":1}
        def add(name,confidence,evidence,source): signals.append({"name":name,"confidence":confidence,"evidence":list(dict.fromkeys(evidence))[:8],"source":source})
        def matches(patterns,haystack=text): return [p for p in patterns if re.search(p,haystack,re.I)]
        signatures={
            "WordPress":[r"wp-content/",r"wp-includes/",r"wordpress",r"generator[^>]*wordpress"],"WooCommerce":[r"woocommerce",r"wc-cart-fragments",r"wc-add-to-cart"],
            "Drupal":[r"drupalsettings",r"/sites/default/",r"generator[^>]*drupal"],"Joomla":[r"joomla",r"/media/system/",r"generator[^>]*joomla"],
            "React":[r"data-reactroot",r"react-dom",r"react\.production",r"react\.development",r"__reactfiber",r"reactroot"],
            "Next.js":[r"/_next/static/",r"__next_data__",r"next/router",r"next-head-count",r"self\.__next_f"],"Nuxt":[r"/_nuxt/",r"__nuxt__",r"data-n-head"],
            "Vue":[r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js",r"data-v-[a-f0-9]{4,}",r"vue-router"],
            "Angular":[r"ng-version",r"ng-app",r"angular\.min\.js",r"@angular",r"_nghost-",r"_ngcontent-"],"Svelte":[r"svelte",r"svelte_component"],
            "Bootstrap":[r"bootstrap(?:\.min)?\.css",r"bootstrap(?:\.bundle)?(?:\.min)?\.js"],"Tailwind CSS":[r"tailwindcss",r"cdn\.tailwindcss\.com"],
            "jQuery":[r"jquery(?:[-.]\w+)?(?:\.min)?\.js",r"jquery\(",r"\$\(document\)"],"Google Analytics":[r"google-analytics\.com",r"googletagmanager\.com",r"gtag\(",r"dataLayer"],
            "Google Tag Manager":[r"googletagmanager\.com/gtm",r"gtm\.js"],"Cloudflare":[r"cf-ray",r"cloudflare",r"cdnjs\.cloudflare\.com"],"Shopify":[r"cdn\.shopify\.com",r"shopify",r"shopifycdn"],
            "Wix":[r"wixstatic\.com",r"wix\.com"],"Webflow":[r"webflow\.com",r"webflow\.js",r"data-wf-page",r"data-wf-site"],"Elementor":[r"elementor",r"elementor-frontend",r"elementor-pro"],
            "Font Awesome":[r"font-awesome",r"fontawesome",r"fa-[a-z-]+"],"Cloudinary":[r"res\.cloudinary\.com",r"cloudinary"],"Stripe":[r"js\.stripe\.com",r"stripe\.com",r"stripe\.js"],"reCAPTCHA":[r"google\.com/recaptcha",r"gstatic\.com/recaptcha",r"grecaptcha"]}
        for name,pats in signatures.items():
            hit=matches(pats)
            if hit:add(name,"high" if len(hit)>1 else "medium",hit,"html")
        header_text="\n".join(f"{k}: {v}" for k,v in headers.items())
        header_rules={"Cloudflare":[r"cf-ray",r"cloudflare"],"Vercel":[r"x-vercel-id",r"x-vercel-cache"],"Netlify":[r"x-nf-request-id"],"Amazon CloudFront":[r"x-amz-cf-id",r"x-amz-cf-pop"],"AWS":[r"x-amzn-requestid",r"x-amz-apigw-id"],"Fastly":[r"x-served-by",r"fastly"],"GitHub Pages":[r"x-github-request-id"],"nginx":[r"server:\s*nginx"],"Apache":[r"server:\s*apache"]}
        for name,pats in header_rules.items():
            hit=matches(pats,header_text)
            if hit:add(name,"high",hit,"headers")
        generators=re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',text,re.I)
        for value in generators:add("Generator: "+value.strip()[:80],"high",[value.strip()],"meta")
        assets=re.findall(r"(?is)(?:src|href)\s*=\s*[\"']([^\"']+)[\"']",text); asset_text="\n".join(assets)
        asset_rules={"React":[r"react(?:[-./])",r"react-dom"],"Vue":[r"vue(?:[-./])",r"vue-router"],"Angular":[r"angular(?:[-./])",r"@angular"],"jQuery":[r"jquery(?:[-./])"],"Bootstrap":[r"bootstrap(?:[-./])"],"Next.js":[r"/_next/"],"Nuxt":[r"/_nuxt/"],"Font Awesome":[r"font[-]?awesome",r"fontawesome"],"Google Fonts":[r"fonts\.googleapis\.com",r"fonts\.gstatic\.com"]}
        existing={x["name"] for x in signals}
        for name,pats in asset_rules.items():
            hit=matches(pats,asset_text)
            if hit and name not in existing:add(name,"high" if name in {"Next.js","Nuxt"} else "medium",hit,"assets")
        cookie_text="\n".join(v for k,v in headers.items() if k=="set-cookie"); cookie_rules={"PHP":[r"PHPSESSID"],"Laravel":[r"laravel_session",r"XSRF-TOKEN"],"Django":[r"csrftoken",r"sessionid"],"ASP.NET":[r"\.ASPXAUTH",r"ASP\.NET_SessionId"]}; existing={x["name"] for x in signals}
        for name,pats in cookie_rules.items():
            hit=matches(pats,cookie_text)
            if hit and name not in existing:add(name,"high",hit,"cookies")
        merged={}
        for item in signals:
            old=merged.get(item["name"])
            if not old or rank[item["confidence"]]>rank[old["confidence"]]:merged[item["name"]]=item
            elif old:old["evidence"]=list(dict.fromkeys(old["evidence"]+item["evidence"]))[:8];old["source"]=', '.join(dict.fromkeys((old["source"]+', '+item["source"]).split(', ')))
        detected=sorted(merged.values(),key=lambda x:(-rank[x["confidence"]],x["name"].lower()))
        server=headers.get("server",""); powered=headers.get("x-powered-by","")
        if server:self.add("server.header","Server software is disclosed","low","server_disclosure","Server header exposes server information.",server,"Technology disclosure assists fingerprinting.","Minimize server-version disclosure.")
        if powered:self.add("server.powered","X-Powered-By is disclosed","low","server_disclosure","X-Powered-By exposes framework information.",powered,"Technology disclosure assists fingerprinting.","Remove or suppress X-Powered-By.")
        return {"detected":detected,"server":server,"x_powered_by":powered,"other_disclosure_headers":{k:headers[k] for k in ("x-generator","x-aspnet-version","x-runtime","via","x-cache","x-served-by") if k in headers},"signals_scanned":{"html":bool(body),"assets":len(assets),"headers":len(headers),"cookies":bool(cookie_text)}}

    def resolver(self):
        r=dns.resolver.Resolver();r.timeout=self.cfg.dns_timeout;r.lifetime=self.cfg.dns_timeout;return r
    def dnsq(self,r,name,typ):
        try:return {"status":"ok","values":[str(x).rstrip(".") for x in r.resolve(name,typ)],"error":None}
        except dns.resolver.NXDOMAIN:return {"status":"nxdomain","values":[],"error":"NXDOMAIN"}
        except dns.resolver.NoAnswer:return {"status":"no_answer","values":[],"error":"NoAnswer"}
        except dns.resolver.NoNameservers:return {"status":"no_nameservers","values":[],"error":"NoNameservers"}
        except dns.exception.Timeout:return {"status":"timeout","values":[],"error":"Timeout"}
        except Exception as e:return {"status":"error","values":[],"error":f"{type(e).__name__}: {e}"}

    def spf(self,values):
        rec=[v for v in values if v.lower().startswith("v=spf1")];issues=[]
        if not rec:issues.append("No SPF record found.")
        elif len(rec)>1:issues.append("Multiple SPF records were found.")
        if rec and not re.search(r"(?:^|\s)[~?+-]all(?:\s|$)",rec[0]):issues.append("SPF record has no explicit all mechanism.")
        if rec and "+all" in rec[0].lower():issues.append("SPF uses +all, which permits all senders.")
        return {"present":bool(rec),"records":rec,"valid":bool(rec) and not any("Multiple" in x or "+all" in x for x in issues),"issues":issues}
    def dmarc(self,values):
        rec=[v for v in values if v.lower().startswith("v=dmarc1")];issues=[];policy=None
        if not rec:issues.append("No DMARC record found.")
        else:
            tags={}
            for part in rec[0].split(";"):
                if "=" in part:k,v=part.strip().split("=",1);tags[k.lower()]=v.strip()
            policy=tags.get("p")
            if policy not in {"none","quarantine","reject"}:issues.append("DMARC policy p= is missing or invalid.")
            elif policy=="none":issues.append("DMARC policy is monitoring-only (p=none).")
        return {"present":bool(rec),"records":rec,"policy":policy,"valid":bool(rec) and not any("invalid" in x for x in issues),"issues":issues}

    async def axfr(self,r):
        out={"checked":False,"vulnerable":False,"nameservers":[],"successful_servers":[],"evidence":"","error":None}
        if not self.cfg.enable_active_checks:out["error"]="Disabled unless authorized active checks are enabled.";return out
        ns=self.dnsq(r,self.domain,"NS");out["nameservers"]=ns["values"];out["checked"]=True
        for name in ns["values"]:
            try:
                ips=self.dnsq(r,name,"A")["values"]
                for ip in ips:
                    def transfer():return dns.zone.from_xfr(dns.query.xfr(ip,self.domain,lifetime=self.cfg.dns_timeout,timeout=self.cfg.dns_timeout),relativize=False)
                    z=await asyncio.to_thread(transfer);out["vulnerable"]=True;out["successful_servers"].append(ip);out["evidence"]=f"AXFR returned {len(z.nodes)} DNS names from {ip}.";self.add("dns.axfr","DNS zone transfer appears permitted","high","dns_email","AXFR returned zone data.",out["evidence"],"Zone contents may be disclosed.","Restrict AXFR to authorized secondary servers.",active_check=True);return out
            except Exception as e:out["error"]=f"{type(e).__name__}: {e}"
        return out

    async def dns(self):
        r=self.resolver(); types={x:x for x in ("A","AAAA","CNAME","NS","MX","TXT","CAA")}
        raw={k:await asyncio.to_thread(self.dnsq,r,self.domain,v) for k,v in types.items()};txt=raw["TXT"]["values"]
        spf=self.spf(txt);dr=await asyncio.to_thread(self.dnsq,r,f"_dmarc.{self.domain}","TXT");dmarc=self.dmarc(dr["values"]);dk=await asyncio.to_thread(self.dnsq,r,self.domain,"DNSKEY")
        if not spf["present"]:self.add("dns.spf","SPF record is missing","medium","dns_email","No SPF TXT record was detected.",self.domain,"Mail receivers have less sender-validation information.","Publish SPF.")
        if any("+all" in x for x in spf["issues"]):self.add("dns.spf.all","SPF uses +all","high","dns_email","SPF authorizes all senders.","; ".join(spf["records"]),"Any sender can appear authorized.","Use a restrictive SPF terminating mechanism.")
        if len(spf["records"])>1:self.add("dns.spf.multiple","Multiple SPF records detected","high","dns_email","More than one SPF record exists."," | ".join(spf["records"]),"SPF evaluation can fail.","Combine into one SPF record.")
        if not dmarc["present"]:self.add("dns.dmarc","DMARC record is missing","medium","dns_email","No DMARC record was detected.",f"_dmarc.{self.domain}","Reduced protection against spoofed email.","Publish DMARC.")
        elif dmarc["policy"]=="none":self.add("dns.dmarc.none","DMARC is monitoring-only","low","dns_email","DMARC uses p=none.","; ".join(dmarc["records"]),"Receivers are not told to quarantine/reject failures.","Strengthen policy after validation.")
        return {"records":raw,"spf":spf,"dmarc":dmarc,"dnssec":{"dnskey_present":bool(dk["values"]),"status":dk["status"]},"axfr":await self.axfr(r)}

    def robots_parse(self,text):
        groups=[];sitemaps=[];agents=[];allow=[];disallow=[]
        def flush():
            nonlocal agents,allow,disallow
            if agents:groups.append({"user_agents":agents,"allow":allow,"disallow":disallow})
            agents=[];allow=[];disallow=[]
        for raw in text.splitlines():
            line=raw.split("#",1)[0].strip()
            if not line or ":" not in line:continue
            k,v=line.split(":",1);k=k.strip().lower();v=v.strip()
            if k=="user-agent":
                if agents and (allow or disallow):flush()
                agents.append(v or "*")
            elif k=="allow":allow.append(v)
            elif k=="disallow":disallow.append(v)
            elif k=="sitemap":
                u=self.norm_url(v)
                if u:sitemaps.append(u)
        flush();return {"present":bool(groups or sitemaps),"groups":groups,"sitemaps":list(dict.fromkeys(sitemaps)),"allow_rules":[x for g in groups for x in g["allow"]],"disallow_rules":[x for g in groups for x in g["disallow"]],"raw":text[:self.cfg.max_body_bytes]}

    def robots_policy(self,url,robots):
        p=urlparse(url);path=p.path or "/";path+=(("?"+p.query) if p.query else "")
        groups=[]
        for g in robots.get("groups",[]):
            agents=[x.lower() for x in g["user_agents"]]
            if "*" in agents:groups.append(g)
        matches=[]
        for g in groups:
            for pattern in g["allow"]:
                if self.robot_match(pattern,path):matches.append((len(pattern),True,pattern))
            for pattern in g["disallow"]:
                if self.robot_match(pattern,path):matches.append((len(pattern),False,pattern))
        if not matches:return {"classification":"allowed","matched_rule":None}
        matches.sort(key=lambda x:(x[0],x[1]),reverse=True);_,ok,rule=matches[0]
        return {"classification":"allowed" if ok else "disallowed","matched_rule":rule}

    @staticmethod
    def robot_match(pattern,path):
        if pattern=="":return False
        end=pattern.endswith("$");pattern=pattern[:-1] if end else pattern
        try:return re.match("^"+re.escape(pattern).replace(r"\*",".*")+("$" if end else ""),path,re.I) is not None
        except re.error:return False

    async def resource(self,client,url):
        r,m=await self.request(client,"GET",url,True)
        if not r:return {"url":url,"status_code":None,"final_url":None,"content_type":None,"text":"","error":m["error"]}
        return {"url":url,"status_code":r.status_code,"final_url":str(r.url),"content_type":r.headers.get("content-type"),"text":r.content[:self.cfg.max_body_bytes].decode(r.encoding or "utf-8",errors="replace"),"error":None}

    def sitemap_xml(self,text):
        try:root=ET.fromstring(text.lstrip("\ufeff \t\r\n"))
        except ET.ParseError as e:return {"valid_xml":False,"kind":"unknown","urls":[],"nested_sitemaps":[],"error":str(e)}
        name=root.tag.rsplit("}",1)[-1].lower();kind="sitemap_index" if name=="sitemapindex" else "urlset" if name=="urlset" else "unknown";urls=[];nested=[]
        for e in root.iter():
            if e.tag.rsplit("}",1)[-1].lower()!="loc":continue
            u=self.norm_url((e.text or "").strip())
            if not u:continue
            (nested if kind=="sitemap_index" else urls).append(u)
        return {"valid_xml":True,"kind":kind,"urls":list(dict.fromkeys(urls)),"nested_sitemaps":list(dict.fromkeys(nested)),"error":None}

    async def sitemap(self,client,robots):
        origin=f"{self.parsed.scheme}://{self.parsed.netloc}";cands=list(robots["sitemaps"])+[f"{origin}/sitemap.xml",f"{origin}/sitemap_index.xml",f"{origin}/sitemap-index.xml"];q=deque();seen=set()
        for x in cands:
            u=self.norm_url(x)
            if u and self.same_origin(u,self.target):q.append(u)
        urls=[];nested=[];resources=[];errors=[]
        while q and len(seen)<max(20,min(self.cfg.max_crawl_urls,500)):
            u=q.popleft()
            if u in seen:continue
            seen.add(u);res=await self.resource(client,u);resources.append({k:v for k,v in res.items() if k!="text"})
            if res["status_code"]!=200:continue
            parsed=self.sitemap_xml(res["text"])
            if not parsed["valid_xml"]:errors.append(f"{u}: {parsed['error']}");continue
            for page in parsed["urls"]:
                if self.same_origin(page,self.target):urls.append(page)
            for sm in parsed["nested_sitemaps"]:
                if self.same_origin(sm,self.target):nested.append(sm);q.append(sm)
        return {"resources":resources,"sitemaps":list(seen),"nested_sitemaps":list(dict.fromkeys(nested)),"urls":list(dict.fromkeys(urls)),"errors":errors}

    @staticmethod
    def html_links(page,html):
        same=[];external=[]
        for href in re.findall(r'''(?is)<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["']''',html):
            if href.strip().lower().startswith(("#","mailto:","tel:","javascript:","data:")):continue
            u=SecurityAnalyzer.norm_url(urldefrag(urljoin(page,href.strip()))[0])
            if not u:continue
            (same if SecurityAnalyzer.same_origin(u,page) else external).append(u)
        return list(dict.fromkeys(same)),list(dict.fromkeys(external))

    async def crawl(self,client,seeds,robots):
        q=deque();queued=set();visited=set();pages={};html_urls=set();external=set();edges=[];limit=self.cfg.max_crawl_urls;depth_limit=self.cfg.max_crawl_depth
        for s in seeds:
            u=self.norm_url(s)
            if u and self.same_origin(u,self.target) and u not in queued:queued.add(u);q.append((u,0,"seed"))
        sem=asyncio.Semaphore(self.cfg.crawl_concurrency)
        async def one(url,depth,source):
            async with sem:r,m=await self.request(client,"GET",url,True)
            if not r:return url,depth,source,{"url":url,"final_url":None,"status_code":None,"content_type":None,"response_time_ms":m["elapsed_ms"],"error":m["error"]},[],[]
            body=r.content[:self.cfg.max_body_bytes].decode(r.encoding or "utf-8",errors="replace");ct=r.headers.get("content-type","");same=[];ext=[]
            if "html" in ct.lower():same,ext=self.html_links(str(r.url),body)
            return url,depth,source,{"url":url,"final_url":str(r.url),"status_code":r.status_code,"content_type":ct,"response_time_ms":m["elapsed_ms"],"content_length":len(r.content),"error":None},same,ext
        while q and len(visited)<limit:
            batch=[]
            while q and len(batch)<self.cfg.crawl_concurrency and len(visited)+len(batch)<limit:
                u,d,s=q.popleft()
                if u in visited:continue
                visited.add(u);batch.append((u,d,s))
            results=await asyncio.gather(*(one(*x) for x in batch))
            for u,d,s,meta,links,ext in results:
                meta.update({"depth":d,"source":s,"robots":self.robots_policy(u,robots),"links_found":len(links),"external_links_found":len(ext)});pages[u]=meta
                for x in ext:external.add(x)
                for x in links:
                    html_urls.add(x);edges.append({"from":u,"to":x})
                    if d<depth_limit and x not in queued and x not in visited and len(queued)<limit:queued.add(x);q.append((x,d+1,"html"))
        return {"pages":pages,"html_urls":list(html_urls),"external_urls":list(external),"link_edges":edges,"visited_count":len(visited)}

    async def recon(self,client,http_info):
        origin=f"{self.parsed.scheme}://{self.parsed.netloc}";rr=await self.resource(client,f"{origin}/robots.txt");robots=self.robots_parse(rr["text"] if rr["status_code"]==200 else "");sm=await self.sitemap(client,robots)
        seeds=[self.target]+([self.norm_url(http_info["final_url"])] if http_info.get("final_url") else [])+sm["urls"];crawl=await self.crawl(client,[x for x in seeds if x],robots)
        all_urls=set(sm["urls"])|set(crawl["html_urls"])|{x for x in seeds if x};inventory=[]
        for u in sorted(x for x in all_urls if x and self.same_origin(x,self.target)):
            policy=self.robots_policy(u,robots);p=crawl["pages"].get(u);inventory.append({"url":u,"path":urlparse(u).path or "/","query":urlparse(u).query,"source":(["target"] if u==self.target else [])+(["sitemap"] if u in sm["urls"] else [])+(["html"] if u in crawl["html_urls"] else []),"robots":policy["classification"],"robots_rule":policy["matched_rule"],"http_status":p.get("status_code") if p else None,"accessibility":"publicly_accessible" if p and p.get("status_code") is not None and p.get("status_code")<400 else "not_crawled" if not p else "not_successful","final_url":p.get("final_url") if p else None,"depth":p.get("depth") if p else None,"content_type":p.get("content_type") if p else None})
        allowed=[x for x in inventory if x["robots"]=="allowed"];disallowed=[x for x in inventory if x["robots"]=="disallowed"];reachable=[x for x in disallowed if x["http_status"] is not None and x["http_status"]<400]
        if reachable:self.add("recon.disallowed_reachable","Robots-disallowed URLs are publicly reachable","info","website_recon","Some URLs marked Disallow returned successful HTTP responses.","; ".join(x["url"] for x in reachable[:10]),"robots.txt is not access control.","Protect sensitive URLs with authentication/authorization.")
        return {"status":"completed","target":self.target,"origin":origin,"limits":{"max_depth":self.cfg.max_crawl_depth,"max_urls":self.cfg.max_crawl_urls,"crawl_concurrency":self.cfg.crawl_concurrency},"robots":{"url":rr["url"],"status_code":rr["status_code"],"available":rr["status_code"]==200,"groups":robots["groups"],"sitemaps":robots["sitemaps"],"allow_rules":robots["allow_rules"],"disallow_rules":robots["disallow_rules"],"raw":robots["raw"],"error":rr["error"]},"sitemap":{**{k:sm[k] for k in ("resources","sitemaps","nested_sitemaps","errors")},"url_count":len(sm["urls"]),"urls":sm["urls"]},"crawl":{"visited_count":crawl["visited_count"],"html_discovered_count":len(crawl["html_urls"]),"external_link_count":len(crawl["external_urls"]),"external_urls":crawl["external_urls"][:500],"pages":list(crawl["pages"].values()),"link_edges":crawl["link_edges"][:2000]},"url_inventory":inventory,"allowed_pages":allowed,"disallowed_pages":disallowed,"publicly_reachable_disallowed":reachable,"counts":{"unique_urls":len(inventory),"allowed":len(allowed),"disallowed":len(disallowed),"sitemap_urls":len(sm["urls"]),"html_discovered":len(crawl["html_urls"]),"crawled":len(crawl["pages"]),"publicly_reachable_disallowed":len(reachable)}}

    async def public_resources(self,client):
        out={}
        for path in self.SECURITY_FILES:
            u=urljoin(self.target+"/",path.lstrip("/"));r=await self.resource(client,u);out[path]={"path":path,"url":u,"status_code":r["status_code"],"final_url":r["final_url"],"available":r["status_code"]==200,"content_type":r["content_type"],"size":len(r["text"].encode()),"error":r["error"]}
            if path=="/.well-known/security.txt" and r["status_code"]!=200:self.add("public.securitytxt","security.txt was not detected","info","public_resources","The standard security.txt resource was not detected.",u,"Researchers have less disclosure guidance.","Publish /.well-known/security.txt.")
        return out

    async def active_exposure(self,client):
        out={"status":"disabled","checked_paths":[],"exposed_paths":[]}
        if not self.cfg.enable_active_checks:return out
        out["status"]="enabled"
        async def check(path):
            r,m=await self.request(client,"GET",urljoin(self.target+"/",path.lstrip("/")),False)
            if not r:return {"path":path,"status_code":None,"content_type":None,"size":0,"body_sample":"","error":m["error"]}
            body=r.content[:self.cfg.max_body_bytes].decode(r.encoding or "utf-8",errors="replace");return {"path":path,"status_code":r.status_code,"content_type":r.headers.get("content-type"),"size":len(r.content),"body_sample":body[:2000],"error":None}
        out["checked_paths"]=await asyncio.gather(*(check(x) for x in self.SENSITIVE))
        for x in out["checked_paths"]:
            if x["status_code"] in {200,206}:
                sev="critical" if x["path"]=="/.env" and re.search(r"(APP_KEY|DB_PASSWORD|SECRET|API_KEY|AWS_ACCESS_KEY)",x["body_sample"],re.I) else "high";self.add("exposure."+hashlib.sha1(x["path"].encode()).hexdigest()[:12],f"Potentially sensitive resource exposed: {x['path']}",sev,"information_exposure","A commonly sensitive path returned a successful response.",f"HTTP {x['status_code']} at {x['path']}","Public exposure may reveal sensitive information.","Remove unintended public access and enforce authorization.",active_check=True);out["exposed_paths"].append(x)
        return out

    async def active_methods(self,client):
        out={"enabled":self.cfg.enable_active_checks,"options":None,"trace":None,"methods":None}
        if not self.cfg.enable_active_checks:return out
        r,m=await self.request(client,"OPTIONS",self.target,False)
        if r:out["options"]={"status_code":r.status_code,"allow":r.headers.get("allow"),"access_control_allow_methods":r.headers.get("access-control-allow-methods"),"access_control_allow_headers":r.headers.get("access-control-allow-headers"),"response_time_ms":m["elapsed_ms"]}
        r,m=await self.request(client,"TRACE",self.target,False)
        if r:
            out["trace"]={"status_code":r.status_code,"response_time_ms":m["elapsed_ms"]}
            if r.status_code<405:self.add("active.trace","HTTP TRACE is enabled","medium","http_behavior","The target accepted TRACE.",f"HTTP {r.status_code}","TRACE increases unnecessary attack surface.","Disable TRACE unless explicitly required.",active_check=True)
        out["methods"]={"tested":["OPTIONS","TRACE"],"note":"No destructive or state-changing requests are performed."};return out

    def surface(self,http,dns,tech,recon,exposure):
        endpoints=[{"type":"primary","url":self.target,"status":http.get("status_code")}]
        endpoints += [{"type":"redirect","url":x["url"],"status":x["status_code"]} for x in http.get("redirect_chain",[]) if x.get("url")!=self.target]
        dns_parts=[]
        for typ in ("A","AAAA","CNAME","MX","NS"):
            for v in dns.get("records",{}).get(typ,{}).get("values",[]):dns_parts.append({"type":typ,"value":v})
        return {"primary_host":self.domain,"endpoints":endpoints,"website_map":{"url_count":recon["counts"]["unique_urls"],"allowed":recon["counts"]["allowed"],"disallowed":recon["counts"]["disallowed"],"crawled":recon["counts"]["crawled"]},"dns_components":dns_parts,"technologies":tech.get("detected",[]),"sensitive_path_candidates":[{"path":x.get("path"),"status_code":x.get("status_code")} for x in exposure.get("exposed_paths",[])],"surface_counts":{"endpoints":len(endpoints),"website_urls":recon["counts"]["unique_urls"],"allowed_pages":recon["counts"]["allowed"],"disallowed_pages":recon["counts"]["disallowed"],"crawled_pages":recon["counts"]["crawled"],"dns_components":len(dns_parts),"technologies":len(tech.get("detected",[])),"sensitive_path_candidates":len(exposure.get("exposed_paths",[]))}}

    def scores(self):
        buckets={x:[] for x in CATEGORIES}
        for f in self.findings:buckets.setdefault(f.category,[]).append(f)
        cats={}
        for c in CATEGORIES:
            fs=buckets[c];pen=sum(WEIGHTS.get(f.severity,0) for f in fs);cnt=Counter(f.severity for f in fs);cats[c]={"score":max(0,100-pen),"finding_count":len(fs),**{s:cnt.get(s,0) for s in ORDER}}
        vals=[cats[x]["score"] for x in CATEGORIES if cats[x]["finding_count"] or x in {"ssl_tls","security_headers","cookies","cors","dns_email"}];score=round(sum(vals)/max(1,len(vals)));grade="A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F";return cats,{"score":score,"grade":grade,"label":"Strong posture" if score>=90 else "Good posture" if score>=80 else "Needs attention" if score>=70 else "High attention required"}

    def recommendations(self):
        fs=sorted(self.findings,key=lambda f:(ORDER[f.severity],f.title.lower()));out=[]
        for f in fs[:12]:
            if f.severity=="info":continue
            out.append({"priority":"Immediate" if f.severity=="critical" else "High" if f.severity=="high" else "Medium" if f.severity=="medium" else "Low","title":f.title,"reason":f.impact or f.description,"action":f.remediation,"category":f.category,"finding_ids":[f.id]})
        return out

    async def run_audit(self):
        start=time.perf_counter();started=datetime.now(timezone.utc).isoformat();base={"schema_version":"2.1","scanner":{"name":"SecureLens","version":"2.1.0","mode":"authorized-active" if self.cfg.enable_active_checks else "passive-first"},"audit":{"status":"running","started_at":started,"duration_ms":0,"error":None},"target":{"url":self.target,"raw_url":self.raw_target,"domain":self.domain,"scheme":self.parsed.scheme,"port":self.port}}
        try:
            limits=httpx.Limits(max_connections=30,max_keepalive_connections=15)
            async with httpx.AsyncClient(verify=self.cfg.verify_tls,timeout=self.cfg.timeout,max_redirects=self.cfg.max_redirects,headers={"User-Agent":self.cfg.user_agent,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},limits=limits) as client:
                h=await self.http(client);headers=h["headers"];tls=await self.tls();sec=self.headers(headers);cookies=self.cookies([v for k,v in headers.items() if k.lower()=="set-cookie"]);cors=self.cors(headers);tech=self.technology(headers,h["body"]);dnsr=await self.dns();public=await self.public_resources(client);recon=await self.recon(client,h);exposure=await self.active_exposure(client);active=await self.active_methods(client);surface=self.surface(h,dnsr,tech,recon,exposure)
            self.findings.sort(key=lambda f:(ORDER[f.severity],f.category,f.title.lower()));cats,score=self.scores();recs=self.recommendations();cnt=Counter(f.severity for f in self.findings);duration=round((time.perf_counter()-start)*1000,2)
            base.update({"http":{k:v for k,v in h.items() if k!="body"},"ssl_tls":tls,"security_headers":sec,"cookies":cookies,"cors":cors,"dns_email":dnsr,"technology":tech,"public_resources":public,"information_exposure":exposure,"active_checks":active,"website_recon":recon,"attack_surface":surface,"findings":[f.to_dict() for f in self.findings],"category_scores":cats,"security_score":score,"recommendations":recs,"summary":{"total":len(self.findings),**{s:cnt.get(s,0) for s in ORDER},"recommendations":len(recs)},"audit":{"status":"completed","started_at":started,"completed_at":datetime.now(timezone.utc).isoformat(),"duration_ms":duration,"error":None}})
            logger.info("Security audit completed | target=%s | status=completed | urls=%s | findings=%s",self.target,recon["counts"]["unique_urls"],len(self.findings));return base
        except Exception as e:
            duration=round((time.perf_counter()-start)*1000,2);logger.exception("Security audit failed | target=%s",self.target);base.update({"findings":[f.to_dict() for f in self.findings],"summary":{"total":len(self.findings),"critical":0,"high":0,"medium":0,"low":0,"info":0,"recommendations":0},"audit":{"status":"failed","started_at":started,"completed_at":datetime.now(timezone.utc).isoformat(),"duration_ms":duration,"error":f"{type(e).__name__}: {e}"},"error":f"{type(e).__name__}: {e}"});return base
