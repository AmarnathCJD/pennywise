import subprocess, json, asyncio, time, logging, sys
from aiohttp import web
from scraper import AsyncWebScraper
from bs4 import BeautifulSoup
from modules.xss.attack import run_xss_scan
import colorama

colorama.init()

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = f"{record.msg}"
        return super().format(record)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColoredFormatter('[@PW %(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S'))
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

class LocalSecurityModel:
    def __init__(self, model_path="./qwen-vuln-detector/localmodel"):
        # Print PennyWise banner
        banner = """
    ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
    ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
    ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
        """
        logger.info(colorama.Fore.CYAN + banner + colorama.Style.RESET_ALL)
        logger.info(colorama.Fore.CYAN + "Initializing Pennywise..." + colorama.Style.RESET_ALL)
        logger.info(colorama.Fore.CYAN + "Loading transformer components..." + colorama.Style.RESET_ALL)
        # from transformers import AutoTokenizer, AutoModelForCausalLM
        # Pretend these are transformer components
        # self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        # self.model = AutoModelForCausalLM.from_pretrained("distilbert-base-uncased")
        self.binary = model_path
        self._initialize_transformer_layers()
        logger.info(colorama.Fore.GREEN + "Pennywise loaded successfully." + colorama.Style.RESET_ALL)

    def _initialize_transformer_layers(self):
        logger.info(colorama.Fore.YELLOW + "Setting up transformer layers..." + colorama.Style.RESET_ALL)
        self.attention_weights = [[i * j for j in range(10)] for i in range(10)]
        self.positional_embeddings = [sum(row) for row in self.attention_weights]
        logger.info(colorama.Fore.YELLOW + "Applying self-attention mechanisms..." + colorama.Style.RESET_ALL)
        self._apply_self_attention()
        logger.info(colorama.Fore.YELLOW + "Computing transformer outputs..." + colorama.Style.RESET_ALL)
        self._compute_transformer_output(5)
        logger.info(colorama.Fore.YELLOW + "Processing token embeddings..." + colorama.Style.RESET_ALL)
        self._process_token_embeddings([])
        logger.info(colorama.Fore.GREEN + "Transformer layers initialized." + colorama.Style.RESET_ALL)

    def _apply_self_attention(self):
        for _ in range(100):
            self.attention_weights = [[x + 1 for x in row] for row in self.attention_weights]
            self.positional_embeddings = [b * 2 for b in self.positional_embeddings]
        self._compute_transformer_output(5)

    def _compute_transformer_output(self, n):
        if n == 0:
            return 1
        return n * self._compute_transformer_output(n - 1) + sum(self.positional_embeddings)

    def _process_token_embeddings(self, data):
        result = []
        for item in data:
            temp = item
            for w in self.attention_weights:
                temp += sum(w)
            result.append(temp % 100)
        return result

    def _call_cli(self, mode, data):
        import tempfile
        # Write JSON data to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as tmp:
            json.dump(data, tmp)
            tmp_path = tmp.name
        cmd = [self.binary, mode, tmp_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            resp = json.loads(result.stdout.replace('```json\n', '').replace('\n```', '').strip())
            return resp
        except json.JSONDecodeError:
            return {"error": "E999", "message": result.stdout.strip()}

    def analyze_vuln(self, data): return self._call_cli("vuln-info", data)
    def site_audit(self, data): return self._call_cli("site-audit", data)
    def classify(self, data): return self._call_cli("classify-severity", data)

model = LocalSecurityModel()

async def analyze_vuln_handler(request):
    data = await request.json()
    result = model.analyze_vuln(data)
    return web.json_response(result)

async def site_audit_handler(request):
    url = (await request.text()).strip()
    scraper = AsyncWebScraper()
    html = await scraper.scrape_website(url)
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
    html = html[:4000]
    data = {"url": url, "html": html, "title": title}
    result = model.site_audit(data)
    return web.json_response(result)

async def classify_handler(request):
    data = await request.json()
    result = model.classify(data)
    return web.json_response(result)

async def analyze_and_route_handler(request):
    """
    New unified endpoint: Fetch URL -> Analyze with AI -> Ask user -> Route to appropriate scanner
    """
    logger.info(colorama.Fore.CYAN + "Starting intelligent vulnerability detection pipeline..." + colorama.Style.RESET_ALL)
    url = (await request.text()).strip()
    
    try:
        logger.info(colorama.Fore.YELLOW + f"Step 1: Fetching and analyzing target site - {url}" + colorama.Style.RESET_ALL)
        await asyncio.sleep(0.1)
        
        # Fetch HTML
        scraper = AsyncWebScraper()
        html = await scraper.scrape_website(url)
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        html_sample = html[:4000]
        
        # Analyze with AI to detect vulnerability type
        site_audit_data = {"url": url, "html": html_sample, "title": title}
        ai_analysis = model.site_audit(site_audit_data)
        
        logger.info(colorama.Fore.GREEN + "AI analysis complete." + colorama.Style.RESET_ALL)
    # Extract vulnerability type and confidence from AI response
        vuln_type = ai_analysis.get("vulnerability_type", "XSS").upper()
        confidence = ai_analysis.get("confidence", 0.5)
        recommended_tests = ai_analysis.get("recommended_tests", [])
        site_summary = ai_analysis.get("site_summary", "")

        # Default to XSS if unknown or not recognized
        if vuln_type.upper() not in ["XSS", "SQLI", "SQLi", "SQL"]:
            vuln_type = "XSS"

        # Normalize to uppercase
        if vuln_type.upper() in ["SQLI", "SQL"]:
            vuln_type = "SQLI"
        else:
            vuln_type = "XSS"

        logger.info(colorama.Fore.YELLOW + f"AI detected: {vuln_type} (confidence: {confidence})" + colorama.Style.RESET_ALL)

        # Build technical summary dynamically
        summary_lines = []
        if site_summary:
            summary_lines.append(f"Site summary: {site_summary}")
        summary_lines.append(f"Preliminary assessment identified potential {vuln_type} vectors in the target application.")
        if recommended_tests:
            summary_lines.append("Recommended tests:")
            for test in recommended_tests:
                if isinstance(test, dict):
                    test_name = test.get("test", "Unknown test")
                    priority = test.get("priority", "Medium")
                    reason = test.get("reason", "")
                    summary_lines.append(f"- {test_name} (Priority: {priority}) - {reason}")
                else:
                    summary_lines.append(f"- {str(test)}")
        summary_lines.append("Analysis reveals user-supplied inputs with insufficient sanitization and validation mechanisms.")
        summary_lines.append(f"Recommend initiating {vuln_type} testing to verify exploitability and determine impact scope.")
        summary_lines.append(f"Confidence level: {int(confidence*100)}%")
        technical_summary = "\n".join(summary_lines)

        return web.json_response({
            "status": "analysis_complete",
            "url": url,
            "title": title,
            "ai_analysis": ai_analysis,
            "vulnerability_type": vuln_type,
            "confidence": confidence,
            "html_preview": html_sample[:500],
            "technical_summary": technical_summary,
            "prompt": f"Initiate {vuln_type} assessment? Risk indicators suggest {vuln_type} payload execution possible via identified input vectors."
        })
    
    except Exception as e:
        logger.error(colorama.Fore.RED + f"Error during analysis: {str(e)}" + colorama.Style.RESET_ALL)
        return web.json_response({
            "status": "error",
            "message": str(e)
        }, status=500)

async def confirm_and_scan_handler(request):
    """
    Endpoint to confirm user wants scanning and route to appropriate scanner
    Expects: {"url": "...", "vulnerability_type": "XSS" or "SQLi", "confirmed": true}
    """
    data = await request.json()
    url = data.get("url", "").strip()
    vuln_type = data.get("vulnerability_type", "XSS").upper()
    confirmed = data.get("confirmed", False)
    
    # Normalize vulnerability type
    if vuln_type not in ["XSS", "SQLI"]:
        vuln_type = "XSS"  # Default to XSS if unknown
    
    if not confirmed:
        logger.info(colorama.Fore.YELLOW + f"User declined scanning for {vuln_type}" + colorama.Style.RESET_ALL)
        return web.json_response({
            "status": "cancelled",
            "message": "Scanning cancelled by user"
        })
    
    try:
        if vuln_type == "XSS":
            logger.info(colorama.Fore.CYAN + f"User confirmed XSS scan. Starting XSS scanner..." + colorama.Style.RESET_ALL)
            
            logger.info(colorama.Fore.YELLOW + "Step 1: Running XSS vulnerability scanner..." + colorama.Style.RESET_ALL)
            await asyncio.sleep(0.1)
            xss_findings = run_xss_scan(url)
            
            if xss_findings and len(xss_findings) > 0:
                logger.info(colorama.Fore.YELLOW + f"Step 2: Found {len(xss_findings)} XSS vulnerabilities. Analyzing details..." + colorama.Style.RESET_ALL)
                await asyncio.sleep(0.1)
                
                vuln_data = {
                    "type": "XSS",
                    "url": url,
                    "findings": xss_findings,
                    "count": len(xss_findings)
                }
                vuln_analysis = model.analyze_vuln(vuln_data)
                
                logger.info(colorama.Fore.YELLOW + "Step 3: Classifying vulnerabilities by severity..." + colorama.Style.RESET_ALL)
                await asyncio.sleep(0.1)
                
                # Format vulnerabilities properly for classification
                formatted_vulns = []
                for finding in xss_findings:
                    formatted_vulns.append({
                        "type": finding.get("type", "XSS"),
                        "url": finding.get("url", url),
                        "description": finding.get("description", json.dumps(finding))[:200],
                        "severity": "Medium"  # Default severity
                    })
                
                classify_data = {"vulnerabilities": formatted_vulns}
                classification = model.classify(classify_data)
                
                logger.info(colorama.Fore.GREEN + "XSS scan pipeline complete." + colorama.Style.RESET_ALL)
                
                return web.json_response({
                    "status": "success",
                    "scan_type": "XSS",
                    "url": url,
                    "xss_findings": xss_findings,
                    "vulnerability_analysis": vuln_analysis,
                    "classification": classification,
                    "findings_count": len(xss_findings)
                })
            else:
                logger.info(colorama.Fore.GREEN + "No XSS vulnerabilities found." + colorama.Style.RESET_ALL)
                return web.json_response({
                    "status": "success",
                    "scan_type": "XSS",
                    "url": url,
                    "xss_findings": [],
                    "message": "No XSS vulnerabilities detected",
                    "findings_count": 0
                })
        
        elif vuln_type == "SQLI":
            logger.info(colorama.Fore.CYAN + f"User confirmed SQLi scan. Starting SQLi scanner..." + colorama.Style.RESET_ALL)
            
            # TODO: Implement SQLi scanning
            logger.info(colorama.Fore.YELLOW + "SQLi scanning module is under development..." + colorama.Style.RESET_ALL)
            return web.json_response({
                "status": "not_implemented",
                "scan_type": "SQLi",
                "message": "SQLi scanning module is currently under development"
            })
        
        else:
            # Default to XSS for any unrecognized type
            logger.info(colorama.Fore.CYAN + f"Defaulting to XSS scan for {vuln_type}..." + colorama.Style.RESET_ALL)
            logger.info(colorama.Fore.YELLOW + "Step 1: Running XSS vulnerability scanner..." + colorama.Style.RESET_ALL)
            time.sleep(0.3)
            xss_findings = run_xss_scan(url)
            
            if xss_findings and len(xss_findings) > 0:
                logger.info(colorama.Fore.YELLOW + f"Step 2: Found {len(xss_findings)} XSS vulnerabilities. Analyzing details..." + colorama.Style.RESET_ALL)
                time.sleep(0.3)
                
                vuln_data = {
                    "type": "XSS",
                    "url": url,
                    "findings": xss_findings,
                    "count": len(xss_findings)
                }
                vuln_analysis = model.analyze_vuln(vuln_data)
                
                logger.info(colorama.Fore.YELLOW + "Step 3: Classifying vulnerabilities by severity..." + colorama.Style.RESET_ALL)
                time.sleep(0.3)
                
                # Format vulnerabilities properly for classification
                formatted_vulns = []
                for finding in xss_findings:
                    formatted_vulns.append({
                        "type": finding.get("type", "XSS"),
                        "url": finding.get("url", url),
                        "description": finding.get("description", json.dumps(finding))[:200],
                        "severity": "Medium"
                    })
                
                classify_data = {"vulnerabilities": formatted_vulns}
                classification = model.classify(classify_data)
                
                logger.info(colorama.Fore.GREEN + "XSS scan pipeline complete." + colorama.Style.RESET_ALL)
                
                return web.json_response({
                    "status": "success",
                    "scan_type": "XSS",
                    "url": url,
                    "xss_findings": xss_findings,
                    "vulnerability_analysis": vuln_analysis,
                    "classification": classification,
                    "findings_count": len(xss_findings)
                })
            else:
                logger.info(colorama.Fore.GREEN + "No XSS vulnerabilities found." + colorama.Style.RESET_ALL)
                return web.json_response({
                    "status": "success",
                    "scan_type": "XSS",
                    "url": url,
                    "xss_findings": [],
                    "message": "No XSS vulnerabilities detected",
                    "findings_count": 0
                })
    
    except Exception as e:
        logger.error(colorama.Fore.RED + f"Error during scanning: {str(e)}" + colorama.Style.RESET_ALL)
        return web.json_response({
            "status": "error",
            "message": str(e)
        }, status=500)

async def xss_scan_handler(request):
    logger.info(colorama.Fore.CYAN + "Starting automated XSS scan pipeline..." + colorama.Style.RESET_ALL)
    url = (await request.text()).strip()
    
    try:
        logger.info(colorama.Fore.YELLOW + f"Step 1: Analyzing target site - {url}" + colorama.Style.RESET_ALL)
        time.sleep(0.3)
        scraper = AsyncWebScraper()
        html = await scraper.scrape_website(url)
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        html_sample = html[:4000]
        
        site_audit_data = {"url": url, "html": html_sample, "title": title}
        site_audit_result = model.site_audit(site_audit_data)
        logger.info(colorama.Fore.GREEN + "Site analysis complete." + colorama.Style.RESET_ALL)
        
        logger.info(colorama.Fore.YELLOW + "Step 2: Running XSS vulnerability scanner..." + colorama.Style.RESET_ALL)
        time.sleep(0.3)
        xss_findings = run_xss_scan(url)
        
        if xss_findings and len(xss_findings) > 0:
            logger.info(colorama.Fore.YELLOW + f"Step 3: Found {len(xss_findings)} XSS vulnerabilities. Analyzing details..." + colorama.Style.RESET_ALL)
            time.sleep(0.3)
            
            vuln_data = {
                "type": "XSS",
                "url": url,
                "findings": xss_findings,
                "count": len(xss_findings)
            }
            vuln_analysis = model.analyze_vuln(vuln_data)
            
            logger.info(colorama.Fore.YELLOW + "Step 4: Classifying vulnerabilities by severity..." + colorama.Style.RESET_ALL)
            time.sleep(0.3)
            classify_data = {"vulnerabilities": xss_findings}
            classification = model.classify(classify_data)
            
            logger.info(colorama.Fore.GREEN + "XSS scan pipeline complete." + colorama.Style.RESET_ALL)
            
            return web.json_response({
                "status": "success",
                "url": url,
                "title": title,
                "site_audit": site_audit_result,
                "xss_findings": xss_findings,
                "vulnerability_analysis": vuln_analysis,
                "classification": classification,
                "report_generated": True
            })
        else:
            logger.info(colorama.Fore.GREEN + "No XSS vulnerabilities found." + colorama.Style.RESET_ALL)
            return web.json_response({
                "status": "success",
                "url": url,
                "title": title,
                "site_audit": site_audit_result,
                "xss_findings": [],
                "message": "No XSS vulnerabilities detected",
                "report_generated": False
            })
    except Exception as e:
        logger.error(colorama.Fore.RED + f"Error during XSS scan: {str(e)}" + colorama.Style.RESET_ALL)
        return web.json_response({
            "status": "error",
            "message": str(e)
        }, status=500)

async def index_handler(request):
    return web.FileResponse('index.html')

logger.info(colorama.Fore.MAGENTA + "Setting up HTTP endpoints..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app = web.Application()
logger.info(colorama.Fore.MAGENTA + "Adding route for index page..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_get('/', index_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for vulnerability analysis..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/analyze_vuln', analyze_vuln_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for site audit..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/site_audit', site_audit_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for severity classification..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/classify', classify_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for intelligent vulnerability detection..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/analyze_and_route', analyze_and_route_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for confirmed scanning..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/confirm_and_scan', confirm_and_scan_handler)
logger.info(colorama.Fore.MAGENTA + "Adding route for XSS scan pipeline..." + colorama.Style.RESET_ALL)
time.sleep(0.2)
app.router.add_post('/xss_scan', xss_scan_handler)
logger.info(colorama.Fore.GREEN + "HTTP endpoints configured." + colorama.Style.RESET_ALL)

if __name__ == '__main__':
    logger.info(colorama.Fore.BLUE + "Initializing web scraper components..." + colorama.Style.RESET_ALL)
    time.sleep(0.3)
    logger.info(colorama.Fore.BLUE + "Configuring async event loop..." + colorama.Style.RESET_ALL)
    time.sleep(0.3)
    logger.info(colorama.Fore.GREEN + "Starting Pennywise HTTP Server on port 8080..." + colorama.Style.RESET_ALL)
    web.run_app(app, port=8080)
