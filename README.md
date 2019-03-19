# SpringCloudFirewall
## 依賴Spring Cloud Config下，開發的防火牆
### 前言

    某某專案設計了使用Quartz的排程系統，定期做資料清洗，由於Spring Security使用上不是很方便(OS:我覺得很不實用)，所以自行設計了一套權限管理跟Filter，後來想說也可以利用排程定期向metrics端口取得資料，來做系統狀態分析，因為有權限管理，所以又要在Filter增加一個忽略條件更新系統，於是直接設計一套可利用Cloud Refresh事件，讀取外部文件並動態更新防火牆規則的服務！

### 作用

    補充不使用Spring Security的安全性以及彈性動態的更新過濾規則。

### 使用方式：
	
	@Autowired
	private FirewallService firewallService;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		boolean pass = verificationRequest(req, res);
		if(pass){
			chain.doFilter(req, res);
		}
	}
	
	public boolean verificationRequest(ServletRequest req, ServletResponse res){
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		String remoteIp = request.getRemoteAddr();
		String clientIp = WebUtil.getClientIp(request);
		String origin = request.getHeader(HttpHeaders.ORIGIN);
		String path = request.getRequestURI();
		String url = request.getRequestURL().toString();
		int status = firewallService.parse(url,path,origin,remoteIp,clientIp);
		switch(status){
			//拒絕跨域訪問
			case FirewallStatus.CROSSDOMAINACCESSDENIED :
				denied = true;
				break;
			//拒絕訪問受保護
			case FirewallStatus.ACCESSDEFENDDENIED :
				denied = true;
				break;
			//拒絕訪問
			case FirewallStatus.ACCESSDENIED :
				denied = true;
				break;
			//忽略檔名訪問
			case FirewallStatus.IGNOREFILEACCESS :
				pass = true;
				break;
			//忽略路徑訪問
			case FirewallStatus.IGNOREPATHACCESS :
				//訪問紀錄
				pass = true;
				break;
			//忽略跨域檔名訪問
			case FirewallStatus.IGNORECROSSDOMAINFILEACCESS :
				pass = true;
				crossDomain = true;
				break;
			//忽略跨域路徑訪問
			case FirewallStatus.IGNORECROSSDOMAINPATHACCESS :
				//訪問紀錄
				pass = true;
				crossDomain = true;
				break;
			//待驗證訪問
			case FirewallStatus.ACCESS :
				break;
			//待驗證跨域訪問
			case FirewallStatus.CROSSDOMAINACCESS :
				crossDomain = true;
				break;
				
		}
		//拒絕
		if(denied)return false;
		//跨域
		if(crossDomain){
			response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, request.getHeader(HttpHeaders.ORIGIN));
			response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,"true");
			response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,"GET,HEAD,POST");
		}
		//通過
		if(pass)return true;
		
		return false;
	}
    
    
### 動態更新防火牆規則
	
     透過設定讀取外部的 __application-firewall.yml__，異動 __application-firewall.yml__ 內容時，只需透過 __Cloud Config Refresh__ 功能，即可更新規則。
	
	http://127.0.0.1/refresh

	

### application-firewall.yml內容說明

可直接使用正規表示式
  
	name:
		- 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
		- 10\.\d{1,3}\.\d{1,3}\.\d{1,3}

1. __ignoreLogPaths__：
	
	不記錄路徑，提供設定不想被記錄的路徑。(可為空
  
2. __denyRemoteIps__：

 	拒絕訪問__遠端連線IP__ 。(可為空
   		
3. __denyClientIps__：

	拒絕訪問__客戶端IP__。(可為空

4. __allowRemoteIps__：

	允許訪問__遠端連線IP__ 。(可為空，則直接全部允許
 
5. __allowClientIps__：

	允許訪問__客戶端IP__。(可為空，則直接全部允許

6. __defendPaths__：

	限制特定路徑只有設定的IP才能訪問，譬如超級管理者才能操作的動作。
  	
		defendPaths:
			- /env/.+

7. __accessDefendRemoteIps__：

	設定可以訪問特定路徑的 __遠端連線IP__。
 
8. __accessDefendClientIps__：

	設定可以訪問特定路徑的 __客戶端IP__。

9. __ignorePaths__：

 	忽略請求路徑，不需要經過自行設計的規則，直接通過。
 	
		ignorePaths:
			- /js/
			- /css/
			- /images/

10. __ignoreFileTypes__：

	忽略請求檔案類型，不需要經過自行設計的規則，直接通過。
 	
		ignoreFileTypes:
			- js
			- css
			- html

11. __accessDefendRemoteIps__：
	
	允許跨域訪問__遠端連線IP__ 。(會先經過allowIps和denyIps的規則
    	
12. __accessDefendClientIps__：
	
	允許跨域訪問__客戶端IP__。(會先經過allowIps和denyIps的規則

13. __ignoreCrossPaths__：

	忽略跨域請求路徑，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	
		ignoreCrossPaths:
			- /js/
			- /css/
			- /images/

14. __ignoreCrossFileTypes__：

	忽略跨域請求檔案類型，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	
		ignoreCrossFileTypes:
			- js
			- css
			- html

 
 
#### 其他：
	
* __遠端連線IP__：
	
	該連線的服務器IP，可能是 Proxy Server 的IP，不一定是發起請求的客戶端IP

		request.getRemoteAddr()

* __客戶端IP__：

	可能是發起請求的客戶端IP，或者從 Request Header 解析出來的 IP

		String clientIp = request.getHeader("x-forwarded-for");
		if (clientIp == null || clientIp.length() == 0 || "unknown".equalsIgnoreCase(clientIp)) {
			clientIp = request.getHeader("Proxy-Client-IP");
		}
		if (clientIp == null || clientIp.length() == 0 || "unknown".equalsIgnoreCase(clientIp)) {
			clientIp = request.getHeader("WL-Proxy-Client-IP");
		}
		if (clientIp == null || clientIp.length() == 0 || "unknown".equalsIgnoreCase(clientIp)) {
			clientIp = request.getRemoteAddr();
		}
		return clientIp;