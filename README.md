# SpringCloudFirewall
## 依賴Spring cloud config下，開發的防火牆
#### 前言

    某某專案設計了使用Quartz的排程系統，定期做資料清洗，由於Spring Security使用上不是很方便(OS:我覺得很不實用)，所以自行設計了一套權限管理跟Filter，後來想說也可以利用排程定期向metrics端口取得資料，來做系統狀態分析，因為有權限管理，所以又要在Filter增加一個忽略條件更新系統，於是直接設計一套可利用Cloud Refresh事件，讀取外部文件並動態更新防火牆規則的服務！

#### 作用

    補充不使用Spring Security的安全性以及彈性動態的更新過濾規則。

#### 使用方式：
	
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
		
		int status = firewallService.parse(request);
		boolean denied = false;
		boolean pass = false;
		boolean crossDomain = false;
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
    
    
1. #### 動態更新防火牆規則：
	
     透過設定讀取外部的application-firewall.yml，異動application-firewall.yml內容時，只需透過Cloud Config Refresh功能，即可更新規則。
	
	http://127.0.0.1/refresh

	

#### application-firewall.yml內容說明：

     裡面的值可直接使用正規表示式

1. #### allowIps：

  	允許訪問IP。(可為空，則直接全部允許
 	ex:
 	
 	allowIps: 
    	- 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
    	- 10\.\d{1,3}\.\d{1,3}\.\d{1,3}

2. #### denyIps：

  	拒絕訪問IP。(可為空
 	ex:
 	
 	denyIps: 
    	- 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
   		- 10\.\d{1,3}\.\d{1,3}\.\d{1,3}

3. #### ignorePaths：

  	忽略請求路徑，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	ex:
 	
  	ignorePaths:
  		- /js/
  		- /css/
  		- /images/

4. #### ignoreFileTypes：

  	忽略請求檔案類型，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	ex:
 	
  	ignoreFileTypes:
  		- js
  		- css
  		- html

5. #### crossIps：
	
  	允許跨域訪問IP。(會先經過allowIps和denyIps的規則
 	ex:
 	
 	crossIps: 
    	- 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
    	- 192\.168\.\d{1,3}\.\d{1,3}

6. #### ignoreCrossPaths：

  	忽略跨域請求路徑，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	ex:
 	
  	ignorePaths:
  		- /js/
  		- /css/
  		- /images/

7. #### ignoreCrossFileTypes：

  	忽略跨域請求檔案類型，不需要經過自行設計的FirewallRuleFunction，直接通過。
 	ex:
 	
  	ignoreFileTypes:
  		- js
  		- css
  		- html

8. #### defendPaths：

  	限制特定路徑只有設定的IP才能訪問，譬如超級管理者才能操作的動作。
  	ex:
  	
  	defendPaths:
  		- /env/.+

9. #### accessDefendIps：

  	設定可以訪問特定路徑的IP。
  	ex:
  	
  	accessDefendIps:
  		- 127\.\d{1,3}\.\d{1,3}\.\d{1,3}
  		- 192\.168\.\d{1,3}\.\d{1,3}

#### 其他：
	
1. #### 
	
