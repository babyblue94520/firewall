package org.gradle.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.gradle.bean.VerifyRequestResult;
import org.gradle.firewall.FirewallService;
import org.gradle.firewall.FirewallStatus;
import org.gradle.util.WebUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;


/**
 * 訪問權限過濾
 * @author Clare 2017年4月12日 
 */
@WebFilter(urlPatterns="/*")
@Order(1)
public class AccessFilter implements Filter{
	private final Logger log = Logger.getLogger(AccessFilter.class);

	@Autowired
	private FirewallService firewallService;
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		log.info("AccessFilter init....");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		VerifyRequestResult verifyResult = new VerifyRequestResult(log.isTraceEnabled());
		
		if (verifyRequest(request, response, verifyResult)) {
			chain.doFilter(request, response);
			verifyResult.log("通過");
		} else {
			verifyResult.setSave(true);
			verifyResult.log("不通過");
			if (response.getStatus() == HttpStatus.OK.value()) {
				response.setStatus(HttpStatus.FORBIDDEN.value());
			}
		}
	}

	@Override
	public void destroy() {
		log.info("AccessFilter destroy....");
	}

	/**
	 * 驗證請求
	 * 
	 * @param req
	 * @param res
	 * @return
	 */
	public boolean verifyRequest(
		HttpServletRequest request
		, HttpServletResponse response
		, VerifyRequestResult verifyResult
	) {
		String remoteIp = request.getRemoteAddr();
		String clientIp = WebUtil.getClientIp(request);
		String origin = request.getHeader(HttpHeaders.ORIGIN);
		String path = request.getRequestURI();
		String url = request.getRequestURL().toString();
		int status = firewallService.parse(url,path,origin,remoteIp,clientIp);
		switch (status) {
		// 拒絕跨域訪問
		case FirewallStatus.CrossDomainAccessDenied:
			verifyResult.log("拒絕跨域訪問");
			return false;
		// 拒絕訪問受保護
		case FirewallStatus.AccessDefendDenied:
			verifyResult.log("拒絕訪問受保護");
			return false;
		// 拒絕訪問
		case FirewallStatus.AccessDenied:
			verifyResult.log("拒絕訪問");
			return false;
		// 忽略檔名訪問
		case FirewallStatus.IgnoreFileAccess:
			verifyResult.log("忽略檔名訪問");
			return true;
		// 忽略路徑訪問
		case FirewallStatus.IgnorePathAccess:
			verifyResult.log("忽略路徑訪問");
			//是否儲存紀錄
			verifyResult.setSave(!firewallService.isIgnoreLogPath(path));
			return true;
		// 忽略跨域檔名訪問
		case FirewallStatus.IgnoreCrossDomainFileAccess:
			verifyResult.log("忽略跨域檔名訪問");
			setCrossDomainHeader(request, response);
			return true;
		// 忽略跨域路徑訪問
		case FirewallStatus.IgnoreCrossDomainPathAccess:
			verifyResult.log("忽略跨域路徑訪問");
			setCrossDomainHeader(request, response);
			//是否儲存紀錄
			verifyResult.setSave(!firewallService.isIgnoreLogPath(path));
			return true;
		// 待驗證跨域訪問
		case FirewallStatus.CrossDomainAccess:
			verifyResult.log("跨域訪問");
			setCrossDomainHeader(request, response);
			break;
		}
		//是否儲存紀錄
		verifyResult.setSave(!firewallService.isIgnoreLogPath(path));
		//驗證使用者
		return true;
	}

	/**
	 * 設定允許跨域Header.
	 *
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 */
	private void setCrossDomainHeader(HttpServletRequest request, HttpServletResponse response) {
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, request.getHeader(HttpHeaders.ORIGIN));
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
				"Origin, X-Requested-With, Content-Type, Accept, Connection, User-Agent, Cookie");
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
		response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, "GET,HEAD,POST");
	}
}
