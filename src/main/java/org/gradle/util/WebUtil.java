package org.gradle.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 取得當前Request工具.
 *
 * @author Clare 2018年6月1日 下午3:52:44
 */
public class WebUtil {

	/**
	 * request 
	 * 取得當前thread request.
	 *
	 * @return the http servlet request
	 */
	public static HttpServletRequest request(){
	    return ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
	}
	
	/**
	 * getOrigin 
	 * 取得來源網址.
	 *
	 * @return the origin
	 */
	public static String getOrigin(){
		return getOrigin(request());
	}

	/**
	 * getOrigin 
	 * 取得來源網址.
	 *
	 * @param request the request
	 * @return the origin
	 */
	public static String getOrigin(HttpServletRequest request){
		return request().getHeader(HttpHeaders.ORIGIN);
	}
	
	
	/**
	 * getDevice 
	 * 取得User-Agent.
	 *
	 * @return the device
	 */
	public static String getDevice(){
		return getDevice(request());
	}
	
	/**
	 * getDevice 
	 * 取得User-Agent.
	 *
	 * @param request the request
	 * @return the device
	 */
	public static String getDevice(HttpServletRequest request){
		String agent = request.getHeader("User-Agent");
		return agent;
	}
	
	/**
	 * sessionId 
	 * 取得session id.
	 *
	 * @param autoCreate the auto create
	 * @return the string
	 */
	public static String sessionId(boolean autoCreate) {
	    return sessionId(request(),autoCreate); // true == allow create
	}

	
	/**
	 * sessionId 
	 * 取得session id.
	 *
	 * @param request the request
	 * @param autoCreate the auto create
	 * @return the string
	 */
	public static String sessionId(HttpServletRequest request,boolean autoCreate) {
		HttpSession session = request.getSession(autoCreate);
		if(session==null){
			return null;
		}
	    return session.getId(); // true == allow create
	}
	
	/**
	 * session 
	 * 取得session.
	 *
	 * @param autoCreate the auto create
	 * @return the http session
	 */
	public static HttpSession session(boolean autoCreate) {
	    return session(request(),autoCreate); // true == allow create
	}
	
	/**
	 * session 
	 * 取得session.
	 *
	 * @param request the request
	 * @param autoCreate the auto create
	 * @return the http session
	 */
	public static HttpSession session(HttpServletRequest request,boolean autoCreate) {
	    return request.getSession(autoCreate); // true == allow create
	}
	
	
	/**
	 * getClientIp 
	 * 取得客戶IP.
	 *
	 * @return the client ip
	 */
    public static String getClientIp(){
		return getClientIp(request());
	}
    
	/**
	 * getClientIp 
	 * 取得客戶IP.
	 *
	 * @param request the request
	 * @return the client ip
	 */
    public static String getClientIp(HttpServletRequest request){
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
	}
}
