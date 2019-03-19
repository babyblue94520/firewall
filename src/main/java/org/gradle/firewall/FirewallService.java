package org.gradle.firewall;

import java.util.regex.Pattern;

import lombok.Builder;
import lombok.ToString;

/**
 * 防火牆.
 *
 * @author Clare 2018年6月1日 下午1:27:57
 */

@Builder
@ToString
public class FirewallService {
	
	/** The allow ip pattern. */
	private final Pattern allowRemoteIpPattern;
	private final Pattern allowClientIpPattern;
	
	/** The deny ip pattern. */
	private final Pattern denyRemoteIpPattern;
	private final Pattern denyClientIpPattern;
	
	/** The defend paths. */
	private final Pattern defendPaths;
	
	/** The access defend ips. */
	private final Pattern accessDefendRemoteIpPattern;
	private final Pattern accessDefendClientIpPattern;
	
	/** The ignore path pattern. */
	private final Pattern ignorePathPattern;
	
	/** The ignore file type pattern. */
	private final Pattern ignoreFileTypePattern;
	
	/** The cross domain ip pattern. */
	private final Pattern crossDomainRemoteIpPattern;
	private final Pattern crossDomainClientIpPattern;
	
	/** The ignore cross domain path pattern. */
	private final Pattern ignoreCrossDomainPathPattern;
	
	/** The ignore cross domain file type pattern. */
	private final Pattern ignoreCrossDomainFileTypePattern;
	/** The allow ip pattern. */
	private final Pattern ignoreLogPathPattern;
	
	/**
	 * parse 
	 * 解析請求.
	 *
	 * @param request the request
	 * @return the int
	 */
	public int parse(
		String url,
		String path ,
		String origin,
		String remoteIp,
		String clientIp
	){
		// 連線IP 跟 客戶端IP是否相同
		boolean ipSame = false;
		if(remoteIp==clientIp) {
			ipSame = true;
		}else if(remoteIp!=null&&remoteIp.equals(clientIp)) {
			ipSame = true;
		}
		if(ipSame) {
			return parse(url,path,origin,remoteIp);
		}else {
			return parseDiff(url,path,origin,remoteIp,clientIp);
		}
	}

	/**
	   *    連線IP和客戶端IP相同
	 * @param url
	 * @param path
	 * @param origin
	 * @param ip
	 * @return
	 */
	private int parse(
		String url,
		String path ,
		String origin,
		String ip
	){
		//檢查是否為拒絕IP
		if(isDenyIp(ip)){
			return FirewallStatus.AccessDenied;
		}
		//檢查是否為允許IP
		if(!isAllowIp(ip)){
			return FirewallStatus.AccessDenied;
		}
		
		if(!isAllowAccessDefendIp(path,ip)){
			return FirewallStatus.AccessDefendDenied;
		}
		
		//跨域請求
		if(isCrossRequest(origin,url)){
			if(!isAllowCrossIp(ip)){
				return FirewallStatus.CrossDomainAccess;
			}
			if(isIgnoreCrossDomainFileType(path)){
				return FirewallStatus.IgnoreCrossDomainFileAccess;
			}
			if(isIgnorecrossDomainPath(path)){
				return FirewallStatus.IgnoreCrossDomainPathAccess;
			}
			return FirewallStatus.CrossDomainAccess;
		//非跨域請求
		}else{
			//是否為忽略的請求
			if(isIgnoreFileType(path)){
				return FirewallStatus.IgnoreFileAccess;
			}
			if(isIgnorePath(path)){
				return FirewallStatus.IgnorePathAccess;
			}
			return FirewallStatus.Access;
		}
	}
	

	/**
	 * parse 
	   *    連線IP和客戶端IP 不相同
	 *
	 * @param request the request
	 * @return the int
	 */
	private int parseDiff(
		String url,
		String path ,
		String origin,
		String remoteIp,
		String clientIp
	){
		//檢查是否為拒絕IP
		if(isDenyIp(remoteIp,clientIp)){
			return FirewallStatus.AccessDenied;
		}
		//檢查是否為允許IP
		if(!(isAllowIp(remoteIp,clientIp))){
			return FirewallStatus.AccessDenied;
		}
		// 檢查是否可訪問保護的路徑
		if(!isAllowAccessDefendIp(path,remoteIp,clientIp)){
			return FirewallStatus.AccessDefendDenied;
		}
		
		//跨域請求
		if(isCrossRequest(origin,url)){
			if(!isAllowCrossIp(remoteIp,clientIp)){
				return FirewallStatus.CrossDomainAccess;
			}
			if(isIgnoreCrossDomainFileType(path)){
				return FirewallStatus.IgnoreCrossDomainFileAccess;
			}
			if(isIgnorecrossDomainPath(path)){
				return FirewallStatus.IgnoreCrossDomainPathAccess;
			}
			return FirewallStatus.CrossDomainAccess;
		//非跨域請求
		}else{
			//是否為忽略的請求
			if(isIgnoreFileType(path)){
				return FirewallStatus.IgnoreFileAccess;
			}
			if(isIgnorePath(path)){
				return FirewallStatus.IgnorePathAccess;
			}
			return FirewallStatus.Access;
		}
	}
	
	/**
	 * 是否忽略紀錄
	 *
	 * @param url the url
	 * @return true, if is ignore path
	 */
	public boolean isIgnoreLogPath(String path){
		return doRegexFind(ignoreLogPathPattern,path);
	}
	
	/**
	 * isAllowAccessDefend 
	 * IP是否可訪問受保護的路徑.
	 *
	 * @param path the request URL
	 * @param ip the ip
	 * @return true, if is allow access defend
	 */
	private boolean isAllowAccessDefendIp(String path,String ip){
		if(doRegexFind(defendPaths,path)){
			return doRegexFind(accessDefendRemoteIpPattern,ip);
		}
		return true;
	}

	/**
	 * isAllowAccessDefend 
	 * IP是否可訪問受保護的路徑.
	 *
	 * @param path the request URL
	 * @param ip the ip
	 * @return true, if is allow access defend
	 */
	private boolean isAllowAccessDefendIp(String path,String remoteIp,String clientIp){
		if(doRegexFind(defendPaths,path)){
			if(doRegexFind(accessDefendRemoteIpPattern,remoteIp)){
				return doRegexFind(accessDefendClientIpPattern,clientIp);
			}
			return false;
		}
		return true;
	}
	
	/**
	 * isCrossRequest 
	 * 檢查是否跨域請求.
	 *
	 * @param origin the origin
	 * @param url the url
	 * @return true, if is cross request
	 */
	private boolean isCrossRequest(String origin,String url){
		if(origin==null||url==null)return false;
		return url.indexOf(origin)==-1;
	}
	
	/**
	 * Checks if is allow ip.
	 *
	 * @param ip the ip
	 * @return true, if is allow ip
	 */
	private boolean isAllowIp(String ip){
		//沒設定為全通過
		if(allowRemoteIpPattern==null)return true;
		return doRegexFind(allowRemoteIpPattern,ip);
	}
	
	/**
	 * Checks if is allow ip.
	 *
	 * @param ip the ip
	 * @return true, if is allow ip
	 */
	private boolean isAllowIp(String remoteIp,String clientIp){
		//沒設定為全通過
		if(allowRemoteIpPattern==null)return true;
		if(doRegexFind(allowRemoteIpPattern,remoteIp)) {
			if(allowClientIpPattern==null)return true;
			return doRegexFind(allowClientIpPattern,clientIp);
		}else {
			return false;
		}
	}
	
	/**
	 * Checks if is deny ip.
	 *
	 * @param ip the ip
	 * @return true, if is deny ip
	 */
	private boolean isDenyIp(String ip){
		return doRegexFind(denyRemoteIpPattern,ip);
	}

	/**
	 * Checks if is deny ip.
	 *
	 * @param ip the ip
	 * @return true, if is deny ip
	 */
	private boolean isDenyIp(String remoteIp,String clientIp){
		if(doRegexFind(denyRemoteIpPattern,remoteIp)) {
			return true;
		}else {
			return doRegexFind(denyClientIpPattern,clientIp);
		}
	}

	/**
	 * Checks if is ignore path.
	 *
	 * @param url the url
	 * @return true, if is ignore path
	 */
	private boolean isIgnorePath(String path){
		return doRegexFind(ignorePathPattern,path);
	}
	
	/**
	 * Checks if is ignore file type.
	 *
	 * @param url the url
	 * @return true, if is ignore file type
	 */
	private boolean isIgnoreFileType(String path){
		return doRegexFind(ignoreFileTypePattern,path);
	}

	/**
	 * Checks if is allow cross ip.
	 *
	 * @param ip the ip
	 * @return true, if is allow cross ip
	 */
	private boolean isAllowCrossIp(String ip){
		return doRegexFind(crossDomainRemoteIpPattern,ip);
	}

	/**
	 * Checks if is allow cross ip.
	 *
	 * @param ip the ip
	 * @return true, if is allow cross ip
	 */
	private boolean isAllowCrossIp(String remoteIp,String clientIp){
		if(doRegexFind(crossDomainRemoteIpPattern,remoteIp)) {
			return doRegexFind(crossDomainClientIpPattern,clientIp);
		}else {
			return false;
		}
	}

	/**
	 * Checks if is ignorecross domain path.
	 *
	 * @param url the url
	 * @return true, if is ignorecross domain path
	 */
	private boolean isIgnorecrossDomainPath(String path){
		return doRegexFind(ignoreCrossDomainPathPattern,path);
	}
	
	/**
	 * Checks if is ignore cross domain file type.
	 *
	 * @param url the url
	 * @return true, if is ignore cross domain file type
	 */
	private boolean isIgnoreCrossDomainFileType(String path){
		return doRegexFind(ignoreCrossDomainFileTypePattern,path);
	}

	/**
	 * Do regex find.
	 *
	 * @param p the p
	 * @param data the data
	 * @return true, if successful
	 */
	private boolean doRegexFind(Pattern p,String data){
		if(p==null)return false;
		return p.matcher(data).find();
	}
}