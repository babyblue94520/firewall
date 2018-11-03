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
	private final Pattern allowIpPattern;
	
	/** The deny ip pattern. */
	private final Pattern denyIpPattern;
	
	/** The defend paths. */
	private final Pattern defendPaths;
	
	/** The access defend ips. */
	private final Pattern accessDefendIps;
	
	/** The ignore path pattern. */
	private final Pattern ignorePathPattern;
	
	/** The ignore file type pattern. */
	private final Pattern ignoreFileTypePattern;
	
	/** The cross domain ip pattern. */
	private final Pattern crossDomainIpPattern;
	
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
		
		if(!isAllowAccessDefend(path,ip)){
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
	 * @param requestURL the request URL
	 * @param ip the ip
	 * @return true, if is allow access defend
	 */
	private boolean isAllowAccessDefend(String requestURL,String ip){
		if(doRegexFind(defendPaths,requestURL)){
			if(!doRegexFind(accessDefendIps,ip)){
				return false;
			}
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
		if(allowIpPattern==null)return true;
		return doRegexFind(allowIpPattern,ip);
	}
	
	/**
	 * Checks if is deny ip.
	 *
	 * @param ip the ip
	 * @return true, if is deny ip
	 */
	private boolean isDenyIp(String ip){
		return doRegexFind(denyIpPattern,ip);
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
		if(crossDomainIpPattern==null)return true;
		return doRegexFind(crossDomainIpPattern,ip);
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