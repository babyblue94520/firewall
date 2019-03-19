package org.gradle.firewall;

import java.util.regex.Pattern;

import javax.servlet.ServletContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 產生防火牆規則服務.
 *
 * @author Clare 2018年6月1日 下午1:28:50
 */
@Configuration
public class FirewallServiceFactory {
	
	/**
	 * Inits the fire wall service.
	 *
	 * @param config the config
	 * @param context the context
	 * @return the firewall service
	 */
	@Bean
	@Autowired
	@RefreshScope
	public FirewallService initFireWallService(
		FirewallConfig config
		,ServletContext context
	){
		//產生完整的Host Path 
		String contextPath = context.getContextPath();
		return FirewallService.builder()
				.ignoreLogPathPattern(path2Pattern(config.getIgnoreLogPaths(), contextPath))
				.allowRemoteIpPattern(ip2Pattern(config.getAllowRemoteIps()))
				.allowClientIpPattern(ip2Pattern(config.getAllowClientIps()))
				.denyRemoteIpPattern(ip2Pattern(config.getDenyRemoteIps()))
				.denyClientIpPattern(ip2Pattern(config.getDenyClientIps()))
				.accessDefendRemoteIpPattern(ip2Pattern(config.getAccessDefendRemoteIps()))
				.accessDefendClientIpPattern(ip2Pattern(config.getAccessDefendClientIps()))
				.defendPaths(path2Pattern(config.getDefendPaths(), contextPath))
				.ignorePathPattern(path2Pattern(config.getIgnorePaths(), contextPath))
				.ignoreFileTypePattern(fileType2Pattern(config.getIgnoreFileTypes()))
				.crossDomainRemoteIpPattern(ip2Pattern(config.getCrossDomainRemoteIps()))
				.crossDomainClientIpPattern(ip2Pattern(config.getCrossDomainClientIps()))
				.ignoreCrossDomainPathPattern(path2Pattern(config.getIgnoreCrossDomainPaths(), contextPath))
				.ignoreCrossDomainFileTypePattern(fileType2Pattern(config.getIgnoreCrossDomainFileTypes()))
				.build();
	}
	
	/**
	 * ip2Pattern 
	 * 依IP array產生正規表示式.
	 *
	 * @param array the array
	 * @return the pattern
	 */
	private Pattern ip2Pattern(String[] array){
		if(array==null||array.length==0)return null;
		return Pattern.compile("^("+String.join("|",array)+")$");
	}
	
	/**
	 * path2Pattern 
	 * 依path array產生正規表示式.
	 *
	 * @param array the array
	 * @return the pattern
	 */
	private Pattern path2Pattern(String[] array,String contextPath){
		if(array==null||array.length==0)return null;
		return Pattern.compile("^"+contextPath+"("+String.join("|",array)+")");
	}
	
	/**
	 * fileType2Pattern 
	 * 依 file type array產生正規表示式.
	 *
	 * @param array the array
	 * @return the pattern
	 */
	private Pattern fileType2Pattern(String[] array){
		if(array==null)return null;
		if(array.length==0)return null;
		return Pattern.compile("\\.("+String.join("|",array)+")$");
	}
}
