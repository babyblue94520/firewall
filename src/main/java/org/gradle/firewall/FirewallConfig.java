package org.gradle.firewall;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

/**
 * 
 * 防火牆配置
 * @author Clare 2018年6月1日 下午1:29:54
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix="firewall")
class FirewallConfig{
	private String[] ignoreLogPaths;
	private String[] allowRemoteIps;
	private String[] allowClientIps;
	private String[] denyRemoteIps;
	private String[] denyClientIps;
	private String[] accessDefendRemoteIps;
	private String[] accessDefendClientIps;
	private String[] defendPaths;
	private String[] ignorePaths;
	private String[] ignoreFileTypes;
	private String[] crossDomainRemoteIps;
	private String[] crossDomainClientIps;
	private String[] ignoreCrossDomainPaths;
	private String[] ignoreCrossDomainFileTypes;
}