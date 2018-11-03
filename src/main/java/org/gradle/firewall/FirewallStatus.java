package org.gradle.firewall;
/**
 * 
 * 防火牆解析狀態
 * @author Clare
 * @date 2018年6月1日 下午1:31:02
 */
public class FirewallStatus {
	//拒絕跨域訪問
	public static final int CrossDomainAccessDenied = -3;
	//拒絕訪問受保護
	public static final int AccessDefendDenied = -2;
	//拒絕訪問
	public static final int AccessDenied = -1;
	//待驗證訪問
	public static final int Access = 0;
	//忽略檔名訪問
	public static final int IgnoreFileAccess = 1;
	//忽略路徑訪問
	public static final int IgnorePathAccess = 2;
	//待驗證跨域訪問
	public static final int CrossDomainAccess = 100;
	//忽略跨域檔名訪問
	public static final int IgnoreCrossDomainFileAccess = 101;
	//忽略跨域路徑訪問
	public static final int IgnoreCrossDomainPathAccess = 102;
}
