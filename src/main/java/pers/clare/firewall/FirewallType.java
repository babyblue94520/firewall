package pers.clare.firewall;
/**
 * Parse result type
 */
public class FirewallType {
	public static final int ACCESS_DEFEND_DENIED = -3;
	public static final int CROSS_ACCESS_DENIED = -2;
	public static final int ACCESS_DENIED = -1;
	public static final int ACCESS = 0;
	public static final int CROSS_ACCESS = 1;
	public static final int IGNORE_PATH_ACCESS = 2;
	public static final int IGNORE_PATH_CROSS_ACCESS = 3;
}
