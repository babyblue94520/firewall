package pers.clare.firewall;


public class FirewallProperties {
    /** Defend path accessible only by defendAllowIp. */
    private String[] defendPath;
    /** IP that can access to defend path. */
    private String[] defendAllowIp;
    /** Remote ip that can access to defend path. */
    private String[] defendAllowRemoteIp;

    /** Allow client ip. */
    private String[] allowIp;
    /** Allow remote ip. */
    private String[] allowRemoteIp;

    /** Block client ip. */
    private String[] blockIp;
    /** Block remote ip. */
    private String[] blockRemoteIp;

    /** Ignore path access. */
    private String[] ignorePath;

    /** Allow domain cross access.  */
    private String[] allowCrossDomain;

    public String[] getDefendPath() {
        return defendPath;
    }

    public void setDefendPath(String[] defendPath) {
        this.defendPath = defendPath;
    }

    public String[] getDefendAllowIp() {
        return defendAllowIp;
    }

    public void setDefendAllowIp(String[] defendAllowIp) {
        this.defendAllowIp = defendAllowIp;
    }

    public String[] getDefendAllowRemoteIp() {
        return defendAllowRemoteIp;
    }

    public void setDefendAllowRemoteIp(String[] defendAllowRemoteIp) {
        this.defendAllowRemoteIp = defendAllowRemoteIp;
    }

    public String[] getAllowIp() {
        return allowIp;
    }

    public void setAllowIp(String[] allowIp) {
        this.allowIp = allowIp;
    }

    public String[] getAllowRemoteIp() {
        return allowRemoteIp;
    }

    public void setAllowRemoteIp(String[] allowRemoteIp) {
        this.allowRemoteIp = allowRemoteIp;
    }

    public String[] getBlockIp() {
        return blockIp;
    }

    public void setBlockIp(String[] blockIp) {
        this.blockIp = blockIp;
    }

    public String[] getBlockRemoteIp() {
        return blockRemoteIp;
    }

    public void setBlockRemoteIp(String[] blockRemoteIp) {
        this.blockRemoteIp = blockRemoteIp;
    }

    public String[] getIgnorePath() {
        return ignorePath;
    }

    public void setIgnorePath(String[] ignorePath) {
        this.ignorePath = ignorePath;
    }

    public String[] getAllowCrossDomain() {
        return allowCrossDomain;
    }

    public void setAllowCrossDomain(String[] allowCrossDomain) {
        this.allowCrossDomain = allowCrossDomain;
    }
}
