package pers.clare.firewall.input;

import org.springframework.boot.context.properties.NestedConfigurationProperty;

public class IpAndRemoteIp {
    @NestedConfigurationProperty
    private FixedRegex ips = new FixedRegex();

    @NestedConfigurationProperty
    private FixedRegex remoteIps = new FixedRegex();

    public FixedRegex getIps() {
        return ips;
    }

    public void setIps(FixedRegex ips) {
        this.ips = ips;
    }

    public FixedRegex getRemoteIps() {
        return remoteIps;
    }

    public void setRemoteIps(FixedRegex remoteIps) {
        this.remoteIps = remoteIps;
    }
}
