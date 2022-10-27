package pers.clare.firewall.input;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "firewall.test.in-out-ip-rule")
public class InOutIpRule {
    @NestedConfigurationProperty
    private IpAndRemoteIp in = new IpAndRemoteIp();

    @NestedConfigurationProperty
    private IpAndRemoteIp out = new IpAndRemoteIp();

    public IpAndRemoteIp getIn() {
        return in;
    }

    public void setIn(IpAndRemoteIp in) {
        this.in = in;
    }

    public IpAndRemoteIp getOut() {
        return out;
    }

    public void setOut(IpAndRemoteIp out) {
        this.out = out;
    }
}
