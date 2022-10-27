package pers.clare.firewall.input;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "firewall.test.in-out-rule")
public class InOutRule {
    @NestedConfigurationProperty
    private FixedRegex in = new FixedRegex();

    @NestedConfigurationProperty
    private FixedRegex out = new FixedRegex();

    public FixedRegex getIn() {
        return in;
    }

    public void setIn(FixedRegex in) {
        this.in = in;
    }

    public FixedRegex getOut() {
        return out;
    }

    public void setOut(FixedRegex out) {
        this.out = out;
    }
}
