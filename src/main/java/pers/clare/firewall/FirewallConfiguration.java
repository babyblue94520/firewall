package pers.clare.firewall;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "firewall")
public class FirewallConfiguration {

    @NestedConfigurationProperty
    private FirewallProperties rule;

    @NestedConfigurationProperty
    private FirewallProperties additionalRule;

    public void setRule(FirewallProperties rule) {
        this.rule = rule;
    }

    public void setAdditionalRule(FirewallProperties additionalRule) {
        this.additionalRule = additionalRule;
    }

    public FirewallProperties getRule() {
        return rule;
    }

    public FirewallProperties getAdditionalRule() {
        return additionalRule;
    }

}
