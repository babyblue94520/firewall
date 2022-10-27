package pers.clare.firewall;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@ConditionalOnBean(FirewallConfiguration.class)
public class FirewallAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(FirewallService.class)
    public FirewallService firewallService(FirewallConfiguration configuration) {
        FirewallService firewallService = new FirewallService();
        firewallService.addRules(configuration.getRule());
        firewallService.addRules(configuration.getAdditionalRule());
        return firewallService;
    }
}
