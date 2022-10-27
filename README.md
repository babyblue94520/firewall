# Firewall

## Overview


## Requirement

* Spring Boot 2.3+
* Java 8+

## QuickStart

1. Write rule in yml

```yaml
firewall:
  rule:

  additional-rule:

```

2. Enable

```java

import com.primestar.firewall.EnableFirewall;

@EnableFirewall
public class Application {

}
```

3. Implement Filter

```java
import com.primestar.firewall.FirewallService;
import com.primestar.firewall.FirewallType;


public class DemoFilter implements Filter {
    @Autowired
    private FirewallService firewallService;
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String path = request.getRequestURI();
        String url = request.getRequestURL().toString();
        String origin = request.getHeader(HttpHeaders.ORIGIN);
        String clientIp = WebUtil.getClientIp(request);
        String remoteIp = request.getRemoteAddr();

        int type = firewallService.parse(path, url, origin, clientIp, remoteIp);
    }
}

```

## Advanced

1. Add rule at runtime

```java

import com.primestar.firewall.EnableFirewall;
import com.primestar.firewall.FirewallService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

@EnableFirewall
@Configuration
public class CustomConfig implements InitializingBean {

    @Autowired
    private FirewallService firewallService;


    @Override
    public void afterPropertiesSet() throws Exception {

        // add other rule
        firewallService.getIgnorePath().add("");
    }
}

```
