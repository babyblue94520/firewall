package pers.clare.firewall;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import({FirewallConfiguration.class})
public @interface EnableFirewall {
}
