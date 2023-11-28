package pers.clare;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import pers.clare.firewall.EnableFirewall;

@EnableFirewall
@SpringBootApplication
public class FirewallApplicationTest {

    public static void main(String[] args) {
        SpringApplication.run(FirewallApplicationTest.class, args);
    }
}
