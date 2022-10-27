package pers.clare;

import pers.clare.firewall.EnableFirewall;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableFirewall
@SpringBootApplication
public class FirewallApplicationTest {

    public static void main(String[] args) {
        SpringApplication.run(FirewallApplicationTest.class, args);
    }
}
