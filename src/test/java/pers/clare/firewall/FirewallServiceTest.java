package pers.clare.firewall;

import pers.clare.FirewallApplicationTest;
import pers.clare.firewall.input.InOutIpRule;
import pers.clare.firewall.input.InOutRule;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.StringUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("FirewallService test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FirewallServiceTest {

    @SpringBootTest(
            classes = FirewallApplicationTest.class
            , properties = {"spring.profiles.active=allow-ip"}
    )
    @Nested
    class allow_ip {
        @Autowired
        private FirewallService firewallService;

        @Autowired
        private InOutIpRule inOutIpRule;

        void test(int type, String[] ips) {
            for (String ip : ips)
                assertEquals(type, firewallService.parse("/", "", "", ip)
                        , () -> String.format("ip:%s", ip)
                );
        }

        void test(int type, String[] ips, String[] remoteIps) {
            for (String ip : ips)
                for (String remoteIp : remoteIps)
                    assertEquals(type, firewallService.parse("/", "", "", ip, remoteIp)
                            , () -> String.format("ip:%s, remoteIp:%s", ip, remoteIp)
                    );
        }

        @Nested
        @DisplayName("Check allow ip data")
        class check {

            @Test
            void allow_ip_not_empty() {
                assertFalse(firewallService.getAllowIp().isEmpty());
            }

            @Test
            void allow_remote_ip_not_empty() {
                assertFalse(firewallService.getAllowRemoteIp().isEmpty());
            }

            @Test
            void in_rule_not_empty() {
                assertTrue(inOutIpRule.getIn().getIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getIn().getIps().getRegex().length > 0);
                assertTrue(inOutIpRule.getIn().getRemoteIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getIn().getRemoteIps().getRegex().length > 0);
            }

            @Test
            void out_rule_not_empty() {
                assertTrue(inOutIpRule.getOut().getIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getOut().getIps().getRegex().length > 0);
                assertTrue(inOutIpRule.getOut().getRemoteIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getOut().getRemoteIps().getRegex().length > 0);
            }
        }

        
        
        @DisplayName("Allowed ip access")
        @Nested
        class allowed {

            @Test
            
            void allowed_fixed_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getFixed());
            }

            @Test
            
            void allowed_regex_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getRegex());
            }

            @Test
            
            void allowed_fixed_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void allowed_regex_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void allowed_fixed_ip_regex_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }

            @Test
            
            void allowed_regex_ip_regex_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }
        }

        
        
        @DisplayName("Denied ip access")
        @Nested
        class denied {

            @Test
            
            void fixed_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getFixed());
            }

            @Test
            
            void regex_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getRegex());
            }

            @Test
            
            void fixed_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void regex_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void fixed_ip_and_regex_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }

            @Test
            
            void regex_ip_and_regex_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }

        }
    }

    @SpringBootTest(
            classes = FirewallApplicationTest.class
            , properties = {"spring.profiles.active=block-ip"}
    )
    @Nested
    class block_ip {
        @Autowired
        private FirewallService firewallService;

        @Autowired
        private InOutIpRule inOutIpRule;

        void test(int type, String[] ips) {
            for (String ip : ips)
                assertEquals(type, firewallService.parse("/", "", "", ip)
                        , () -> String.format("ip:%s", ip)
                );
        }

        void test(int type, String[] ips, String[] remoteIps) {
            for (String ip : ips)
                for (String remoteIp : remoteIps)
                    assertEquals(type, firewallService.parse("/", "", "", ip, remoteIp)
                            , () -> String.format("ip:%s, remoteIp:%s", ip, remoteIp)
                    );
        }

        @Nested
        
        
        @DisplayName("Check block ip data")
        class check {

            @Test
            void allow_ip_not_empty() {
                assertFalse(firewallService.getBlockIp().isEmpty());
            }

            @Test
            void allow_remote_ip_not_empty() {
                assertFalse(firewallService.getBlockRemoteIp().isEmpty());
            }

            @Test
            void in_rule_not_empty() {
                assertTrue(inOutIpRule.getIn().getIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getIn().getIps().getRegex().length > 0);
                assertTrue(inOutIpRule.getIn().getRemoteIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getIn().getRemoteIps().getRegex().length > 0);
            }

            @Test
            void out_rule_not_empty() {
                assertTrue(inOutIpRule.getOut().getIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getOut().getIps().getRegex().length > 0);
                assertTrue(inOutIpRule.getOut().getRemoteIps().getFixed().length > 0);
                assertTrue(inOutIpRule.getOut().getRemoteIps().getRegex().length > 0);
            }
        }

        
        
        @DisplayName("Allowed ip access")
        @Nested
        class allowed {

            @Test
            
            void allowed_fixed_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getFixed());
            }

            @Test
            
            void allowed_regex_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getRegex());
            }

            @Test
            
            void allowed_fixed_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void allowed_regex_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void allowed_fixed_ip_regex_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }

            @Test
            
            void allowed_regex_ip_regex_remote_ip_access() {
                test(FirewallType.ACCESS, inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }
        }

        
        
        @DisplayName("Denied ip access")
        @Nested
        class denied {

            @Test
            
            void fixed_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getFixed());
            }

            @Test
            
            void regex_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getRegex());
            }

            @Test
            
            void fixed_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void regex_ip_and_fixed_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void fixed_ip_and_regex_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }

            @Test
            
            void regex_ip_and_regex_remote_ip_access() {
                test(FirewallType.ACCESS_DENIED, inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }

        }
    }

    @SpringBootTest(
            classes = FirewallApplicationTest.class
            , properties = {"spring.profiles.active=defend-path"}
    )
    @Nested
    class defend_path {

        @Autowired
        private FirewallService firewallService;

        @Autowired
        private InOutRule inOutRule;

        @Autowired
        private InOutIpRule inOutIpRule;

        @Nested
        
        
        @DisplayName("Allow access to defend path")
        class allow {
            void test(String[] paths, String[] ips) {
                for (String path : paths)
                    for (String ip : ips)
                        assertEquals(FirewallType.ACCESS, firewallService.parse(path, "", "", ip)
                                , () -> String.format("path:%s, ip:%s", path, ip)
                        );
            }

            void test(String[] paths, String[] ips, String[] remoteIps) {
                for (String path : paths)
                    for (String ip : ips)
                        for (String remoteIp : remoteIps)
                            assertEquals(FirewallType.ACCESS, firewallService.parse(path, "", "", ip, remoteIp)
                                    , () -> String.format("path:%s, ip:%s, remoteIp:%s", path, ip, remoteIp)
                            );
            }

            @Test
            
            void fixed_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getIn().getIps().getFixed());
            }

            @Test
            
            void fixed_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getIn().getIps().getFixed());
            }

            @Test
            
            void regex_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getIn().getIps().getRegex());
            }

            @Test
            
            void regex_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getIn().getIps().getRegex());
            }

            @Test
            
            void fixed_remote_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void fixed_remote_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getIn().getIps().getFixed(), inOutIpRule.getIn().getRemoteIps().getFixed());
            }

            @Test
            
            void regex_remote_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }

            @Test
            
            void regex_remote_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getIn().getIps().getRegex(), inOutIpRule.getIn().getRemoteIps().getRegex());
            }
        }

        @Nested
        
        
        @DisplayName("Deny access to defend path")
        class deny {

            void test(String[] paths, String[] ips) {
                for (String path : paths) {
                    if (StringUtils.hasLength(path)) continue;
                    for (String ip : ips) {
                        if (!StringUtils.hasLength(ip)) continue;
                        assertEquals(FirewallType.ACCESS_DEFEND_DENIED, firewallService.parse(path, "", "", ip)
                                , () -> String.format("path:%s, ip:%s", path, ip)
                        );
                    }
                }
            }

            void test(String[] paths, String[] ips, String[] remoteIps) {
                for (String path : paths) {
                    if (!StringUtils.hasLength(path)) continue;
                    for (String ip : ips) {
                        if (!StringUtils.hasLength(ip)) continue;
                        for (String remoteIp : remoteIps) {
                            if (!StringUtils.hasLength(remoteIp)) continue;
                            assertEquals(FirewallType.ACCESS_DEFEND_DENIED, firewallService.parse(path, "", "", ip, remoteIp)
                                    , () -> String.format("path:%s, ip:%s, remoteIp:%s", path, ip, remoteIp)
                            );
                        }
                    }
                }
            }

            @Test
            
            void fixed_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getOut().getIps().getFixed());
            }

            @Test
            
            void fixed_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getOut().getIps().getFixed());
            }

            @Test
            
            void regex_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getOut().getIps().getRegex());
            }

            @Test
            
            void regex_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getOut().getIps().getRegex());
            }


            @Test
            
            void fixed_remote_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void fixed_remote_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getOut().getIps().getFixed(), inOutIpRule.getOut().getRemoteIps().getFixed());
            }

            @Test
            
            void regex_remote_ip_access_fixed_defend_path() {
                test(inOutRule.getIn().getFixed(), inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }

            @Test
            
            void regex_remote_ip_access_regex_defend_path() {
                test(inOutRule.getIn().getRegex(), inOutIpRule.getOut().getIps().getRegex(), inOutIpRule.getOut().getRemoteIps().getRegex());
            }
        }
    }

    @SpringBootTest(
            classes = FirewallApplicationTest.class
            , properties = {"spring.profiles.active=ignore-path"}
    )
    @Nested
    class ignore_path {

        @Autowired
        private FirewallService firewallService;

        @Autowired
        private InOutRule inOutRule;

        void test(int type, String... paths) {
            for (String path : paths)
                assertEquals(type, firewallService.parse(path, "", "", "127.0.0.1")
                        , () -> String.format("path:%s", path)
                );
        }

        @Nested
        
        
        @DisplayName("Access to ignore path")
        class ignore {
            @Test
            
            void access_fixed_ignore_path() {
                test(FirewallType.IGNORE_PATH_ACCESS, inOutRule.getIn().getFixed());
            }

            @Test
            
            void access_regex_ignore_path() {
                test(FirewallType.IGNORE_PATH_ACCESS, inOutRule.getIn().getRegex());
            }

            @Test
            
            void add_rule() {
                String path = "/" + System.currentTimeMillis();
                test(FirewallType.ACCESS, path);
                firewallService.getIgnorePath().add(path);
                test(FirewallType.IGNORE_PATH_ACCESS, path);

                String oldPath = path;
                path += "/" + System.currentTimeMillis();
                test(FirewallType.ACCESS, path);
                firewallService.getIgnorePath().add("regex:^" + oldPath + "/\\d+");
                test(FirewallType.IGNORE_PATH_ACCESS, path);
            }
        }

        @Nested
        
        
        @DisplayName("Access to not ignore path")
        class not_ignore {
            @Test
            
            void access_not_fixed_ignore_path() {
                test(FirewallType.ACCESS, inOutRule.getOut().getFixed());
            }

            @Test
            
            void access_not_regex_ignore_path() {
                test(FirewallType.ACCESS, inOutRule.getOut().getRegex());
            }
        }
    }


    @SpringBootTest(
            classes = FirewallApplicationTest.class
            , properties = {"spring.profiles.active=cross-domain"}
    )
    @Nested
    class cross_domain {

        @Autowired
        private FirewallService firewallService;

        @Autowired
        private InOutRule inOutRule;

        private final String[] urls = {"http://9.9.9.9:8300/test/api", "https://9.9.9.9:8300/test/api", "http://test.domain.com/test/api", "https://test.domain.com/test/api"};

        void test(int type, String... origins) {
            for (String url : urls)
                for (String origin : origins)
                    assertEquals(type, firewallService.parse("/", url, origin, "127.0.0.1")
                            , () -> String.format("origin:%s", origin)
                    );
        }

        @Nested
        
        
        @DisplayName("Allow cross-domain")
        class allowed {
            @Test
            
            void fixed_cross_domain() {
                test(FirewallType.CROSS_ACCESS, inOutRule.getIn().getFixed());
            }

            @Test
            
            void regex_cross_domain() {
                test(FirewallType.CROSS_ACCESS, inOutRule.getIn().getRegex());
            }

            @Test
            
            void add_rule() {
                String domain = String.valueOf(System.currentTimeMillis());
                String origin = "http://" + domain;
                test(FirewallType.CROSS_ACCESS_DENIED, origin);
                firewallService.getAllowCrossDomain().add(domain);
                test(FirewallType.CROSS_ACCESS, origin);

                origin += "." + System.currentTimeMillis();
                test(FirewallType.CROSS_ACCESS_DENIED, origin);
                firewallService.getAllowCrossDomain().add("regex:^" + domain + "\\.\\d+");
                test(FirewallType.CROSS_ACCESS, origin);
            }
        }

        @Nested
        
        
        @DisplayName("Deny cross-domain")
        class denied {
            @Test
            
            void fixed_cross_domain() {
                test(FirewallType.CROSS_ACCESS_DENIED, inOutRule.getOut().getFixed());
            }

            @Test
            
            void regex_cross_domain() {
                test(FirewallType.CROSS_ACCESS_DENIED, inOutRule.getOut().getRegex());
            }
        }
    }
}
