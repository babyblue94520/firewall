package pers.clare.firewall;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FirewallService {
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^https?://([^:/]+)");
    private FirewallRule defendPath = new FirewallRule();
    private FirewallRule defendAllowIp = new FirewallRule();
    private FirewallRule defendAllowRemoteIp = new FirewallRule();

    private FirewallRule allowIp = new FirewallRule();
    private FirewallRule allowRemoteIp = new FirewallRule();

    private FirewallRule blockIp = new FirewallRule();
    private FirewallRule blockRemoteIp = new FirewallRule();

    private FirewallRule ignorePath = new FirewallRule();

    private FirewallRule allowCrossDomain = new FirewallRule();

    public FirewallService() {
    }

    public void addRules(FirewallProperties properties) {
        if (properties == null) return;
        defendPath.add(properties.getDefendPath());
        defendAllowIp.add(properties.getDefendAllowIp());
        defendAllowRemoteIp.add(properties.getDefendAllowIp());

        allowIp.add(properties.getAllowIp());
        allowRemoteIp.add(properties.getAllowRemoteIp());

        blockIp.add(properties.getBlockIp());
        blockRemoteIp.add(properties.getBlockRemoteIp());

        ignorePath.add(properties.getIgnorePath());

        allowCrossDomain.add(properties.getAllowCrossDomain());
    }

    public void reset(FirewallProperties properties) {
        if (properties == null) {
            reset();
        } else {
            defendPath = new FirewallRule(properties.getDefendPath());
            defendAllowIp = new FirewallRule(properties.getDefendAllowIp());
            defendAllowRemoteIp = new FirewallRule(properties.getDefendAllowRemoteIp());

            allowIp = new FirewallRule(properties.getAllowIp());
            allowRemoteIp = new FirewallRule(properties.getAllowRemoteIp());

            blockIp = new FirewallRule(properties.getBlockIp());
            blockRemoteIp = new FirewallRule(properties.getBlockRemoteIp());

            ignorePath = new FirewallRule(properties.getIgnorePath());

            allowCrossDomain = new FirewallRule(properties.getAllowCrossDomain());
        }
    }

    public void reset() {
        defendPath = new FirewallRule();
        defendAllowIp = new FirewallRule();
        defendAllowRemoteIp = new FirewallRule();

        allowIp = new FirewallRule();
        allowRemoteIp = new FirewallRule();

        blockIp = new FirewallRule();
        blockRemoteIp = new FirewallRule();

        ignorePath = new FirewallRule();

        allowCrossDomain = new FirewallRule();
    }

    /**
     * Resolve request type.
     *
     * @param path     path
     * @param url      url
     * @param origin   Origin request header
     * @param clientIp RemoteAddr or forward ip request header
     * @param remoteIp RemoteAddr
     * @return type {@link FirewallType}
     */
    public int parse(
            String path
            , String url
            , String origin
            , String clientIp
            , String remoteIp
    ) {
        // 連線IP 跟 客戶端IP是否相同
        if (Objects.equals(clientIp, remoteIp)) {
            return parse(path, url, origin, clientIp);
        } else {
            return parseDifferent(path, url, origin, clientIp, remoteIp);
        }
    }

    /**
     * Resolve request type.
     *
     * @param path   path
     * @param url    url
     * @param origin Origin request header
     * @param ip     RemoteAddr or forward ip request header
     * @return type {@link FirewallType}
     */
    public int parse(
            String path
            , String url
            , String origin
            , String ip
    ) {
        //檢查是否為拒絕IP
        if (isBlockIp(ip)) {
            return FirewallType.ACCESS_DENIED;
        }
        //檢查是否為允許IP
        if (!isAllowIp(ip)) {
            return FirewallType.ACCESS_DENIED;
        }

        if (isDefendPath(path) && !isDefendAllowIp(ip)) {
            return FirewallType.ACCESS_DEFEND_DENIED;
        }

        return parsePathAndCross(url, origin, path);
    }


    /**
     * The remote IP is different from the client IP
     */
    private int parseDifferent(
            String path
            , String url
            , String origin
            , String clientIp
            , String remoteIp
    ) {
        //檢查是否為拒絕IP
        if (isBlockIp(clientIp, remoteIp)) {
            return FirewallType.ACCESS_DENIED;
        }
        //檢查是否為允許IP
        if (!isAllowIp(clientIp, remoteIp)) {
            return FirewallType.ACCESS_DENIED;
        }
        // 檢查是否可訪問保護的路徑
        if (isDefendPath(path) && !isDefendAllowIp(clientIp, remoteIp)) {
            return FirewallType.ACCESS_DEFEND_DENIED;
        }
        return parsePathAndCross(url, origin, path);
    }

    private int parsePathAndCross(String url, String origin, String path) {
        //跨域請求
        String domain = toDomain(origin);
        if (isCross(domain, url)) {
            if (!isAllowCrossDomain(domain)) {
                return FirewallType.CROSS_ACCESS_DENIED;
            }
            if (isIgnorePath(path)) {
                return FirewallType.IGNORE_PATH_CROSS_ACCESS;
            }
            return FirewallType.CROSS_ACCESS;
            //非跨域請求
        } else {
            //是否為忽略的請求
            if (isIgnorePath(path)) {
                return FirewallType.IGNORE_PATH_ACCESS;
            }
            return FirewallType.ACCESS;
        }
    }

    public boolean isDefendPath(String path) {
        if (defendPath.isEmpty()) return false;
        return defendPath.match(path);
    }

    public boolean isDefendAllowIp(String ip) {
        if (defendAllowIp.isEmpty()) return false;
        return defendAllowIp.match(ip);
    }

    /**
     * IP是否可訪問受保護的路徑
     */
    public boolean isDefendAllowIp(String clientIp, String remoteIp) {
        if (defendAllowRemoteIp.isEmpty()) return isDefendAllowIp(clientIp);
        return defendAllowRemoteIp.match(remoteIp) && isDefendAllowIp(clientIp);
    }

    /**
     * 檢查是否跨域請求.
     */
    public boolean isCross(String domain, String url) {
        if (domain == null || url == null) return false;
        return !url.contains(domain);
    }

    public boolean isAllowIp(String ip) {
        // 沒設定為全通過
        if (allowIp.isEmpty()) return true;
        return allowIp.match(ip);
    }

    public boolean isAllowIp(String clientIp, String remoteIp) {
        // 沒設定為全通過
        if (allowRemoteIp.isEmpty()) return isAllowIp(clientIp);
        return allowRemoteIp.match(remoteIp) && isAllowIp(clientIp);
    }

    public boolean isBlockIp(String ip) {
        if (blockIp.isEmpty()) return false;
        return blockIp.match(ip);
    }

    public boolean isBlockIp(String clientIp, String remoteIp) {
        if (blockRemoteIp.isEmpty()) return isBlockIp(clientIp);
        return blockRemoteIp.match(remoteIp) || isBlockIp(clientIp);
    }

    public boolean isIgnorePath(String path) {
        if (ignorePath.isEmpty()) return false;
        return ignorePath.match(path);
    }

    public boolean isAllowCrossDomain(String domain) {
        if (allowCrossDomain.isEmpty()) return false;
        return allowCrossDomain.match(domain);
    }

    private String toDomain(String origin) {
        if (origin == null || origin.length() == 0) return null;
        Matcher matcher = DOMAIN_PATTERN.matcher(origin);
        if (!matcher.find()) return null;
        return matcher.group(1);
    }

    public FirewallRule getDefendPath() {
        return defendPath;
    }

    public FirewallRule getDefendAllowIp() {
        return defendAllowIp;
    }

    public FirewallRule getDefendAllowRemoteIp() {
        return defendAllowRemoteIp;
    }

    public FirewallRule getAllowIp() {
        return allowIp;
    }

    public FirewallRule getAllowRemoteIp() {
        return allowRemoteIp;
    }

    public FirewallRule getBlockIp() {
        return blockIp;
    }

    public FirewallRule getBlockRemoteIp() {
        return blockRemoteIp;
    }

    public FirewallRule getIgnorePath() {
        return ignorePath;
    }

    public FirewallRule getAllowCrossDomain() {
        return allowCrossDomain;
    }
}
