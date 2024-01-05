package pers.clare.firewall;


import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

public class FirewallRule {
    private final static Pattern replace = Pattern.compile("^regex:");

    private final ConcurrentMap<String, String> fixedRules = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, String> regexRules = new ConcurrentHashMap<>();

    private Pattern regexRule = null;

    public FirewallRule() {
    }

    public FirewallRule(String... array) {
        add(array);
    }

    public FirewallRule(Collection<String> collection) {
        add(collection);
    }

    public void add(Collection<String> collection) {
        if (collection == null || collection.size() == 0) return;
        for (String data : collection) {
            add(data);
        }
    }

    public void add(String... array) {
        if (array == null) return;
        for (String data : array) {
            add(data);
        }
    }

    public void add(String data) {
        if (data == null || data.length() == 0) return;
        String rule = replace.matcher(data).replaceFirst("");
        if (data.equals(rule)) {
            fixedRules.put(rule, rule);
        } else {
            regexRules.put(rule, rule);
            regexRule = null;
        }
    }

    public boolean isEmpty() {
        return fixedRules.size() == 0 && regexRules.size() == 0;
    }

    public boolean match(String data) {
        if (isEmpty()) return false;
        if (fixedRules.containsKey(data)) return true;
        if (regexRules.size() == 0) return false;
        if (regexRule == null && (regexRule = toPattern(regexRules.keySet())) == null) return false;
        return regexRule.matcher(data).find();
    }

    private Pattern toPattern(Set<String> regexRules) {
        if (regexRules == null || regexRules.size() == 0) return null;
        StringBuilder sb = new StringBuilder();
        for (String regexRule : regexRules) {
            sb.append('(').append(regexRule).append(')').append('|');
        }
        sb.delete(sb.length() - 1, sb.length());
        return Pattern.compile(sb.toString());
    }
}
