package pers.clare.firewall.input;

import org.springframework.util.StringUtils;

import java.util.Arrays;

public class FixedRegex {
    private String[] fixed = {};

    private String[] regex = {};

    public String[] getFixed() {
        return fixed;
    }

    public void setFixed(String[] fixed) {
        this.fixed = Arrays.stream(fixed).filter(v-> !StringUtils.isEmpty(v)).toArray(String[]::new);
    }

    public String[] getRegex() {
        return regex;
    }

    public void setRegex(String[] regex) {
        this.regex = Arrays.stream(regex).filter(v-> !StringUtils.isEmpty(v)).toArray(String[]::new);
    }
}
