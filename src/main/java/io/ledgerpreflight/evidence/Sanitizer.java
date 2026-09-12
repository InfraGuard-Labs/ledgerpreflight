package io.ledgerpreflight.evidence;

import java.io.IOException;
import java.util.regex.*;

/** Defense in depth: redact before rendering, then scan every bundle entry. */
public final class Sanitizer {
    private Sanitizer() { }
    private static final String KEY="(?:password|passwd|pwd|secret|token|api[ _.-]?key|access[ _.-]?key|secret[ _.-]?key|authorization|client[ _.-]?secret|keystore[ _.-]?password|truststore[ _.-]?password)";
    private static final Pattern ASSIGN=Pattern.compile("(?im)(?<![\\w.-])([\\\"']?[\\w.-]{0,128}"+KEY+"[\\w.-]{0,128}[\\\"']?\\s*[:=]\\s*)(\\\"(?:\\\\.|[^\\\"\\r\\n])*+\\\"|'[^'\\r\\n]*'|[^,;&}\\r\\n]+)");
    private static final Pattern SENSITIVE_KEY=Pattern.compile("(?i).*"+KEY+".*");
    private static final Pattern BEARER=Pattern.compile("(?i)\\b(Bearer|Basic)\\s+[A-Za-z0-9+/_=.-]+");
    private static final Pattern USERINFO=Pattern.compile("(://)[^\\s/@:]+:[^\\s/@]+@");
    private static final Pattern PEM=Pattern.compile("(?s)-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)[^-]*-----.*?(?:-----END [^-]+-----|\\z)");
    private static final Pattern SUSPICIOUS=Pattern.compile("-----BEGIN .*PRIVATE KEY|\\bAKIA[0-9A-Z]{16}\\b|\\bgh[pousr]_[A-Za-z0-9]{20,}\\b|\\bsk-[A-Za-z0-9_-]{20,}\\b|\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b");
    public static boolean isSensitiveKey(String key) { return SENSITIVE_KEY.matcher(key).matches(); }
    public static String redact(String input) {
        if (input==null) return null;
        String text=PEM.matcher(input).replaceAll("[REDACTED PRIVATE MATERIAL]");
        text=BEARER.matcher(text).replaceAll("$1 [REDACTED]");
        text=USERINFO.matcher(text).replaceAll("$1[REDACTED]@");
        Matcher matcher=ASSIGN.matcher(text); StringBuffer out=new StringBuffer();
        while (matcher.find()) matcher.appendReplacement(out, Matcher.quoteReplacement(matcher.group(1)+"\"[REDACTED]\""));
        matcher.appendTail(out);
        return out.toString();
    }
    public static void assertSafe(String text,String file) throws IOException {
        if (SUSPICIOUS.matcher(text).find()) throw new IOException("Support bundle safety gate rejected entry: "+file);
        Matcher matcher=ASSIGN.matcher(text);
        while(matcher.find()) if(!matcher.group(2).contains("[REDACTED]"))
            throw new IOException("Support bundle safety gate rejected entry: "+file);
    }
}
