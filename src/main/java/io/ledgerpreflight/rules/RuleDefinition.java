package io.ledgerpreflight.rules;

import java.util.List;

/** Declarative conditions are ANDed. There is no scripting, regex, file access, or network. */
public record RuleDefinition(String id, String title, String severity, String category,
                             String confidence, String source, String impact, String explanation,
                             String nextAction, String documentationReference,
                             List<Condition> conditions) {
    public RuleDefinition { conditions = List.copyOf(conditions); }
    public record Condition(String fact, String operator, String value) {}
}
