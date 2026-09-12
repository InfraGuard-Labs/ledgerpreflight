package io.ledgerpreflight.rules;

import java.util.List;

/** Immutable finding emitted by a versioned rule. No input files are modified. */
public record RuleFinding(String id, String title, String severity, String category,
                          String status, String confidence, String source,
                          String affectedArtifact, List<String> evidence, String impact,
                          String explanation, String nextAction, String documentationReference) {
    public RuleFinding { evidence = List.copyOf(evidence); }
}
