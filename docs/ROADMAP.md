# Scope and roadmap

Version 0.1.0 is a standalone Linux CLI for Corda upgrade preflight and analysis of existing TVU evidence. Its Linux x86_64 package includes private Java 17. Release validation targets Ubuntu 18.04, 20.04, 22.04 and 24.04, including coexistence with node Java 8.

The scope covers offline artifact discovery, exact JVM member compatibility, configuration risks, imported TVU failure correlation, constrained local rules, technical reports and sanitized support evidence. Headless terminal use is primary; HTML is an output artifact.

v0.1.0 does not execute TVU or Corda, clone databases, run migrations or perform upgrades. Future work should improve evidence quality and versioned rules using reproducible cases and public vendor documentation. No future orchestration feature is a release commitment.

Privately licensed validation inputs may be used only in ignored local fixtures. They must never become public fixtures, build-context contents or release dependencies.
