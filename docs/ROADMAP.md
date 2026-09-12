# Scope and roadmap

Version 0.1.0 is a standalone Linux-first CLI with a bundled Java 17 runtime. Its release validation matrix targets Ubuntu 18.04, 20.04 and 22.04 LTS x86_64. It covers offline artifact discovery, JVM member compatibility, configuration risks, TVU evidence correlation, constrained local rules, reports and sanitized support bundles for the Corda 4.11 to 4.12 migration workflow. Headless terminal use is primary; HTML is secondary executive output. No Jenkins plugin or dashboard is part of the product.

Future 1.x work should refine evidence handling and versioned rules using reproducible cases and public vendor documentation. Privately licensed artifacts may be validated in ignored local fixtures; they must not become release dependencies.

Possible later work includes deeper mapping from historical transactions to attachments, controlled TVU orchestration and richer target comparisons. These are possibilities, not shipped features or commitments. Production upgrades, fleet management and automated database changes remain outside the v1 product.
