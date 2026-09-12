# Bytecode analysis

The scanner reads class files using ASM without loading application classes or deserializing application objects. It inventories classes, superclasses, interfaces, members and symbolic references. Member identity includes kind, name and exact JVM descriptor; methods with `Iterable` and `Collection` parameters do not match. Constructors are not inherited. Method and field static/instance mismatches are incompatible even when names and descriptors agree.

Compatibility analysis resolves available ancestor declarations conservatively. A missing ancestor prevents a definitive removed-member conclusion. Duplicate target definitions produce uncertainty about which class is selected. Declared API differences in `compare-runtime` are informational: a removed declaration may have moved to an ancestor, and a changed API matters only when something consumes it.

References to Corda internal packages warn because ordinary stability guarantees do not cover them. A required missing internal member can block. The engine has no hardcoded list of missing members by patch release; supplied runtime bytecode determines whether a symbol exists. Synthetic tests model a class that remains present while its exact `sum(Iterable): BigDecimal` method disappears and later returns.

Class-file major versions above 61 cannot execute on Java 17. Compatible major versions alone do not prove a Java 17 rebuild, compiler version, third-party support or absence of reflective/module-access problems. Multi-release JAR selection targets Java 17, honoring the manifest's multi-release declaration. Nested runtime archives are inspected within configured archive limits.

The analyzer cannot prove reachability, reflective method names, bytecode created at runtime, every JVM resolution corner case, or contracts stored only in the ledger database. Classpath evidence and actual TVU validation remain necessary. Verification-pattern warnings identify static conversion/verify references; they do not claim a full data-flow proof. Signature block metadata is not cryptographic signer verification. Installed artifacts alone cannot establish every historical attachment or persisted constraint.

Malformed archives, path traversal, escaping symlinks, oversized entries and bounded-resource failures become coverage findings. Scanned JARs are never executed. See [Security model](SECURITY-MODEL.md) for limits and threat boundaries.
