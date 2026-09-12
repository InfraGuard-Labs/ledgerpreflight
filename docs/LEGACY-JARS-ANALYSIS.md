# Legacy JAR and classpath analysis

`legacy-jars` supplies historical third-party dependencies to the external verifier. It is different from `legacy-contracts`, which contains old contract artifacts for transaction building on mixed-version networks. TVU uses database attachments and does not itself require `legacy-contracts`. See the [R3 crosswalk](R3-DOCUMENTATION-CROSSWALK.md) for the specific official sections.

The analyzer inventories duplicate fully qualified class names across target/runtime and legacy artifacts, compares complete member identities, and identifies additional members found only in the legacy definition. Java selects a whole class definition: it cannot take one class from a runtime JAR and add a missing method from a second JAR with the same class name.

A duplicate without proven order is a potential shadowing warning. If supplied evidence establishes runtime precedence, a purported legacy augmentation can block as shadowed. The report preserves whether order was established; it never treats directory names as universal runtime loading order. Provide a verifier command such as `java -cp verifier.jar:legacy-jars/shim.jar net.corda.verifier.Main` and, where available, class-loading diagnostics identifying the actual selected source. Windows classpaths use semicolons; quoted paths may contain spaces.

Classpath evidence must describe the actual intended runtime and artifacts. A user-supplied command is not authenticated execution proof, and custom classloaders can differ from ordinary application classpaths. Confirm class source with diagnostic output and TVU. Do not resolve a duplicate by blindly moving a shim earlier or replacing vendor classes: use supported runtime/dependency fixes.
