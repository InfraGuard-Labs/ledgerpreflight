import java.security.MessageDigest
import java.util.Properties
plugins {
    java
    application
    jacoco
}
group = "io.ledgerpreflight"
version = "0.1.0"
repositories { mavenCentral() }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }
dependencies {
    implementation("info.picocli:picocli:4.7.6")
    implementation("org.ow2.asm:asm:9.7.1")
    implementation("com.typesafe:config:1.4.3")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.10")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}
dependencyLocking { lockAllConfigurations() }
application { mainClass.set("io.ledgerpreflight.cli.Main") }
tasks.test { environment("LP_DISCOVERY_TEST_IDENTITY", "Example Company"); environment("LP_DISCOVERY_SECRET", "CredentialFixture91"); useJUnitPlatform(); finalizedBy(tasks.jacocoTestReport) }
jacoco { toolVersion = "0.8.12" }
tasks.jacocoTestReport { reports { xml.required.set(true); html.required.set(true) } }
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
tasks.jar {
    from(listOf("LICENSE", "THIRD-PARTY-NOTICES")) { into("META-INF/ledgerpreflight") }
    manifest { attributes("Main-Class" to application.mainClass.get(), "Implementation-Version" to project.version) }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    exclude("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "module-info.class", "META-INF/versions/**/module-info.class")
}

tasks.register<JavaExec>("syntheticReplay") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("io.ledgerpreflight.integration.SyntheticFixtureFactory")
    args(layout.buildDirectory.dir("synthetic").get().asFile.absolutePath)
}
tasks.register<JavaExec>("benchmark") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("io.ledgerpreflight.integration.Benchmark")
    args(layout.buildDirectory.dir("benchmark").get().asFile.absolutePath)
}
tasks.register("sbom") {
    doLast {
        val artifacts = configurations.runtimeClasspath.get().resolvedConfiguration.resolvedArtifacts.sortedBy { it.moduleVersion.id.toString() }
        val components = artifacts.map { artifact ->
            val id = artifact.moduleVersion.id
            val purl = "pkg:maven/${id.group}/${id.name}@${id.version}"
            val digest = MessageDigest.getInstance("SHA-256").digest(artifact.file.readBytes()).joinToString("") { "%02x".format(it) }
            mapOf("type" to "library", "bom-ref" to purl, "group" to id.group, "name" to id.name, "version" to id.version, "purl" to purl, "hashes" to listOf(mapOf("alg" to "SHA-256", "content" to digest)))
        }
        val runtimeHome = file("/opt/ledgerpreflight-jre")
        val runtimeRelease = Properties().apply { runtimeHome.resolve("release").inputStream().use { load(it) } }
        val runtimeVersion = runtimeRelease.getProperty("JAVA_VERSION").replace("\"", "")
        val runtimeRef = "pkg:generic/eclipse-temurin-jre@$runtimeVersion?arch=x86_64&os=linux"
        val runtimeComponent = mapOf("type" to "framework", "bom-ref" to runtimeRef, "name" to "eclipse-temurin-jre", "version" to runtimeVersion, "purl" to runtimeRef, "licenses" to listOf(mapOf("expression" to "GPL-2.0-only WITH Classpath-exception-2.0")))
        val distributedComponents = components + runtimeComponent
        val rootRef = "pkg:maven/io.ledgerpreflight/ledger-preflight@0.1.0"
        val document = mapOf("bomFormat" to "CycloneDX", "specVersion" to "1.5", "version" to 1,
            "metadata" to mapOf("component" to mapOf("type" to "application", "bom-ref" to rootRef, "name" to "ledger-preflight", "version" to "0.1.0", "licenses" to listOf(mapOf("license" to mapOf("id" to "Apache-2.0"))))),
            "components" to distributedComponents, "dependencies" to listOf(mapOf("ref" to rootRef, "dependsOn" to distributedComponents.map { it["bom-ref"] })))
        val output = layout.buildDirectory.file("reports/sbom.cdx.json").get().asFile
        output.parentFile.mkdirs()
        output.writeText(groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(document)) + "\n")
    }
}
