package io.ledgerpreflight.evidence;

import com.typesafe.config.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.*;

public final class ConfigAnalyzer {
    public record ConfigEvidence(String schema, String jdbcCurrentSchema, String hibernateDefaultSchema,
            boolean mixedCase, boolean contradictory, boolean postgresql, List<String> issues, String sanitizedConfig,
            Map<String,Object> safeSettings) {
        public ConfigEvidence(String schema,String jdbcCurrentSchema,String hibernateDefaultSchema,boolean mixedCase,
                boolean contradictory,boolean postgresql,List<String> issues,String sanitizedConfig) {
            this(schema,jdbcCurrentSchema,hibernateDefaultSchema,mixedCase,contradictory,postgresql,issues,sanitizedConfig,Map.of());
        }
    }
    public ConfigEvidence analyze(Path path) throws IOException {
        return analyze(path,path==null?null:path.toRealPath().getParent());
    }
    public ConfigEvidence analyze(Path path,Path permittedRoot) throws IOException {
        if (path == null) return new ConfigEvidence(null,null,null,false,false,false,List.of("node.conf was not supplied"), "# No configuration supplied\n");
        try {
            var parsed=SafeHocon.read(path,permittedRoot);Config cfg=parsed.config();
            String schema = value(cfg,"database.schema");
            String hibernate = value(cfg,"hibernate.default_schema");
            if (hibernate == null) hibernate=value(cfg,"database.hibernate.default_schema");
            if (hibernate == null) hibernate=value(cfg,"\"hibernate.default_schema\"");
            String jdbc=value(cfg,"dataSourceProperties.dataSource.url");
            if (jdbc==null) jdbc=value(cfg,"dataSourceProperties.\"dataSource.url\"");
            if (jdbc==null) jdbc=value(cfg,"database.url");
            if (jdbc==null) jdbc=value(cfg,"dataSource.url");
            if (jdbc==null) jdbc=value(cfg,"\"dataSource.url\"");
            String current=null;
            if (jdbc!=null) {
                Matcher m=Pattern.compile("(?i)[?&;]currentSchema=([^&;]*)").matcher(jdbc);
                if (m.find()) current=URLDecoder.decode(m.group(1),StandardCharsets.UTF_8);
            }
            List<String> issues=new ArrayList<>();
            TreeMap<String,Object> settings=new TreeMap<>();
            settings.put("configurationIncludes",parsed.includes());
            for(String key:List.of("database.schema","database.url","dataSource.url","\"dataSource.url\"","dataSourceProperties.dataSource.url","dataSourceProperties.\"dataSource.url\"","connectionInitSql","dataSourceProperties.connectionInitSql","dataSourceProperties.\"dataSource.connectionInitSql\"","hibernate.default_schema","database.hibernate.default_schema","\"hibernate.default_schema\"","notary.validating","myLegalName")){
                try{if(cfg.hasPath(key))cfg.getValue(key).valueType();}catch(ConfigException.NotResolved e){issues.add("Unresolved configuration value: "+key);}
            }
            boolean notary=false,notaryUnknown=false;
            try{notary=cfg.hasPath("notary")&&cfg.getValue("notary").valueType()==ConfigValueType.OBJECT;}catch(ConfigException.NotResolved e){notaryUnknown=true;issues.add("Unresolved configuration value: notary");}
            String validating=value(cfg,"notary.validating");
            settings.put("nodeType",notaryUnknown?"Unknown":notary?"Notary":"Corda node");settings.put("nodeTypeConfidence",notaryUnknown?"UNKNOWN":notary?"CONFIRMED":"HIGH");
            settings.put("notaryMode",notary?("true".equals(validating)?"Validating":"false".equals(validating)?"Non-validating":"Unknown"):"Not applicable");
            settings.put("notaryModeConfidence",Set.of("true","false").contains(Objects.toString(validating,""))?"CONFIRMED":"UNKNOWN");
            settings.put("businessRole","Unknown");settings.put("businessRoleConfidence","UNKNOWN");
            String legalName=value(cfg,"myLegalName");
            if(legalName!=null)settings.put("myLegalName",legalName);
            String sourceClass=value(cfg,"dataSourceProperties.dataSourceClassName");
            if(sourceClass!=null) settings.put("dataSourceClassName",sourceClass);
            String jdbcType=null;
            if(jdbc!=null) { Matcher type=Pattern.compile("^jdbc:([A-Za-z0-9]+):").matcher(jdbc); if(type.find()) jdbcType=type.group(1).toLowerCase(Locale.ROOT); }
            if(jdbcType==null&&sourceClass!=null){String driver=sourceClass.toLowerCase(Locale.ROOT);jdbcType=driver.contains("postgresql")?"postgresql":driver.contains("oracle")?"oracle":driver.contains("sqlserver")?"sqlserver":null;}
            settings.put("databaseVendor",switch(Objects.toString(jdbcType,"")){case "postgresql"->"PostgreSQL";case "oracle"->"Oracle";case "sqlserver"->"SQL Server";default->"Unknown";});
            if(jdbcType!=null) { settings.put("jdbcDatabaseType",jdbcType); settings.put("sanitizedJdbcUrl","jdbc:"+jdbcType+":[CONNECTION-DETAILS-OMITTED]"+(current==null?"":"?currentSchema="+current)); }
            String init=value(cfg,"dataSourceProperties.connectionInitSql");
            if(init==null) init=value(cfg,"connectionInitSql");
            if(init==null) init=value(cfg,"dataSourceProperties.\"dataSource.connectionInitSql\"");
            settings.put("connectionInitSqlPresent",init!=null);
            List<String> searchPath=new ArrayList<>();
            boolean quotedIdentifiers=false;
            if(init!=null) {
                Matcher search=Pattern.compile("(?i)\\bset\\s+(?:session\\s+)?search_path\\s*(?:=|to)\\s*([^;]+)").matcher(init);
                if(search.find()) for(String element:search.group(1).split(",")) {
                    String identifier=element.strip();
                    if(identifier.matches("\"[A-Za-z_][A-Za-z0-9_$]*\"")) { quotedIdentifiers=true; searchPath.add(identifier.substring(1,identifier.length()-1)); }
                    else if(identifier.matches("[A-Za-z_][A-Za-z0-9_$]*")) searchPath.add(identifier.toLowerCase(Locale.ROOT));
                    else issues.add("connectionInitSql search_path contains unsupported expressions; validate it manually");
                }
            }
            settings.put("searchPath",List.copyOf(searchPath)); settings.put("quotedIdentifierSensitivity",quotedIdentifiers);
            for(String key:List.of("database.runMigration","database.initialiseSchema","devMode","detectPublicIp"))
                if(cfg.hasPath(key)) settings.put(key,cfg.getBoolean(key));
            for(String key:List.of("p2pAddress","rpcSettings.address","rpcSettings.adminAddress","rpcSettings.useSsl","compatibilityZoneURL","networkServices","externalVerifier"))
                settings.put(key+"Present",cfg.hasPath(key));
            for(String key:List.of("externalVerifier.jvmArgs","custom.externalVerifierJvmArgs")) if(cfg.hasPath(key)) {
                List<String> args=cfg.getStringList(key); List<String> safeArgs=new ArrayList<>();
                for(String arg:args) if(arg.matches("-Xm[sx][0-9]+[kKmMgG]?|-XX:[+-]Use[A-Za-z0-9]+GC")) safeArgs.add(arg);
                settings.put(key+"Count",args.size()); settings.put(key+"SafeMemorySettings",List.copyOf(safeArgs));
            }
            List<String> declarations=new ArrayList<>();
            for(String declared:Arrays.asList(schema,current,hibernate))if(declared!=null)declarations.add(identifier(declared));
            if(!searchPath.isEmpty())declarations.add(searchPath.get(0));
            boolean conflict=declarations.stream().distinct().count()>1;
            boolean unresolvedSchema=issues.stream().anyMatch(i->i.contains("unsupported expressions")||i.startsWith("Unresolved")&&!i.endsWith("notary")&&!i.endsWith("notary.validating")&&!i.endsWith("myLegalName"));
            settings.put("schemaDeclarations",Collections.unmodifiableMap(new TreeMap<>(Map.of("database.schema",Objects.toString(schema,"Not supplied"),"JDBC currentSchema",Objects.toString(current,"Not supplied"),"Hibernate default_schema",Objects.toString(hibernate,"Not supplied"),"search_path",searchPath))));
            settings.put("schemaResolution",unresolvedSchema?"UNRESOLVED":conflict?"AMBIGUOUS":declarations.isEmpty()?"DEFAULT_UNVERIFIED":"CONFIGURED");
            settings.put("effectiveSchema",unresolvedSchema?"Unknown":conflict?"Ambiguous":declarations.isEmpty()?"Default (not independently established)":declarations.get(0));
            settings.put("schemaExplanation",unresolvedSchema?"Required schema evidence is unresolved":conflict?"Explicit schema declarations disagree":declarations.isEmpty()?"No explicit schema declaration; database defaults are unverified":declarations.size()==1?"One explicit schema declaration; database behavior is unverified":"Explicit schema declarations agree");
            settings.put("schemaConfidence",unresolvedSchema||conflict||declarations.isEmpty()?"UNKNOWN":declarations.size()>1?"HIGH":"MEDIUM");
            if (conflict) issues.add("Schema declarations disagree; verify effective TVU and node schema separately");
            boolean mixed=declarations.stream().anyMatch(d->!d.equals(d.toLowerCase(Locale.ROOT)));
            if (mixed&&"postgresql".equals(jdbcType)) issues.add("Mixed-case schema requires explicit TVU schema-resolution validation");
            settings.put("configurationConfidence",issues.stream().anyMatch(i->i.startsWith("Unresolved"))?"UNKNOWN":"HIGH");
            settings.put("configurationSource",path.getFileName().toString());
            String clean="# Allowlisted configuration signals; all other configuration omitted\n" +
                render("database.schema",schema)+render("jdbc.currentSchema",current)+render("hibernate.default_schema",hibernate);
            return new ConfigEvidence(schema,current,hibernate,mixed,conflict,"postgresql".equals(jdbcType),List.copyOf(issues),clean,Collections.unmodifiableMap(settings));
        } catch (ConfigException | IllegalArgumentException e) {
            throw new IOException("Malformed or unsupported HOCON configuration");
        }
    }
    private static String identifier(String declaration) {
        String value=declaration.strip();
        if(value.startsWith("\"")){int end=1;StringBuilder out=new StringBuilder();while(end<value.length()){char c=value.charAt(end++);if(c=='"'){if(end<value.length()&&value.charAt(end)=='"'){out.append(c);end++;}else return out.toString();}else out.append(c);}throw new IllegalArgumentException("Unclosed schema identifier");}
        return value.split(",",2)[0].strip();
    }
    private static String value(Config c,String key) {
        try { if (!c.hasPath(key)) return null; } catch(ConfigException.NotResolved e){return null;}
        String v;try{v=c.getString(key);}catch(ConfigException.NotResolved e){return null;}
        if (v.length()>4096) throw new IllegalArgumentException("Configuration signal exceeds limit");
        return Sanitizer.redact(v);
    }
    private static String render(String key,String value) {
        return value==null ? "" : key+" = "+ConfigValueFactory.fromAnyRef(value).render(ConfigRenderOptions.concise())+"\n";
    }
}
