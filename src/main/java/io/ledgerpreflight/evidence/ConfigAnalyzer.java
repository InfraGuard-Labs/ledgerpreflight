package io.ledgerpreflight.evidence;

import com.typesafe.config.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.*;

public final class ConfigAnalyzer {
    private static final List<String> HIBERNATE_SCHEMA_KEYS=List.of("hibernate.default_schema","database.hibernate.default_schema","\"hibernate.default_schema\"");
    public record ConfigEvidence(String schema, String jdbcCurrentSchema, String hibernateDefaultSchema,
            boolean mixedCase, boolean contradictory, boolean postgresql, List<String> issues, String sanitizedConfig,
            Map<String,Object> safeSettings) {
        public ConfigEvidence(String schema,String jdbcCurrentSchema,String hibernateDefaultSchema,boolean mixedCase,
                boolean contradictory,boolean postgresql,List<String> issues,String sanitizedConfig) {
            this(schema,jdbcCurrentSchema,hibernateDefaultSchema,mixedCase,contradictory,postgresql,issues,sanitizedConfig,Map.of());
        }
    }
    /** Static proof for the selected configuration, never proof of a successful TVU/database run. */
    public record TvuSchemaReadiness(boolean applicable,boolean proven,String status,String configurationSource,
            String effectiveSchema,String mappedProperty,String configuredValue,List<String> evidence) { }
    public static TvuSchemaReadiness tvuSchemaReadiness(ConfigEvidence config,String targetVersion) {
        String primary=Objects.toString(config.safeSettings().get("primarySchema"),"");
        boolean known="CONFIGURED".equals(config.safeSettings().get("schemaResolution"));
        boolean mixed=known&&!primary.isEmpty()&&!primary.equals(primary.toLowerCase(Locale.ROOT));
        boolean family=Objects.toString(targetVersion,"").matches("4\\.12(?:\\.[0-9]+)*");
        boolean applicable=config.postgresql()&&mixed&&family;
        String source=Objects.toString(config.safeSettings().get("configurationSource"),"Not established");
        // Corda documents database.schema as the property mapped to Hibernate default_schema.
        // TVU reads the selected node configuration via -f. A HOCON string containing a
        // complete double-quoted identifier preserves its case in Hibernate-generated SQL.
        // Undocumented hibernate.* aliases and node-only JVM settings cannot establish this.
        String quoted=quotedIdentifier(config.schema());
        boolean proven=applicable&&!config.contradictory()&&quoted!=null&&quoted.equals(primary);
        List<String> proof=new ArrayList<>();
        proof.add("Target TVU family: "+(family?"4.12":"Not established as 4.12"));
        proof.add("Selected configuration: "+source);
        proof.add("Effective schema: "+Objects.toString(config.safeSettings().get("effectiveSchema"),"Not established"));
        if(applicable)proof.add(proven?"Explicit quoted database.schema matches the effective schema and maps to Hibernate default_schema":"Required explicit quoted TVU Hibernate schema configuration is not proven in the selected configuration");
        else proof.add("The known 4.12 mixed-case effective PostgreSQL schema condition is not established");
        proof.add("Configuration proof applies only when TVU uses this selected configuration; it does not prove physical database state, a different validation copy, or successful TVU execution");
        return new TvuSchemaReadiness(applicable,proven,proven?"CONFIGURATION_PROVEN":applicable?"REQUIRED_UNPROVEN":"NOT_APPLICABLE",source,primary,"hibernate.default_schema",Objects.toString(config.schema(),""),List.copyOf(proof));
    }
    /** A known rule can be applied only in a private guided workspace, after database approval. */
    public static boolean canPrepareTvuSchema(ConfigEvidence config,String targetVersion) {
        if(!tvuSchemaReadiness(config,targetVersion).applicable()||config.contradictory())return false;
        try{selectTvuSchema(config,null);return true;}catch(IOException ignored){return false;}
    }
    /** A manual selection is constrained to names already established by configuration evidence. */
    public static String selectTvuSchema(ConfigEvidence config,String explicitSchema)throws IOException {
        String primary=Objects.toString(config.safeSettings().get("primarySchema"),"");
        boolean configured="CONFIGURED".equals(config.safeSettings().get("schemaResolution"));
        String chosen=explicitSchema==null||explicitSchema.isBlank()?null:explicitSchema;
        if(chosen==null){
            if(!configured||primary.isBlank())throw new IOException("Could not determine the effective schema. Select a schema from the discovered configuration.");
            chosen=primary;
        }else{
            if(configured&&!primary.isBlank()&&!chosen.equals(primary))throw new IOException("The selected TVU schema differs from the established primary schema.");
            Set<String> candidates=new LinkedHashSet<>();if(!primary.isBlank())candidates.add(primary);
            for(String key:List.of("schemas","schemaDeclarations")){
                Object value=config.safeSettings().get(key);
                if(value instanceof Collection<?> values)for(Object item:values)if(item instanceof String name)candidates.add(name);
            }
            if(!candidates.contains(chosen))throw new IOException("The selected TVU schema is not established by the supplied configuration.");
        }
        if(chosen.isBlank()||chosen.length()>256||chosen.codePoints().anyMatch(Character::isISOControl))
            throw new IOException("The effective schema cannot be safely represented in TVU configuration.");
        return chosen;
    }
    public static String quotedTvuSchema(String schema)throws IOException {
        if(schema==null||schema.isBlank()||schema.length()>256||schema.codePoints().anyMatch(Character::isISOControl))
            throw new IOException("The effective schema cannot be safely represented in TVU configuration.");
        return "\""+schema.replace("\"","\"\"")+"\"";
    }
    private static String quotedIdentifier(String value) {
        if(value==null)return null;String text=value.strip();
        if(text.length()<3||text.charAt(0)!='"'||text.charAt(text.length()-1)!='"')return null;
        StringBuilder decoded=new StringBuilder();
        for(int i=1;i<text.length()-1;i++){
            char c=text.charAt(i);
            if(Character.isISOControl(c))return null;
            if(c=='"'){if(i+1>=text.length()-1||text.charAt(i+1)!='"')return null;i++;}
            decoded.append(c);
        }
        return decoded.toString().isBlank()?null:decoded.toString();
    }
    public ConfigEvidence analyze(Path path) throws IOException {
        return analyze(path,path==null?null:path.toRealPath().getParent());
    }
    public ConfigEvidence analyze(Path path,Path permittedRoot) throws IOException {
        if (path == null) return new ConfigEvidence(null,null,null,false,false,false,List.of("node.conf was not supplied"), "# No configuration supplied\n");
        try {
            var parsed=SafeHocon.read(path,permittedRoot);Config cfg=parsed.config();
            String schema = value(cfg,"database.schema");
            Map<String,String> hibernateDeclarations=new TreeMap<>();
            for(String key:HIBERNATE_SCHEMA_KEYS){String declaration=value(cfg,key);if(declaration!=null)hibernateDeclarations.put(key,declaration);}
            String hibernate=null;for(String key:HIBERNATE_SCHEMA_KEYS)if(hibernateDeclarations.containsKey(key)){hibernate=hibernateDeclarations.get(key);break;}
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
            settings.put("hibernateSchemaDeclarations",Collections.unmodifiableMap(hibernateDeclarations));
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
            List<String> searchPath=new ArrayList<>(),jdbcPath=new ArrayList<>();
            boolean quotedIdentifiers=false;
            if(current!=null)jdbcPath.addAll(schemaPath(current,false,issues));
            if(init!=null) {
                Matcher search=Pattern.compile("(?i)\\bset\\s+(?:session\\s+)?search_path\\s*(?:=|to)\\s*([^;]+)").matcher(init);
                if(search.find()){String declaration=search.group(1);quotedIdentifiers=declaration.contains("\"");searchPath.addAll(schemaPath(declaration,true,issues));if(search.find())issues.add("search_path contains unsupported expressions: multiple assignments require review");}
            }
            settings.put("searchPath",List.copyOf(searchPath));settings.put("jdbcSchemaPath",List.copyOf(jdbcPath));settings.put("quotedIdentifierSensitivity",quotedIdentifiers);
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
            if(schema!=null)declarations.add(identifier(schema));
            for(String declared:hibernateDeclarations.values())declarations.add(identifier(declared));
            if(!jdbcPath.isEmpty())declarations.add(jdbcPath.get(0));
            if(!searchPath.isEmpty())declarations.add(searchPath.get(0));
            boolean conflict=declarations.stream().distinct().count()>1;
            boolean unresolvedSchema=issues.stream().anyMatch(i->i.contains("unsupported expressions")||i.startsWith("Unresolved")&&!i.endsWith("notary")&&!i.endsWith("notary.validating")&&!i.endsWith("myLegalName"));
            settings.put("schemaDeclarations",Collections.unmodifiableMap(new TreeMap<>(Map.of("database.schema",Objects.toString(schema,"Not supplied"),"JDBC currentSchema",Objects.toString(current,"Not supplied"),"Hibernate default_schema",Objects.toString(hibernate,"Not supplied"),"search_path",searchPath))));
            settings.put("schemaResolution",unresolvedSchema?"UNRESOLVED":conflict?"AMBIGUOUS":declarations.isEmpty()?"DEFAULT_UNVERIFIED":"CONFIGURED");
            settings.put("effectiveSchema",unresolvedSchema?"Unknown":conflict?"Ambiguous":declarations.isEmpty()?"Default (not independently established)":declarations.get(0));
            LinkedHashSet<String> schemas=new LinkedHashSet<>();
            if(schema!=null)schemas.add(identifier(schema));for(String declared:hibernateDeclarations.values())schemas.add(identifier(declared));
            schemas.addAll(jdbcPath);schemas.addAll(searchPath);
            String primary=unresolvedSchema||conflict||declarations.isEmpty()?"":declarations.get(0);
            settings.put("primarySchema",primary);
            settings.put("schemas",List.copyOf(schemas));
            settings.put("additionalSchemas",schemas.stream().filter(name->!name.equals(primary)).toList());
            settings.put("schemaExplanation",unresolvedSchema?"Required schema evidence is unresolved":conflict?"Explicit schema declarations disagree":declarations.isEmpty()?"No explicit schema declaration; database defaults are unverified":declarations.size()==1?"One explicit schema declaration; database behavior is unverified":"Explicit schema declarations agree");
            settings.put("schemaConfidence",unresolvedSchema||conflict||declarations.isEmpty()?"UNKNOWN":declarations.size()>1?"HIGH":"MEDIUM");
            if (conflict) issues.add("Schema declarations disagree; verify effective TVU and node schema separately");
            boolean mixed=schemas.stream().anyMatch(d->!d.equals(d.toLowerCase(Locale.ROOT)));
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
    /** PostgreSQL paths preserve order and quoted commas; SQL folds unquoted names, JDBC supplies names. */
    private static List<String> schemaPath(String declaration,boolean foldUnquoted,List<String> issues) {
        List<String> result=new ArrayList<>();int i=0;
        while(i<declaration.length()) {
            while(i<declaration.length()&&Character.isWhitespace(declaration.charAt(i)))i++;
            boolean quoted=i<declaration.length()&&declaration.charAt(i)=='"';StringBuilder name=new StringBuilder();boolean closed=!quoted;
            if(quoted){i++;while(i<declaration.length()){char c=declaration.charAt(i++);if(c=='"'){if(i<declaration.length()&&declaration.charAt(i)=='"'){name.append('"');i++;}else{closed=true;break;}}else name.append(c);}}
            else while(i<declaration.length()&&declaration.charAt(i)!=',')name.append(declaration.charAt(i++));
            while(i<declaration.length()&&Character.isWhitespace(declaration.charAt(i)))i++;
            String value=quoted?name.toString():name.toString().strip();
            if(!closed||value.isEmpty()||value.equals("$user")||(!quoted&&!value.matches("[A-Za-z_][A-Za-z0-9_$]*"))||i<declaration.length()&&declaration.charAt(i)!=',') {
                issues.add("Schema path contains unsupported expressions; primary schema requires review");return List.copyOf(result);
            }
            result.add(foldUnquoted&&!quoted?value.toLowerCase(Locale.ROOT):value);
            if(i<declaration.length()){i++;if(i==declaration.length())issues.add("Schema path contains unsupported expressions: empty final schema");}
        }
        return List.copyOf(result);
    }
    private static String identifier(String declaration) {
        String value=declaration.strip();if(value.isEmpty())throw new IllegalArgumentException("Empty schema identifier");
        if(value.startsWith("\"")){String quoted=quotedIdentifier(value);if(quoted==null)throw new IllegalArgumentException("Malformed quoted schema identifier");return quoted;}
        return value;
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
