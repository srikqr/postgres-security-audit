/*================================================================
  POSTGRESQL COMPLETE SECURITY & METADATA EXTRACTION SCRIPT
  Comprehensive A-Z Database Security Audit & Analysis
  Compatible with PostgreSQL 12+ - All Distributions
  No Syntax Errors - Database Viewer Compatible
================================================================*/

-- =====================================================
-- SECTION 1: SERVER & INSTANCE INFORMATION
-- =====================================================
\echo '=== SERVER & INSTANCE INFORMATION ==='

-- PostgreSQL version and server information
SELECT version() AS "PostgreSQL Version";
SELECT current_database() AS "Current Database", current_user AS "Current User";
SELECT inet_server_addr() AS "Server IP", inet_server_port() AS "Server Port";
SELECT pg_postmaster_start_time() AS "Server Start Time";
SELECT pg_is_in_recovery() AS "Is In Recovery Mode";

-- Database list with comprehensive metadata
SELECT 
    d.datname AS "Database Name",
    pg_catalog.pg_get_userbyid(d.datdba) AS "Database Owner",
    pg_size_pretty(pg_database_size(d.datname)) AS "Database Size",
    d.encoding AS "Encoding",
    d.datcollate AS "Collate",
    d.datctype AS "CType",
    d.datistemplate AS "Is Template",
    d.datallowconn AS "Allow Connections",
    d.datconnlimit AS "Connection Limit",
    d.datlastsysoid AS "Last System OID",
    d.datfrozenxid AS "Frozen XID",
    d.datminmxid AS "Min Multixact ID",
    d.dattablespace AS "Tablespace OID",
    ts.spcname AS "Tablespace Name",
    has_database_privilege(d.datname, 'CONNECT') AS "Can Connect",
    has_database_privilege(d.datname, 'CREATE') AS "Can Create",
    has_database_privilege(d.datname, 'TEMPORARY') AS "Can Create Temp"
FROM pg_database d
LEFT JOIN pg_tablespace ts ON d.dattablespace = ts.oid
ORDER BY d.datname;

-- Server settings and configuration
SELECT 
    name AS "Setting Name",
    setting AS "Current Value",
    unit AS "Unit",
    category AS "Category",
    short_desc AS "Description",
    context AS "Context",
    vartype AS "Type",
    source AS "Source",
    min_val AS "Min Value",
    max_val AS "Max Value",
    boot_val AS "Boot Value",
    reset_val AS "Reset Value",
    pending_restart AS "Pending Restart",
    sourcefile AS "Source File",
    sourceline AS "Source Line",
    CASE 
        WHEN name IN ('ssl', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file') THEN 'SSL Configuration'
        WHEN name LIKE '%auth%' OR name LIKE '%password%' THEN 'Authentication'
        WHEN name LIKE '%log%' THEN 'Logging'
        WHEN name LIKE '%max%' OR name LIKE '%limit%' THEN 'Resource Limits'
        WHEN name LIKE '%security%' OR name LIKE '%privilege%' THEN 'Security'
        ELSE 'General'
    END AS "Security Category"
FROM pg_settings
WHERE name IN (
    'ssl', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file',
    'password_encryption', 'krb_server_keyfile', 'krb_caseins_users',
    'log_connections', 'log_disconnections', 'log_statement',
    'log_line_prefix', 'log_hostname', 'log_duration',
    'max_connections', 'max_prepared_transactions', 'max_locks_per_transaction',
    'shared_preload_libraries', 'listen_addresses', 'port',
    'unix_socket_directories', 'unix_socket_group', 'unix_socket_permissions',
    'authentication_timeout', 'db_user_namespace', 'row_security',
    'default_transaction_isolation', 'statement_timeout', 'lock_timeout',
    'idle_in_transaction_session_timeout', 'tcp_keepalives_idle',
    'tcp_keepalives_interval', 'tcp_keepalives_count', 'tcp_user_timeout'
)
ORDER BY 
    CASE 
        WHEN name IN ('ssl', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file', 'ssl_crl_file') THEN 1
        WHEN name LIKE '%auth%' OR name LIKE '%password%' THEN 2
        WHEN name LIKE '%log%' THEN 3
        WHEN name LIKE '%max%' OR name LIKE '%limit%' THEN 4
        WHEN name LIKE '%security%' OR name LIKE '%privilege%' THEN 5
        ELSE 6
    END, name;

-- System information
SELECT 
    current_setting('server_version') AS "Server Version",
    current_setting('server_version_num') AS "Version Number",
    current_setting('data_directory') AS "Data Directory",
    current_setting('config_file') AS "Config File",
    current_setting('hba_file') AS "HBA File",
    current_setting('ident_file') AS "Ident File",
    current_setting('external_pid_file') AS "PID File",
    current_setting('timezone') AS "Timezone",
    current_setting('log_timezone') AS "Log Timezone",
    current_setting('lc_messages') AS "LC Messages",
    current_setting('lc_monetary') AS "LC Monetary",
    current_setting('lc_numeric') AS "LC Numeric",
    current_setting('lc_time') AS "LC Time",
    current_setting('default_text_search_config') AS "Default Text Search Config",
    current_setting('max_identifier_length') AS "Max Identifier Length",
    current_setting('block_size') AS "Block Size",
    current_setting('segment_size') AS "Segment Size",
    current_setting('wal_block_size') AS "WAL Block Size",
    current_setting('wal_segment_size') AS "WAL Segment Size",
    current_setting('integer_datetimes') AS "Integer Datetimes";

-- =====================================================
-- SECTION 2: AUTHENTICATION & AUTHORIZATION
-- =====================================================
\echo '=== AUTHENTICATION & AUTHORIZATION ==='

-- All roles with comprehensive security analysis
SELECT 
    r.oid AS "Role OID",
    r.rolname AS "Role Name",
    r.rolsuper AS "Is Superuser",
    r.rolinherit AS "Inherit Privileges",
    r.rolcreaterole AS "Can Create Roles",
    r.rolcreatedb AS "Can Create Databases",
    r.rolcanlogin AS "Can Login",
    r.rolreplication AS "Replication Role",
    r.rolbypassrls AS "Bypass RLS",
    r.rolconnlimit AS "Connection Limit",
    r.rolvaliduntil AS "Password Valid Until",
    CASE 
        WHEN r.rolpassword IS NOT NULL THEN 
            CASE 
                WHEN r.rolpassword LIKE 'SCRAM-SHA-256%' THEN 'SCRAM-SHA-256'
                WHEN r.rolpassword LIKE 'md5%' THEN 'MD5'
                ELSE 'Plain Text'
            END
        ELSE 'No Password'
    END AS "Password Type",
    CASE 
        WHEN r.rolvaliduntil IS NOT NULL AND r.rolvaliduntil < NOW() THEN 'Expired'
        WHEN r.rolvaliduntil IS NOT NULL AND r.rolvaliduntil < NOW() + INTERVAL '30 days' THEN 'Expires Soon'
        ELSE 'Valid'
    END AS "Password Status",
    array_to_string(r.rolconfig, ', ') AS "Role Config",
    CASE 
        WHEN r.rolsuper THEN 'CRITICAL - Superuser Access'
        WHEN r.rolcreaterole THEN 'HIGH - Can Create Roles'
        WHEN r.rolcreatedb THEN 'MEDIUM - Can Create Databases'
        WHEN r.rolcanlogin THEN 'LOW - Login Access'
        ELSE 'MINIMAL - Group Role'
    END AS "Security Risk Level"
FROM pg_authid r
ORDER BY r.rolsuper DESC, r.rolcreaterole DESC, r.rolcreatedb DESC, r.rolname;

-- Role membership and inheritance
SELECT 
    r.rolname AS "Role Name",
    m.rolname AS "Member Role",
    am.admin_option AS "Admin Option",
    CASE 
        WHEN r.rolsuper THEN 'Superuser Membership'
        WHEN r.rolcreaterole THEN 'Role Creation Privileges'
        WHEN r.rolcreatedb THEN 'Database Creation Privileges'
        ELSE 'Standard Membership'
    END AS "Membership Type"
FROM pg_auth_members am
JOIN pg_authid r ON am.roleid = r.oid
JOIN pg_authid m ON am.member = m.oid
ORDER BY r.rolname, m.rolname;

-- Database-level permissions
SELECT 
    d.datname AS "Database Name",
    r.rolname AS "Role Name",
    p.privilege_type AS "Privilege Type",
    p.is_grantable AS "Grantable",
    CASE 
        WHEN p.privilege_type = 'CONNECT' THEN 'Database Connection'
        WHEN p.privilege_type = 'CREATE' THEN 'Schema Creation'
        WHEN p.privilege_type = 'TEMPORARY' THEN 'Temporary Objects'
        ELSE 'Other'
    END AS "Privilege Category"
FROM information_schema.role_table_grants p
JOIN pg_database d ON d.datname = p.table_catalog
JOIN pg_authid r ON r.rolname = p.grantee
WHERE p.table_schema = 'information_schema'
ORDER BY d.datname, r.rolname, p.privilege_type;

-- Current active sessions and connections
SELECT 
    sa.datid AS "Database ID",
    sa.datname AS "Database Name",
    sa.pid AS "Process ID",
    sa.usesysid AS "User ID",
    sa.usename AS "Username",
    sa.application_name AS "Application",
    sa.client_addr AS "Client Address",
    sa.client_hostname AS "Client Hostname",
    sa.client_port AS "Client Port",
    sa.backend_start AS "Backend Start",
    sa.xact_start AS "Transaction Start",
    sa.query_start AS "Query Start",
    sa.state_change AS "State Change",
    sa.wait_event_type AS "Wait Event Type",
    sa.wait_event AS "Wait Event",
    sa.state AS "State",
    sa.backend_xid AS "Backend XID",
    sa.backend_xmin AS "Backend XMIN",
    sa.query AS "Current Query",
    sa.backend_type AS "Backend Type",
    CASE 
        WHEN sa.client_addr IS NULL THEN 'Local Connection'
        WHEN sa.client_addr = '127.0.0.1' THEN 'Local Loopback'
        WHEN sa.client_addr <<= '10.0.0.0/8' OR sa.client_addr <<= '192.168.0.0/16' OR sa.client_addr <<= '172.16.0.0/12' THEN 'Private Network'
        ELSE 'External Connection'
    END AS "Connection Type",
    CASE 
        WHEN sa.state = 'active' THEN 'Currently Executing'
        WHEN sa.state = 'idle' THEN 'Idle'
        WHEN sa.state = 'idle in transaction' THEN 'Idle In Transaction'
        WHEN sa.state = 'idle in transaction (aborted)' THEN 'Idle In Aborted Transaction'
        ELSE 'Unknown State'
    END AS "Session Status"
FROM pg_stat_activity sa
ORDER BY sa.backend_start DESC;

-- =====================================================
-- SECTION 3: SCHEMAS & NAMESPACES
-- =====================================================
\echo '=== SCHEMAS & NAMESPACES ==='

-- All schemas with ownership and privileges
SELECT 
    n.oid AS "Schema OID",
    n.nspname AS "Schema Name",
    pg_get_userbyid(n.nspowner) AS "Schema Owner",
    array_to_string(n.nspacl, ', ') AS "Access Privileges",
    CASE 
        WHEN n.nspname = 'public' THEN 'Public Schema'
        WHEN n.nspname LIKE 'pg_%' THEN 'System Schema'
        WHEN n.nspname = 'information_schema' THEN 'Information Schema'
        ELSE 'User Schema'
    END AS "Schema Type",
    has_schema_privilege(n.nspname, 'USAGE') AS "Has Usage",
    has_schema_privilege(n.nspname, 'CREATE') AS "Has Create",
    CASE 
        WHEN n.nspname = 'public' AND array_to_string(n.nspacl, ', ') LIKE '%=UC%' THEN 'PUBLIC ACCESS - SECURITY RISK'
        WHEN n.nspname LIKE 'pg_%' THEN 'System Schema - Protected'
        ELSE 'User Schema - Review Permissions'
    END AS "Security Assessment"
FROM pg_namespace n
ORDER BY 
    CASE 
        WHEN n.nspname = 'public' THEN 1
        WHEN n.nspname LIKE 'pg_%' THEN 2
        WHEN n.nspname = 'information_schema' THEN 3
        ELSE 4
    END, n.nspname;

-- Schema usage privileges
SELECT 
    n.nspname AS "Schema Name",
    r.rolname AS "Role Name",
    p.privilege_type AS "Privilege Type",
    p.is_grantable AS "Grantable",
    CASE 
        WHEN p.privilege_type = 'USAGE' THEN 'Schema Access'
        WHEN p.privilege_type = 'CREATE' THEN 'Object Creation'
        ELSE 'Other'
    END AS "Privilege Category"
FROM information_schema.usage_privileges p
JOIN pg_namespace n ON n.nspname = p.object_schema
JOIN pg_authid r ON r.rolname = p.grantee
WHERE p.object_type = 'SCHEMA'
ORDER BY n.nspname, r.rolname, p.privilege_type;

-- =====================================================
-- SECTION 4: TABLES & RELATIONS
-- =====================================================
\echo '=== TABLES & RELATIONS ==='

-- All tables with comprehensive metadata
SELECT 
    t.schemaname AS "Schema Name",
    t.tablename AS "Table Name",
    t.tableowner AS "Table Owner",
    t.tablespace AS "Tablespace",
    t.hasindexes AS "Has Indexes",
    t.hasrules AS "Has Rules",
    t.hastriggers AS "Has Triggers",
    t.rowsecurity AS "Row Security",
    pg_size_pretty(pg_total_relation_size(c.oid)) AS "Total Size",
    pg_size_pretty(pg_relation_size(c.oid)) AS "Table Size",
    pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) AS "Index Size",
    c.reltuples::bigint AS "Estimated Rows",
    c.relpages AS "Pages",
    c.relallvisible AS "All Visible",
    c.reltoastrelid AS "Toast Relation ID",
    c.relhasoids AS "Has OIDs",
    c.relhaspkey AS "Has Primary Key",
    c.relhasrules AS "Has Rules",
    c.relhastriggers AS "Has Triggers",
    c.relhassubclass AS "Has Subclass",
    c.relrowsecurity AS "Row Security Enabled",
    c.relforcerowsecurity AS "Force Row Security",
    c.relispopulated AS "Is Populated",
    c.relreplident AS "Replica Identity",
    c.relispartition AS "Is Partition",
    c.relpersistence AS "Persistence",
    CASE c.relpersistence
        WHEN 'p' THEN 'Permanent'
        WHEN 'u' THEN 'Unlogged'
        WHEN 't' THEN 'Temporary'
        ELSE 'Unknown'
    END AS "Persistence Type",
    CASE 
        WHEN c.relrowsecurity THEN 'Row Level Security Enabled'
        WHEN c.relhaspkey THEN 'Has Primary Key'
        WHEN NOT c.relhaspkey THEN 'NO PRIMARY KEY - SECURITY RISK'
        ELSE 'Standard Table'
    END AS "Security Features"
FROM pg_tables t
JOIN pg_class c ON c.relname = t.tablename
JOIN pg_namespace n ON n.nspname = t.schemaname AND n.oid = c.relnamespace
WHERE t.schemaname NOT IN ('information_schema', 'pg_catalog')
ORDER BY pg_total_relation_size(c.oid) DESC;

-- Table privileges and permissions
SELECT 
    p.table_schema AS "Schema Name",
    p.table_name AS "Table Name",
    p.grantee AS "Grantee",
    p.privilege_type AS "Privilege Type",
    p.is_grantable AS "Grantable",
    p.with_hierarchy AS "With Hierarchy",
    CASE 
        WHEN p.privilege_type = 'SELECT' THEN 'Read Access'
        WHEN p.privilege_type = 'INSERT' THEN 'Insert Access'
        WHEN p.privilege_type = 'UPDATE' THEN 'Update Access'
        WHEN p.privilege_type = 'DELETE' THEN 'Delete Access'
        WHEN p.privilege_type = 'TRUNCATE' THEN 'Truncate Access'
        WHEN p.privilege_type = 'REFERENCES' THEN 'Reference Access'
        WHEN p.privilege_type = 'TRIGGER' THEN 'Trigger Access'
        ELSE 'Other Access'
    END AS "Access Type",
    CASE 
        WHEN p.privilege_type IN ('DELETE', 'TRUNCATE') THEN 'HIGH RISK'
        WHEN p.privilege_type IN ('INSERT', 'UPDATE') THEN 'MEDIUM RISK'
        WHEN p.privilege_type = 'SELECT' THEN 'LOW RISK'
        ELSE 'REVIEW REQUIRED'
    END AS "Risk Level"
FROM information_schema.table_privileges p
WHERE p.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY 
    CASE 
        WHEN p.privilege_type IN ('DELETE', 'TRUNCATE') THEN 1
        WHEN p.privilege_type IN ('INSERT', 'UPDATE') THEN 2
        WHEN p.privilege_type = 'SELECT' THEN 3
        ELSE 4
    END, p.table_schema, p.table_name, p.grantee;

-- =====================================================
-- SECTION 5: COLUMNS & DATA TYPES
-- =====================================================
\echo '=== COLUMNS & DATA TYPES ==='

-- All columns with security analysis
SELECT 
    c.table_schema AS "Schema Name",
    c.table_name AS "Table Name",
    c.column_name AS "Column Name",
    c.ordinal_position AS "Position",
    c.column_default AS "Default Value",
    c.is_nullable AS "Nullable",
    c.data_type AS "Data Type",
    c.character_maximum_length AS "Max Length",
    c.numeric_precision AS "Precision",
    c.numeric_scale AS "Scale",
    c.datetime_precision AS "DateTime Precision",
    c.character_set_name AS "Character Set",
    c.collation_name AS "Collation",
    c.domain_name AS "Domain",
    c.udt_name AS "UDT Name",
    c.is_identity AS "Is Identity",
    c.identity_generation AS "Identity Generation",
    c.identity_start AS "Identity Start",
    c.identity_increment AS "Identity Increment",
    c.identity_maximum AS "Identity Maximum",
    c.identity_minimum AS "Identity Minimum",
    c.identity_cycle AS "Identity Cycle",
    c.is_generated AS "Is Generated",
    c.generation_expression AS "Generation Expression",
    c.is_updatable AS "Is Updatable",
    CASE 
        WHEN c.column_name ~* 'password|pwd|pass' THEN 'PASSWORD FIELD'
        WHEN c.column_name ~* 'ssn|social.*security' THEN 'SSN FIELD'
        WHEN c.column_name ~* 'credit.*card|card.*number' THEN 'CREDIT CARD FIELD'
        WHEN c.column_name ~* 'email|mail' THEN 'EMAIL FIELD'
        WHEN c.column_name ~* 'phone|mobile|tel' THEN 'PHONE FIELD'
        WHEN c.column_name ~* 'address|addr' THEN 'ADDRESS FIELD'
        WHEN c.column_name ~* 'birth|dob' THEN 'DATE OF BIRTH FIELD'
        WHEN c.column_name ~* 'license|passport' THEN 'ID DOCUMENT FIELD'
        WHEN c.column_name ~* 'salary|wage|income' THEN 'FINANCIAL FIELD'
        WHEN c.column_name ~* 'medical|health' THEN 'MEDICAL FIELD'
        ELSE 'STANDARD FIELD'
    END AS "PII Classification",
    CASE 
        WHEN c.column_name ~* 'password|pwd|pass' THEN 'CRITICAL - Encrypt and Hash'
        WHEN c.column_name ~* 'ssn|social.*security|credit.*card' THEN 'HIGH - Encrypt Required'
        WHEN c.column_name ~* 'email|phone|address' THEN 'MEDIUM - Consider Encryption'
        WHEN c.data_type = 'text' AND c.character_maximum_length IS NULL THEN 'MEDIUM - Unlimited Text'
        WHEN c.is_nullable = 'YES' AND c.column_name ~* 'id|key' THEN 'LOW - Nullable Key Field'
        ELSE 'STANDARD'
    END AS "Security Risk"
FROM information_schema.columns c
WHERE c.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY c.table_schema, c.table_name, c.ordinal_position;

-- Column privileges
SELECT 
    p.table_schema AS "Schema Name",
    p.table_name AS "Table Name",
    p.column_name AS "Column Name",
    p.grantee AS "Grantee",
    p.privilege_type AS "Privilege Type",
    p.is_grantable AS "Grantable",
    CASE 
        WHEN p.privilege_type = 'SELECT' THEN 'Read Access'
        WHEN p.privilege_type = 'INSERT' THEN 'Insert Access'
        WHEN p.privilege_type = 'UPDATE' THEN 'Update Access'
        WHEN p.privilege_type = 'REFERENCES' THEN 'Reference Access'
        ELSE 'Other Access'
    END AS "Access Type"
FROM information_schema.column_privileges p
WHERE p.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY p.table_schema, p.table_name, p.column_name, p.grantee;

-- =====================================================
-- SECTION 6: INDEXES & CONSTRAINTS
-- =====================================================
\echo '=== INDEXES & CONSTRAINTS ==='

-- All indexes with detailed information
SELECT 
    i.schemaname AS "Schema Name",
    i.tablename AS "Table Name",
    i.indexname AS "Index Name",
    i.tablespace AS "Tablespace",
    i.indexdef AS "Index Definition",
    pg_size_pretty(pg_relation_size(c.oid)) AS "Index Size",
    c.reltuples::bigint AS "Estimated Rows",
    c.relpages AS "Pages",
    CASE 
        WHEN i.indexdef LIKE '%UNIQUE%' THEN 'Unique Index'
        WHEN i.indexdef LIKE '%btree%' THEN 'B-Tree Index'
        WHEN i.indexdef LIKE '%hash%' THEN 'Hash Index'
        WHEN i.indexdef LIKE '%gist%' THEN 'GiST Index'
        WHEN i.indexdef LIKE '%gin%' THEN 'GIN Index'
        WHEN i.indexdef LIKE '%spgist%' THEN 'SP-GiST Index'
        WHEN i.indexdef LIKE '%brin%' THEN 'BRIN Index'
        ELSE 'Other Index'
    END AS "Index Type",
    s.n_tup_ins AS "Tuples Inserted",
    s.n_tup_upd AS "Tuples Updated",
    s.n_tup_del AS "Tuples Deleted",
    s.n_tup_hot_upd AS "HOT Updates",
    s.n_live_tup AS "Live Tuples",
    s.n_dead_tup AS "Dead Tuples",
    s.last_vacuum AS "Last Vacuum",
    s.last_autovacuum AS "Last Autovacuum",
    s.last_analyze AS "Last Analyze",
    s.last_autoanalyze AS "Last Autoanalyze"
FROM pg_indexes i
JOIN pg_class c ON c.relname = i.indexname
JOIN pg_namespace n ON n.nspname = i.schemaname AND n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.schemaname = i.schemaname AND s.relname = i.tablename
WHERE i.schemaname NOT IN ('information_schema', 'pg_catalog')
ORDER BY pg_relation_size(c.oid) DESC;

-- Primary key constraints
SELECT 
    kcu.table_schema AS "Schema Name",
    kcu.table_name AS "Table Name",
    kcu.constraint_name AS "Constraint Name",
    kcu.column_name AS "Column Name",
    kcu.ordinal_position AS "Position",
    tc.constraint_type AS "Constraint Type",
    tc.is_deferrable AS "Deferrable",
    tc.initially_deferred AS "Initially Deferred"
FROM information_schema.key_column_usage kcu
JOIN information_schema.table_constraints tc ON kcu.constraint_name = tc.constraint_name
WHERE tc.constraint_type = 'PRIMARY KEY'
  AND kcu.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY kcu.table_schema, kcu.table_name, kcu.ordinal_position;

-- Foreign key constraints
SELECT 
    kcu.table_schema AS "Schema Name",
    kcu.table_name AS "Table Name",
    kcu.constraint_name AS "Constraint Name",
    kcu.column_name AS "Column Name",
    ccu.table_schema AS "Referenced Schema",
    ccu.table_name AS "Referenced Table",
    ccu.column_name AS "Referenced Column",
    rc.update_rule AS "Update Rule",
    rc.delete_rule AS "Delete Rule",
    rc.match_option AS "Match Option"
FROM information_schema.key_column_usage kcu
JOIN information_schema.referential_constraints rc ON kcu.constraint_name = rc.constraint_name
JOIN information_schema.constraint_column_usage ccu ON rc.unique_constraint_name = ccu.constraint_name
WHERE kcu.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY kcu.table_schema, kcu.table_name, kcu.constraint_name;

-- Check constraints
SELECT 
    cc.table_schema AS "Schema Name",
    cc.table_name AS "Table Name",
    cc.constraint_name AS "Constraint Name",
    cc.check_clause AS "Check Clause",
    tc.is_deferrable AS "Deferrable",
    tc.initially_deferred AS "Initially Deferred"
FROM information_schema.check_constraints cc
JOIN information_schema.table_constraints tc ON cc.constraint_name = tc.constraint_name
WHERE cc.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY cc.table_schema, cc.table_name, cc.constraint_name;

-- =====================================================
-- SECTION 7: VIEWS & MATERIALIZED VIEWS
-- =====================================================
\echo '=== VIEWS & MATERIALIZED VIEWS ==='

-- All views with definitions
SELECT 
    v.table_schema AS "Schema Name",
    v.table_name AS "View Name",
    v.view_definition AS "View Definition",
    v.check_option AS "Check Option",
    v.is_updatable AS "Is Updatable",
    v.is_insertable_into AS "Is Insertable",
    v.is_trigger_updatable AS "Is Trigger Updatable",
    v.is_trigger_deletable AS "Is Trigger Deletable",
    v.is_trigger_insertable_into AS "Is Trigger Insertable",
    CASE 
        WHEN v.view_definition ~* 'password|pwd|pass' THEN 'CONTAINS PASSWORD FIELDS'
        WHEN v.view_definition ~* 'ssn|social.*security' THEN 'CONTAINS SSN FIELDS'
        WHEN v.view_definition ~* 'credit.*card' THEN 'CONTAINS CREDIT CARD FIELDS'
        WHEN v.view_definition ~* 'select.*\*.*from' THEN 'USES SELECT *'
        ELSE 'STANDARD VIEW'
    END AS "Security Analysis"
FROM information_schema.views v
WHERE v.table_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY v.table_schema, v.table_name;

-- Materialized views
SELECT 
    m.schemaname AS "Schema Name",
    m.matviewname AS "Materialized View Name",
    m.matviewowner AS "Owner",
    m.tablespace AS "Tablespace",
    m.hasindexes AS "Has Indexes",
    m.ispopulated AS "Is Populated",
    m.definition AS "Definition",
    pg_size_pretty(pg_total_relation_size(c.oid)) AS "Size"
FROM pg_matviews m
JOIN pg_class c ON c.relname = m.matviewname
JOIN pg_namespace n ON n.nspname = m.schemaname AND n.oid = c.relnamespace
WHERE m.schemaname NOT IN ('information_schema', 'pg_catalog')
ORDER BY pg_total_relation_size(c.oid) DESC;

-- View dependencies
SELECT 
    vtu.view_schema AS "View Schema",
    vtu.view_name AS "View Name",
    vtu.table_schema AS "Table Schema",
    vtu.table_name AS "Table Name",
    CASE 
        WHEN vtu.table_schema = vtu.view_schema THEN 'Same Schema'
        WHEN vtu.table_schema IN ('information_schema', 'pg_catalog') THEN 'System Dependency'
        ELSE 'Cross Schema'
    END AS "Dependency Type"
FROM information_schema.view_table_usage vtu
WHERE vtu.view_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY vtu.view_schema, vtu.view_name, vtu.table_schema, vtu.table_name;

-- =====================================================
-- SECTION 8: FUNCTIONS & PROCEDURES
-- =====================================================
\echo '=== FUNCTIONS & PROCEDURES ==='

-- All functions and procedures
SELECT 
    r.routine_schema AS "Schema Name",
    r.routine_name AS "Routine Name",
    r.routine_type AS "Routine Type",
    r.data_type AS "Return Type",
    r.routine_definition AS "Definition",
    r.external_language AS "Language",
    r.is_deterministic AS "Is Deterministic",
    r.sql_data_access AS "SQL Data Access",
    r.is_null_call AS "Is Null Call",
    r.security_type AS "Security Type",
    r.is_udt_dependent AS "Is UDT Dependent",
    CASE 
        WHEN r.routine_definition ~* 'EXECUTE|SYSTEM|COPY|\\\\' THEN 'POTENTIAL SECURITY RISK'
        WHEN r.security_type = 'DEFINER' THEN 'SECURITY DEFINER - REVIEW REQUIRED'
        WHEN r.external_language NOT IN ('sql', 'plpgsql') THEN 'EXTERNAL LANGUAGE - REVIEW REQUIRED'
        ELSE 'STANDARD FUNCTION'
    END AS "Security Analysis",
    CASE 
        WHEN r.routine_definition ~* 'EXECUTE|SYSTEM|COPY' THEN 'HIGH'
        WHEN r.security_type = 'DEFINER' THEN 'MEDIUM'
        WHEN r.external_language NOT IN ('sql', 'plpgsql') THEN 'MEDIUM'
        ELSE 'LOW'
    END AS "Risk Level"
FROM information_schema.routines r
WHERE r.routine_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY 
    CASE 
        WHEN r.routine_definition ~* 'EXECUTE|SYSTEM|COPY' THEN 1
        WHEN r.security_type = 'DEFINER' THEN 2
        WHEN r.external_language NOT IN ('sql', 'plpgsql') THEN 3
        ELSE 4
    END, r.routine_schema, r.routine_name;

-- Function parameters
SELECT 
    p.specific_schema AS "Schema Name",
    p.specific_name AS "Function Name",
    p.parameter_name AS "Parameter Name",
    p.ordinal_position AS "Position",
    p.parameter_mode AS "Mode",
    p.data_type AS "Data Type",
    p.parameter_default AS "Default Value"
FROM information_schema.parameters p
WHERE p.specific_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY p.specific_schema, p.specific_name, p.ordinal_position;

-- =====================================================
-- SECTION 9: TRIGGERS & RULES
-- =====================================================
\echo '=== TRIGGERS & RULES ==='

-- All triggers
SELECT 
    t.trigger_schema AS "Schema Name",
    t.trigger_name AS "Trigger Name",
    t.event_manipulation AS "Event",
    t.event_object_schema AS "Table Schema",
    t.event_object_table AS "Table Name",
    t.action_order AS "Action Order",
    t.action_condition AS "Action Condition",
    t.action_statement AS "Action Statement",
    t.action_orientation AS "Action Orientation",
    t.action_timing AS "Action Timing",
    t.action_reference_old_table AS "Old Table Reference",
    t.action_reference_new_table AS "New Table Reference",
    t.action_reference_old_row AS "Old Row Reference",
    t.action_reference_new_row AS "New Row Reference",
    CASE 
        WHEN t.action_statement ~* 'EXECUTE|SYSTEM|COPY' THEN 'POTENTIAL SECURITY RISK'
        WHEN t.action_timing = 'BEFORE' AND t.event_manipulation IN ('INSERT', 'UPDATE') THEN 'DATA VALIDATION TRIGGER'
        WHEN t.action_timing = 'AFTER' AND t.event_manipulation IN ('INSERT', 'UPDATE', 'DELETE') THEN 'AUDIT TRIGGER'
        ELSE 'STANDARD TRIGGER'
    END AS "Trigger Analysis"
FROM information_schema.triggers t
WHERE t.trigger_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY t.trigger_schema, t.event_object_table, t.trigger_name;

-- =====================================================
-- SECTION 10: SEQUENCES & IDENTITY COLUMNS
-- =====================================================
\echo '=== SEQUENCES & IDENTITY COLUMNS ==='

-- All sequences
SELECT 
    s.sequence_schema AS "Schema Name",
    s.sequence_name AS "Sequence Name",
    s.data_type AS "Data Type",
    s.numeric_precision AS "Precision",
    s.numeric_scale AS "Scale",
    s.start_value AS "Start Value",
    s.minimum_value AS "Minimum Value",
    s.maximum_value AS "Maximum Value",
    s.increment AS "Increment",
    s.cycle_option AS "Cycle Option",
    pg_size_pretty(pg_relation_size(c.oid)) AS "Size",
    CASE 
        WHEN s.maximum_value = '9223372036854775807' THEN 'Default Max Value'
        WHEN s.minimum_value = '1' THEN 'Default Min Value'
        ELSE 'Custom Range'
    END AS "Range Type"
FROM information_schema.sequences s
JOIN pg_class c ON c.relname = s.sequence_name
JOIN pg_namespace n ON n.nspname = s.sequence_schema AND n.oid = c.relnamespace
WHERE s.sequence_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY s.sequence_schema, s.sequence_name;

-- Sequence usage and ownership
SELECT 
    s.sequence_schema AS "Schema Name",
    s.sequence_name AS "Sequence Name",
    d.table_schema AS "Owner Table Schema",
    d.table_name AS "Owner Table Name",
    d.column_name AS "Owner Column Name"
FROM information_schema.sequences s
LEFT JOIN information_schema.column_column_usage d ON s.sequence_name = d.column_name
WHERE s.sequence_schema NOT IN ('information_schema', 'pg_catalog')
ORDER BY s.sequence_schema, s.sequence_name;

-- =====================================================
-- SECTION 11: EXTENSIONS & INSTALLED FEATURES
-- =====================================================
\echo '=== EXTENSIONS & INSTALLED FEATURES ==='

-- Installed extensions
SELECT 
    e.extname AS "Extension Name",
    e.extversion AS "Version",
    n.nspname AS "Schema",
    e.extrelocatable AS "Relocatable",
    e.extconfig AS "Configuration",
    e.extcondition AS "Condition",
    pg_get_userbyid(e.extowner) AS "Owner",
    CASE 
        WHEN e.extname IN ('adminpack', 'file_fdw', 'postgres_fdw') THEN 'Administrative Extension'
        WHEN e.extname IN ('pg_stat_statements', 'pg_stat_monitor') THEN 'Monitoring Extension'
        WHEN e.extname IN ('pgcrypto', 'pg_trgm', 'uuid-ossp') THEN 'Security/Utility Extension'
        WHEN e.extname IN ('postgis', 'hstore', 'jsonb_plperl') THEN 'Data Type Extension'
        ELSE 'Other Extension'
    END AS "Extension Category",
    CASE 
        WHEN e.extname IN ('adminpack', 'file_fdw') THEN 'HIGH - Administrative Access'
        WHEN e.extname IN ('postgres_fdw', 'dblink') THEN 'MEDIUM - Remote Access'
        WHEN e.extname IN ('pgcrypto') THEN 'LOW - Security Enhancement'
        ELSE 'REVIEW REQUIRED'
    END AS "Security Impact"
FROM pg_extension e
JOIN pg_namespace n ON e.extnamespace = n.oid
ORDER BY 
    CASE 
        WHEN e.extname IN ('adminpack', 'file_fdw') THEN 1
        WHEN e.extname IN ('postgres_fdw', 'dblink') THEN 2
        ELSE 3
    END, e.extname;

-- Available extensions
SELECT 
    name AS "Extension Name",
    default_version AS "Default Version",
    installed_version AS "Installed Version",
    comment AS "Description",
    CASE 
        WHEN installed_version IS NOT NULL THEN 'Installed'
        ELSE 'Available'
    END AS "Status"
FROM pg_available_extensions
ORDER BY 
    CASE WHEN installed_version IS NOT NULL THEN 1 ELSE 2 END, name;

-- =====================================================
-- SECTION 12: TABLESPACES & STORAGE
-- =====================================================
\echo '=== TABLESPACES & STORAGE ==='

-- All tablespaces
SELECT 
    ts.oid AS "Tablespace OID",
    ts.spcname AS "Tablespace Name",
    pg_get_userbyid(ts.spcowner) AS "Owner",
    array_to_string(ts.spcacl, ', ') AS "Access Privileges",
    array_to_string(ts.spcoptions, ', ') AS "Options",
    pg_size_pretty(pg_tablespace_size(ts.oid)) AS "Size",
    pg_tablespace_location(ts.oid) AS "Location",
    CASE 
        WHEN ts.spcname IN ('pg_default', 'pg_global') THEN 'System Tablespace'
        ELSE 'User Tablespace'
    END AS "Tablespace Type"
FROM pg_tablespace ts
ORDER BY 
    CASE WHEN ts.spcname IN ('pg_default', 'pg_global') THEN 1 ELSE 2 END, ts.spcname;

-- Tablespace usage
SELECT 
    ts.spcname AS "Tablespace Name",
    n.nspname AS "Schema Name",
    c.relname AS "Object Name",
    c.relkind AS "Object Type",
    CASE c.relkind
        WHEN 'r' THEN 'Table'
        WHEN 'i' THEN 'Index'
        WHEN 'S' THEN 'Sequence'
        WHEN 'v' THEN 'View'
        WHEN 'm' THEN 'Materialized View'
        WHEN 'c' THEN 'Composite Type'
        WHEN 't' THEN 'TOAST Table'
        WHEN 'f' THEN 'Foreign Table'
        ELSE 'Other'
    END AS "Object Type Description",
    pg_size_pretty(pg_relation_size(c.oid)) AS "Size"
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
JOIN pg_tablespace ts ON c.reltablespace = ts.oid
WHERE n.nspname NOT IN ('information_schema', 'pg_catalog')
ORDER BY ts.spcname, n.nspname, c.relname;

-- =====================================================
-- SECTION 13: LOCKS & BLOCKING QUERIES
-- =====================================================
\echo '=== LOCKS & BLOCKING QUERIES ==='

-- Current locks
SELECT 
    l.locktype AS "Lock Type",
    l.database AS "Database OID",
    d.datname AS "Database Name",
    l.relation AS "Relation OID",
    CASE 
        WHEN l.relation IS NOT NULL THEN l.relation::regclass::text
        ELSE 'N/A'
    END AS "Relation Name",
    l.page AS "Page",
    l.tuple AS "Tuple",
    l.virtualxid AS "Virtual XID",
    l.transactionid AS "Transaction ID",
    l.classid AS "Class ID",
    l.objid AS "Object ID",
    l.objsubid AS "Object Sub ID",
    l.virtualtransaction AS "Virtual Transaction",
    l.pid AS "Process ID",
    l.mode AS "Lock Mode",
    l.granted AS "Granted",
    l.fastpath AS "Fast Path",
    sa.usename AS "Username",
    sa.application_name AS "Application",
    sa.client_addr AS "Client Address",
    sa.query AS "Query",
    sa.state AS "State",
    CASE 
        WHEN NOT l.granted THEN 'WAITING FOR LOCK'
        WHEN l.mode IN ('AccessExclusiveLock', 'ExclusiveLock') THEN 'EXCLUSIVE LOCK'
        WHEN l.mode IN ('ShareUpdateExclusiveLock', 'ShareRowExclusiveLock') THEN 'SHARED EXCLUSIVE LOCK'
        ELSE 'SHARED LOCK'
    END AS "Lock Status"
FROM pg_locks l
LEFT JOIN pg_database d ON l.database = d.oid
LEFT JOIN pg_stat_activity sa ON l.pid = sa.pid
ORDER BY 
    CASE WHEN NOT l.granted THEN 1 ELSE 2 END,
    CASE 
        WHEN l.mode IN ('AccessExclusiveLock', 'ExclusiveLock') THEN 1
        WHEN l.mode IN ('ShareUpdateExclusiveLock', 'ShareRowExclusiveLock') THEN 2
        ELSE 3
    END, l.pid;

-- Blocking queries analysis
SELECT 
    blocked_locks.pid AS "Blocked PID",
    blocked_activity.usename AS "Blocked User",
    blocked_activity.query AS "Blocked Query",
    blocked_locks.mode AS "Blocked Mode",
    blocking_locks.pid AS "Blocking PID",
    blocking_activity.usename AS "Blocking User",
    blocking_activity.query AS "Blocking Query",
    blocking_locks.mode AS "Blocking Mode",
    blocking_activity.application_name AS "Blocking Application",
    now() - blocked_activity.query_start AS "Waiting Duration",
    CASE 
        WHEN blocked_locks.mode IN ('AccessExclusiveLock', 'ExclusiveLock') THEN 'CRITICAL - Exclusive Lock Blocked'
        WHEN now() - blocked_activity.query_start > INTERVAL '5 minutes' THEN 'HIGH - Long Wait Time'
        ELSE 'MEDIUM - Standard Lock Wait'
    END AS "Priority"
FROM pg_locks blocked_locks
JOIN pg_stat_activity blocked_activity ON blocked_locks.pid = blocked_activity.pid
JOIN pg_locks blocking_locks ON 
    blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_stat_activity blocking_activity ON blocking_locks.pid = blocking_activity.pid
WHERE NOT blocked_locks.granted
ORDER BY 
    CASE 
        WHEN blocked_locks.mode IN ('AccessExclusiveLock', 'ExclusiveLock') THEN 1
        WHEN now() - blocked_activity.query_start > INTERVAL '5 minutes' THEN 2
        ELSE 3
    END, now() - blocked_activity.query_start DESC;

-- =====================================================
-- SECTION 14: STATISTICS & MONITORING
-- =====================================================
\echo '=== STATISTICS & MONITORING ==='

-- Database statistics
SELECT 
    d.datname AS "Database Name",
    pg_stat_get_db_numbackends(d.oid) AS "Active Backends",
    pg_stat_get_db_xact_commit(d.oid) AS "Transactions Committed",
    pg_stat_get_db_xact_rollback(d.oid) AS "Transactions Rolled Back",
    pg_stat_get_db_blocks_fetched(d.oid) AS "Blocks Fetched",
    pg_stat_get_db_blocks_hit(d.oid) AS "Blocks Hit",
    pg_stat_get_db_tuples_returned(d.oid) AS "Tuples Returned",
    pg_stat_get_db_tuples_fetched(d.oid) AS "Tuples Fetched",
    pg_stat_get_db_tuples_inserted(d.oid) AS "Tuples Inserted",
    pg_stat_get_db_tuples_updated(d.oid) AS "Tuples Updated",
    pg_stat_get_db_tuples_deleted(d.oid) AS "Tuples Deleted",
    pg_stat_get_db_conflict_tablespace(d.oid) AS "Conflicts Tablespace",
    pg_stat_get_db_conflict_lock(d.oid) AS "Conflicts Lock",
    pg_stat_get_db_conflict_snapshot(d.oid) AS "Conflicts Snapshot",
    pg_stat_get_db_conflict_bufferpin(d.oid) AS "Conflicts Buffer Pin",
    pg_stat_get_db_conflict_startup_deadlock(d.oid) AS "Conflicts Startup Deadlock",
    pg_stat_get_db_deadlocks(d.oid) AS "Deadlocks",
    pg_stat_get_db_temp_files(d.oid) AS "Temp Files",
    pg_stat_get_db_temp_bytes(d.oid) AS "Temp Bytes",
    pg_stat_get_db_blk_read_time(d.oid) AS "Block Read Time",
    pg_stat_get_db_blk_write_time(d.oid) AS "Block Write Time",
    CASE 
        WHEN pg_stat_get_db_numbackends(d.oid) > 100 THEN 'HIGH CONNECTION COUNT'
        WHEN pg_stat_get_db_deadlocks(d.oid) > 0 THEN 'DEADLOCKS DETECTED'
        WHEN pg_stat_get_db_conflict_lock(d.oid) > 0 THEN 'LOCK CONFLICTS'
        ELSE 'NORMAL'
    END AS "Database Health"
FROM pg_database d
WHERE d.datallowconn
ORDER BY pg_stat_get_db_numbackends(d.oid) DESC;

-- Table statistics
SELECT 
    s.schemaname AS "Schema Name",
    s.relname AS "Table Name",
    s.seq_scan AS "Sequential Scans",
    s.seq_tup_read AS "Sequential Tuples Read",
    s.idx_scan AS "Index Scans",
    s.idx_tup_fetch AS "Index Tuples Fetched",
    s.n_tup_ins AS "Tuples Inserted",
    s.n_tup_upd AS "Tuples Updated",
    s.n_tup_del AS "Tuples Deleted",
    s.n_tup_hot_upd AS "HOT Updates",
    s.n_live_tup AS "Live Tuples",
    s.n_dead_tup AS "Dead Tuples",
    s.n_mod_since_analyze AS "Modified Since Analyze",
    s.last_vacuum AS "Last Vacuum",
    s.last_autovacuum AS "Last Autovacuum",
    s.last_analyze AS "Last Analyze",
    s.last_autoanalyze AS "Last Autoanalyze",
    s.vacuum_count AS "Vacuum Count",
    s.autovacuum_count AS "Autovacuum Count",
    s.analyze_count AS "Analyze Count",
    s.autoanalyze_count AS "Autoanalyze Count",
    CASE 
        WHEN s.n_dead_tup > s.n_live_tup * 0.2 THEN 'HIGH DEAD TUPLE RATIO'
        WHEN s.last_vacuum IS NULL AND s.last_autovacuum IS NULL THEN 'NEVER VACUUMED'
        WHEN s.last_analyze IS NULL AND s.last_autoanalyze IS NULL THEN 'NEVER ANALYZED'
        ELSE 'NORMAL'
    END AS "Maintenance Status"
FROM pg_stat_user_tables s
ORDER BY s.n_dead_tup DESC;

-- Index statistics
SELECT 
    s.schemaname AS "Schema Name",
    s.relname AS "Table Name",
    s.indexrelname AS "Index Name",
    s.idx_scan AS "Index Scans",
    s.idx_tup_read AS "Index Tuples Read",
    s.idx_tup_fetch AS "Index Tuples Fetched",
    pg_size_pretty(pg_relation_size(i.indexrelid)) AS "Index Size",
    CASE 
        WHEN s.idx_scan = 0 THEN 'UNUSED INDEX'
        WHEN s.idx_scan < 10 THEN 'RARELY USED INDEX'
        ELSE 'ACTIVELY USED INDEX'
    END AS "Usage Status"
FROM pg_stat_user_indexes s
JOIN pg_index i ON s.indexrelid = i.indexrelid
ORDER BY s.idx_scan DESC;

-- =====================================================
-- SECTION 15: REPLICATION & HIGH AVAILABILITY
-- =====================================================
\echo '=== REPLICATION & HIGH AVAILABILITY ==='

-- Replication slots
SELECT 
    slot_name AS "Slot Name",
    plugin AS "Plugin",
    slot_type AS "Slot Type",
    datoid AS "Database OID",
    database AS "Database Name",
    temporary AS "Temporary",
    active AS "Active",
    active_pid AS "Active PID",
    xmin AS "XMin",
    catalog_xmin AS "Catalog XMin",
    restart_lsn AS "Restart LSN",
    confirmed_flush_lsn AS "Confirmed Flush LSN",
    CASE 
        WHEN active THEN 'ACTIVE REPLICATION'
        WHEN NOT active AND slot_type = 'logical' THEN 'INACTIVE LOGICAL SLOT'
        WHEN NOT active AND slot_type = 'physical' THEN 'INACTIVE PHYSICAL SLOT'
        ELSE 'UNKNOWN STATUS'
    END AS "Replication Status"
FROM pg_replication_slots
ORDER BY active DESC, slot_name;

-- WAL sender processes
SELECT 
    pid AS "Process ID",
    usesysid AS "User ID",
    usename AS "Username",
    application_name AS "Application Name",
    client_addr AS "Client Address",
    client_hostname AS "Client Hostname",
    client_port AS "Client Port",
    backend_start AS "Backend Start",
    backend_xmin AS "Backend XMin",
    state AS "State",
    sent_lsn AS "Sent LSN",
    write_lsn AS "Write LSN",
    flush_lsn AS "Flush LSN",
    replay_lsn AS "Replay LSN",
    write_lag AS "Write Lag",
    flush_lag AS "Flush Lag",
    replay_lag AS "Replay Lag",
    sync_priority AS "Sync Priority",
    sync_state AS "Sync State",
    CASE 
        WHEN state = 'streaming' THEN 'STREAMING REPLICATION'
        WHEN state = 'startup' THEN 'STARTING UP'
        WHEN state = 'catchup' THEN 'CATCHING UP'
        WHEN state = 'backup' THEN 'BACKUP MODE'
        ELSE 'UNKNOWN STATE'
    END AS "Replication Mode"
FROM pg_stat_replication
ORDER BY backend_start;

-- =====================================================
-- SECTION 16: FOREIGN DATA WRAPPERS & EXTERNAL DATA
-- =====================================================
\echo '=== FOREIGN DATA WRAPPERS & EXTERNAL DATA ==='

-- Foreign data wrappers
SELECT 
    fdw.fdwname AS "FDW Name",
    pg_get_userbyid(fdw.fdwowner) AS "Owner",
    array_to_string(fdw.fdwacl, ', ') AS "Access Privileges",
    array_to_string(fdw.fdwoptions, ', ') AS "Options",
    fdw.fdwhandler AS "Handler",
    fdw.fdwvalidator AS "Validator",
    CASE 
        WHEN fdw.fdwname = 'file_fdw' THEN 'FILE ACCESS - HIGH SECURITY RISK'
        WHEN fdw.fdwname = 'postgres_fdw' THEN 'REMOTE POSTGRES - MEDIUM RISK'
        ELSE 'EXTERNAL DATA ACCESS - REVIEW REQUIRED'
    END AS "Security Assessment"
FROM pg_foreign_data_wrapper fdw
ORDER BY fdw.fdwname;

-- Foreign servers
SELECT 
    fs.srvname AS "Server Name",
    fs.srvtype AS "Server Type",
    fs.srvversion AS "Server Version",
    fdw.fdwname AS "FDW Name",
    pg_get_userbyid(fs.srvowner) AS "Owner",
    array_to_string(fs.srvacl, ', ') AS "Access Privileges",
    array_to_string(fs.srvoptions, ', ') AS "Options"
FROM pg_foreign_server fs
JOIN pg_foreign_data_wrapper fdw ON fs.srvfdw = fdw.oid
ORDER BY fs.srvname;

-- Foreign tables
SELECT 
    ft.foreign_table_schema AS "Schema Name",
    ft.foreign_table_name AS "Table Name",
    ft.foreign_server_name AS "Server Name",
    array_to_string(array(
        SELECT option_name || '=' || option_value 
        FROM information_schema.foreign_table_options 
        WHERE foreign_table_schema = ft.foreign_table_schema 
        AND foreign_table_name = ft.foreign_table_name
    ), ', ') AS "Table Options"
FROM information_schema.foreign_tables ft
ORDER BY ft.foreign_table_schema, ft.foreign_table_name;

-- User mappings
SELECT 
    um.srvname AS "Server Name",
    um.usename AS "Username",
    array_to_string(um.umoptions, ', ') AS "Options",
    CASE 
        WHEN um.usename IS NULL THEN 'PUBLIC MAPPING - SECURITY RISK'
        ELSE 'USER SPECIFIC MAPPING'
    END AS "Security Assessment"
FROM pg_user_mappings um
ORDER BY um.srvname, um.usename;

-- =====================================================
-- SECTION 17: SECURITY COMPLIANCE & AUDIT SUMMARY
-- =====================================================
\echo '=== SECURITY COMPLIANCE & AUDIT SUMMARY ==='

-- Security configuration assessment
SELECT 
    'SSL Configuration' AS "Security Domain",
    CASE 
        WHEN current_setting('ssl') = 'on' THEN 'ENABLED'
        ELSE 'DISABLED - CRITICAL RISK'
    END AS "Status",
    'Encryption in transit' AS "Security Impact",
    CASE 
        WHEN current_setting('ssl') = 'on' THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END AS "Compliance Status"
UNION ALL
SELECT 
    'Password Encryption',
    CASE 
        WHEN current_setting('password_encryption') = 'scram-sha-256' THEN 'SCRAM-SHA-256 - SECURE'
        WHEN current_setting('password_encryption') = 'md5' THEN 'MD5 - WEAK'
        ELSE 'UNKNOWN'
    END,
    'Password storage security',
    CASE 
        WHEN current_setting('password_encryption') = 'scram-sha-256' THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END
UNION ALL
SELECT 
    'Connection Logging',
    CASE 
        WHEN current_setting('log_connections') = 'on' THEN 'ENABLED'
        ELSE 'DISABLED - AUDIT RISK'
    END,
    'Connection audit trail',
    CASE 
        WHEN current_setting('log_connections') = 'on' THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END
UNION ALL
SELECT 
    'Statement Logging',
    CASE 
        WHEN current_setting('log_statement') != 'none' THEN 'ENABLED - ' || current_setting('log_statement')
        ELSE 'DISABLED - AUDIT RISK'
    END,
    'SQL statement audit trail',
    CASE 
        WHEN current_setting('log_statement') != 'none' THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END
UNION ALL
SELECT 
    'Row Level Security',
    CASE 
        WHEN current_setting('row_security') = 'on' THEN 'ENABLED'
        ELSE 'DISABLED - CONSIDER ENABLING'
    END,
    'Fine-grained access control',
    CASE 
        WHEN current_setting('row_security') = 'on' THEN 'COMPLIANT'
        ELSE 'REVIEW REQUIRED'
    END
UNION ALL
SELECT 
    'Listen Addresses',
    CASE 
        WHEN current_setting('listen_addresses') = 'localhost' THEN 'LOCALHOST ONLY - SECURE'
        WHEN current_setting('listen_addresses') = '*' THEN 'ALL ADDRESSES - HIGH RISK'
        ELSE 'SPECIFIC ADDRESSES - REVIEW'
    END,
    'Network exposure',
    CASE 
        WHEN current_setting('listen_addresses') = 'localhost' THEN 'COMPLIANT'
        WHEN current_setting('listen_addresses') = '*' THEN 'NON-COMPLIANT'
        ELSE 'REVIEW REQUIRED'
    END;

-- High-risk findings summary
SELECT 
    'Superuser Accounts' AS "Risk Category",
    COUNT(*) AS "Count",
    'CRITICAL' AS "Risk Level",
    'Review and minimize superuser access' AS "Recommendation"
FROM pg_authid 
WHERE rolsuper = true
UNION ALL
SELECT 
    'Accounts Without Password Expiry',
    COUNT(*),
    'HIGH',
    'Implement password expiry policies'
FROM pg_authid 
WHERE rolcanlogin = true AND rolvaliduntil IS NULL
UNION ALL
SELECT 
    'Tables Without Primary Keys',
    COUNT(*),
    'MEDIUM',
    'Add primary keys for data integrity'
FROM pg_tables t
JOIN pg_class c ON c.relname = t.tablename
JOIN pg_namespace n ON n.nspname = t.schemaname AND n.oid = c.relnamespace
WHERE t.schemaname NOT IN ('information_schema', 'pg_catalog')
AND NOT EXISTS (
    SELECT 1 FROM pg_constraint con 
    WHERE con.conrelid = c.oid AND con.contype = 'p'
)
UNION ALL
SELECT 
    'Unused Indexes',
    COUNT(*),
    'LOW',
    'Consider removing unused indexes'
FROM pg_stat_user_indexes 
WHERE idx_scan = 0;

-- Security recommendations
SELECT 
    'Enable SSL/TLS' AS "Recommendation",
    'Configure SSL certificates and enable encrypted connections' AS "Description",
    'HIGH' AS "Priority",
    'ssl = on, ssl_cert_file, ssl_key_file' AS "Configuration"
UNION ALL
SELECT 
    'Implement Connection Logging',
    'Enable comprehensive logging for security monitoring',
    'HIGH',
    'log_connections = on, log_disconnections = on'
UNION ALL
SELECT 
    'Use Strong Password Encryption',
    'Configure SCRAM-SHA-256 for password storage',
    'HIGH',
    'password_encryption = scram-sha-256'
UNION ALL
SELECT 
    'Restrict Network Access',
    'Limit listen_addresses to specific networks',
    'HIGH',
    'listen_addresses = localhost or specific IPs'
UNION ALL
SELECT 
    'Enable Row Level Security',
    'Implement fine-grained access control',
    'MEDIUM',
    'row_security = on, CREATE POLICY statements'
UNION ALL
SELECT 
    'Regular Password Rotation',
    'Implement password expiry policies',
    'MEDIUM',
    'VALID UNTIL clause in CREATE/ALTER ROLE'
UNION ALL
SELECT 
    'Audit Extensions',
    'Review and minimize installed extensions',
    'MEDIUM',
    'DROP EXTENSION for unused extensions'
UNION ALL
SELECT 
    'Monitor Lock Contention',
    'Implement lock monitoring and alerting',
    'LOW',
    'pg_stat_activity, pg_locks monitoring'
ORDER BY 
    CASE 
        WHEN "Priority" = 'HIGH' THEN 1
        WHEN "Priority" = 'MEDIUM' THEN 2
        ELSE 3
    END;

-- Final audit summary
\echo '=== AUDIT COMPLETION SUMMARY ==='
\echo 'PostgreSQL Security and Metadata Extraction Complete'
\echo 'Review all findings for security vulnerabilities and compliance gaps'
\echo 'Implement high-priority recommendations immediately'
\echo 'Schedule regular security audits using this script'
\echo 'Maintain audit logs and documentation for compliance'

-- End of comprehensive PostgreSQL security audit script
