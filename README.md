# 🛡️ PostgreSQL Complete Security & Metadata Extraction Script

**A comprehensive A-Z database security audit and analysis tool**  
*Originally created by **srikqr** from scratch*

Compatible with PostgreSQL 12+ - All Distributions  
Single-file, zero-dependency security audit script

## 📋 What This Script Does

This script performs a complete security audit and metadata extraction of your PostgreSQL database, covering:

- **17 Security Domains**: Authentication, authorization, schemas, tables, indexes, functions, triggers, replication, and more
- **Comprehensive Analysis**: Server configuration, user privileges, data types, storage, locks, statistics
- **Security Risk Assessment**: Identifies potential vulnerabilities and compliance gaps
- **Detailed Reporting**: Color-coded risk levels and actionable recommendations

## 🚀 Quick Start

### Basic Usage
```bash
psql -f postgres_audit_extended.sql
```

### With Connection Parameters
```bash
psql -h <hostname> -p <port> -U <username> -d <database> -f postgres_audit_extended.sql
```

### Save Output to File
```bash
psql -h <hostname> -p <port> -U <username> -d <database> \
     -f postgres_audit_extended.sql \
     -o security_audit_$(date +%Y%m%d_%H%M).txt
```

## 💻 Usage Examples

### 1. Local Database Audit
```bash
# Audit local PostgreSQL instance
psql -U postgres -f postgres_audit_extended.sql
```

### 2. Remote Database Audit with Output
```bash
# Audit remote database and save timestamped report
psql -h db.example.com -p 5432 -U auditor -d production \
     -f postgres_audit_extended.sql \
     -o audit_report_$(date +%F_%H%M).txt
```

### 3. Automated/Scheduled Audit
```bash
# For cron jobs or automation (quiet mode)
psql -h <host> -U <user> -d <database> \
     -f postgres_audit_extended.sql \
     -q -v ON_ERROR_STOP=1 \
     -o /var/log/pg_audit/daily_audit.txt
```

### 4. Interactive Mode with Redirection
```bash
# Run interactively with output redirection
psql -U postgres
\o audit_output.txt
\i postgres_audit_extended.sql
\o
\q
```

## 📊 Script Output

The script generates organized output with:

- **Section Headers**: Clear markers like `=== AUTHENTICATION & AUTHORIZATION ===`
- **Risk Levels**: CRITICAL, HIGH, MEDIUM, LOW classifications
- **Security Assessments**: Immediate security status for each component
- **Compliance Status**: COMPLIANT/NON-COMPLIANT indicators
- **Recommendations**: Actionable security improvements

## 🔧 Command Options Explained

| Option | Description | Example |
|--------|-------------|---------|
| `-f` | Execute SQL file | `-f postgres_audit_extended.sql` |
| `-o` | Output to file | `-o audit_report.txt` |
| `-h` | Database host | `-h db.example.com` |
| `-p` | Port number | `-p 5432` |
| `-U` | Username | `-U auditor` |
| `-d` | Database name | `-d production` |
| `-q` | Quiet mode (no banners) | `-q` |
| `-v ON_ERROR_STOP=1` | Stop on first error | For automation safety |

## 📝 Sample Commands

### Development Environment
```bash
psql -U developer -d myapp_dev -f postgres_audit_extended.sql -o dev_audit.txt
```

### Production Environment (Secure)
```bash
PGPASSWORD=$DB_PASSWORD psql -h prod-db.company.com -U readonly_auditor \
    -d production -f postgres_audit_extended.sql \
    -o prod_security_audit_$(date +%Y%m%d).txt -q
```

### Docker Container
```bash
docker exec -i postgres_container psql -U postgres \
    -f /scripts/postgres_audit_extended.sql -o /tmp/audit.txt
```

## 🛠️ Prerequisites

- PostgreSQL 12 or higher
- `psql` client installed
- Database connection privileges
- Read access to system catalogs

## 📋 What Gets Audited

1. **Server & Instance Information**
2. **Authentication & Authorization**
3. **Schemas & Namespaces**
4. **Tables & Relations**
5. **Columns & Data Types**
6. **Indexes & Constraints**
7. **Views & Materialized Views**
8. **Functions & Procedures**
9. **Triggers & Rules**
10. **Sequences & Identity Columns**
11. **Extensions & Installed Features**
12. **Tablespaces & Storage**
13. **Locks & Blocking Queries**
14. **Statistics & Monitoring**
15. **Replication & High Availability**
16. **Foreign Data Wrappers**
17. **Security Compliance Summary**

## ⚠️ Important Notes

- **Read-Only**: Script only performs SELECT queries, no data modification
- **Safe to Run**: No impact on database performance or data
- **Comprehensive**: May take several minutes on large databases
- **Network Security**: Be cautious when running on production networks

## 📄 Output File Analysis

The generated report includes:
- Security risk assessments
- Configuration recommendations
- Compliance gap analysis
- Performance insights
- Detailed metadata extraction

## 🔒 Security Best Practices

1. **Secure Connection**: Always use encrypted connections for remote audits
2. **Limited Privileges**: Use read-only accounts when possible
3. **Output Security**: Protect audit reports containing sensitive metadata
4. **Regular Audits**: Run periodic security assessments
5. **Review Findings**: Act on high-priority security recommendations

## 👨‍💻 Author

**Script created from scratch by srikqr**

---

*For questions, issues, or contributions, please refer to the repository documentation.*
