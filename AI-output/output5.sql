```sql
CREATE TABLESPACE ts_bkup_dest DATAFILE '/path/to/ts_bkup_dest.dbf' SIZE 10G AUTOEXTEND ON;

BEGIN
  DBMS_SCHEDULER.CREATE_JOB (
    job_name        => 'DAILY_DB_BACKUP',
    job_type        => 'EXECUTABLE',
    job_action      => '/path/to/backup_script.sh',
    start_date      => SYSDATE,
    repeat_interval => 'FREQ=DAILY',
    enabled         => TRUE
  );
END;
/
```

```bash
#!/bin/bash

ORACLE_SID="YOUR_ORACLE_SID"
BACKUP_DIR="/path/to/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

sqlplus -s /nolog << EOF
CONNECT / AS SYSDBA
expdp system/YOUR_PASSWORD@${ORACLE_SID} directory=DATA_PUMP_DIR dumpfile=full_backup_${TIMESTAMP}.dmp logfile=full_backup_${TIMESTAMP}.log full=y;
EXIT;
EOF
```

**Important:**

* **Replace placeholders:** Update the following placeholders in both scripts:
    * `/path/to/ts_bkup_dest.dbf`: Actual path and filename for the tablespace datafile.
    * `/path/to/backup_script.sh`: Actual path to the bash script file.
    * `YOUR_ORACLE_SID`: Your Oracle SID.
    * `/path/to/backups`: Desired directory to store backup files.
    * `YOUR_PASSWORD`: Your system password.
* **Permissions:** Ensure the Oracle user running the scripts has necessary permissions:
    * Create tablespaces.
    * Create and manage scheduler jobs.
    * Write access to the backup directory.
* **Test thoroughly:** Execute and thoroughly test the scripts in a non-production environment before deploying to production. 
* **Security:**  **Never** hardcode passwords directly in scripts. Use environment variables or other secure methods to manage sensitive information.

```sql
-- Enable RMAN CONTROLFILE AUTOBACKUP
SHOW PARAMETER CONTROL_FILE_AUTOBACKUP_FORMAT;

ALTER SYSTEM SET CONTROL_FILE_AUTOBACKUP_FORMAT = 'AUTOBACKUP_%F' SCOPE=SPFILE;

-- Configure RMAN retention policy
CONFIGURE RETENTION POLICY TO RECOVERY WINDOW OF 14 DAYS;

-- Configure RMAN archivelog deletion policy
CONFIGURE ARCHIVELOG DELETION POLICY TO APPLIED ON ALL STANDBY;

-- Create a script for daily incremental backups
$ cat /usr/local/bin/daily_incremental_backup.sh
#!/bin/bash
sqlplus -s / as sysdba << EOF
RMAN TARGET /
BACKUP INCREMENTAL LEVEL 1 DATABASE PLUS ARCHIVELOG;
BACKUP CURRENT CONTROLFILE FOR STANDBY;
CROSSCHECK BACKUP;
DELETE NOPROMPT OBSOLETE;
EXIT;
EOF

-- Schedule the daily incremental backup script
crontab -l | { cat; echo "0 0 * * * /usr/local/bin/daily_incremental_backup.sh"; } | crontab -

-- Create a script for weekly full backups
$ cat /usr/local/bin/weekly_full_backup.sh
#!/bin/bash
sqlplus -s / as sysdba << EOF
RMAN TARGET /
BACKUP AS COMPRESSED BACKUPSET DATABASE PLUS ARCHIVELOG;
BACKUP CURRENT CONTROLFILE FOR STANDBY;
CROSSCHECK BACKUP;
DELETE NOPROMPT OBSOLETE;
EXIT;
EOF

-- Schedule the weekly full backup script
crontab -l | { cat; echo "0 0 * * 0 /usr/local/bin/weekly_full_backup.sh"; } | crontab -

-- Verify all backups
RMAN TARGET /
RESTORE DATABASE VALIDATE;
```

```sql
-- This script is provided without warranty and should be thoroughly tested 
-- in a non-production environment before being used in production. 
-- No guarantee is made that this script is suitable for all environments.

SELECT 
    'DBMS_SCHEDULER.CREATE_JOB (  job_name           => ''' || owner || '.BACKUP_SLAVE_' || database_name || ''',  job_type           => ''EXECUTABLE'',  number_of_arguments => 1,  job_action         => ''/usr/bin/expdp'',  enabled            => TRUE,  auto_drop          => FALSE);'
FROM 
    dba_audit_trail
WHERE 
    action_name = 'LOGON'
    AND returncode = 0
    AND username = 'REPLICATION_USER'
    AND client_id LIKE '%Authority%'
GROUP BY 
    owner, database_name;
```

