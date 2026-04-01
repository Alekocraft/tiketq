from services.db import commit, execute


def ensure_schema() -> None:
    execute(
        """
        IF COL_LENGTH('dbo.users', 'job_title') IS NULL
            ALTER TABLE dbo.users ADD job_title NVARCHAR(200) NULL;
        IF COL_LENGTH('dbo.users', 'department') IS NULL
            ALTER TABLE dbo.users ADD department NVARCHAR(200) NULL;

        IF COL_LENGTH('dbo.cases', 'response_due_at') IS NULL
            ALTER TABLE dbo.cases ADD response_due_at DATETIME2(7) NULL;
        IF COL_LENGTH('dbo.cases', 'resolution_due_at') IS NULL
            ALTER TABLE dbo.cases ADD resolution_due_at DATETIME2(7) NULL;

        IF COL_LENGTH('dbo.case_attachments', 'update_id') IS NULL
            ALTER TABLE dbo.case_attachments ADD update_id INT NULL;

        IF OBJECT_ID('dbo.user_roles', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.user_roles(
                id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
                user_id NVARCHAR(120) NOT NULL,
                role NVARCHAR(50) NOT NULL,
                created_at DATETIME2(7) NOT NULL,
                updated_at DATETIME2(7) NOT NULL,
                CONSTRAINT UQ_user_roles UNIQUE(user_id, role)
            );
        END;

        IF OBJECT_ID('dbo.holidays', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.holidays(
                holiday_date DATE NOT NULL,
                name NVARCHAR(200) NOT NULL,
                is_active BIT NOT NULL CONSTRAINT DF_holidays_is_active DEFAULT((1)),
                created_at DATETIME2(7) NOT NULL CONSTRAINT DF_holidays_created_at DEFAULT(SYSDATETIME()),
                updated_at DATETIME2(7) NOT NULL CONSTRAINT DF_holidays_updated_at DEFAULT(SYSDATETIME()),
                CONSTRAINT PK_holidays PRIMARY KEY CLUSTERED (holiday_date ASC)
            );
        END;

        IF OBJECT_ID('dbo.case_surveys', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.case_surveys(
                id INT IDENTITY(1,1) NOT NULL,
                case_id NVARCHAR(30) NOT NULL,
                resolved_at_snapshot DATETIME2(7) NOT NULL,
                token NVARCHAR(80) NOT NULL,
                recipient_email NVARCHAR(200) NULL,
                sent_at DATETIME2(7) NULL,
                rating TINYINT NULL,
                reason NVARCHAR(MAX) NULL,
                completed_at DATETIME2(7) NULL,
                delivery_error NVARCHAR(1000) NULL,
                created_at DATETIME2(7) NOT NULL CONSTRAINT DF_case_surveys_created_at DEFAULT(SYSDATETIME()),
                updated_at DATETIME2(7) NOT NULL CONSTRAINT DF_case_surveys_updated_at DEFAULT(SYSDATETIME()),
                CONSTRAINT PK_case_surveys PRIMARY KEY CLUSTERED (id ASC),
                CONSTRAINT UQ_case_surveys_token UNIQUE(token),
                CONSTRAINT UQ_case_surveys_case_resolved UNIQUE(case_id, resolved_at_snapshot),
                CONSTRAINT CK_case_surveys_rating CHECK (rating IS NULL OR rating BETWEEN 1 AND 5)
            );
        END;
        """
    )

    execute(
        """
        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'IX_case_attachments_update' AND object_id = OBJECT_ID('dbo.case_attachments')
        )
        BEGIN
            CREATE NONCLUSTERED INDEX IX_case_attachments_update
                ON dbo.case_attachments(update_id ASC)
                WHERE update_id IS NOT NULL;
        END;

        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'IX_case_surveys_case_created' AND object_id = OBJECT_ID('dbo.case_surveys')
        )
        BEGIN
            CREATE NONCLUSTERED INDEX IX_case_surveys_case_created
                ON dbo.case_surveys(case_id ASC, created_at DESC);
        END;

        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'IX_case_surveys_pending' AND object_id = OBJECT_ID('dbo.case_surveys')
        )
        BEGIN
            CREATE NONCLUSTERED INDEX IX_case_surveys_pending
                ON dbo.case_surveys(sent_at ASC, completed_at ASC);
        END;

        IF NOT EXISTS (
            SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_case_attachments_update'
        )
        BEGIN
            ALTER TABLE dbo.case_attachments WITH CHECK
            ADD CONSTRAINT FK_case_attachments_update FOREIGN KEY(update_id)
            REFERENCES dbo.case_updates(id);
        END;

        IF NOT EXISTS (
            SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_case_surveys_case'
        )
        BEGIN
            ALTER TABLE dbo.case_surveys WITH CHECK
            ADD CONSTRAINT FK_case_surveys_case FOREIGN KEY(case_id)
            REFERENCES dbo.cases(id);
        END;
        """
    )

    execute(
        """
        UPDATE dbo.users
        SET role = CASE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(role, ''))), '-', '_'), ' ', '_'))
            WHEN 'admin' THEN 'administrador'
            WHEN 'administrador' THEN 'administrador'
            WHEN 'gestor_tic' THEN 'gestor_ti'
            WHEN 'gestor_ti' THEN 'gestor_ti'
            WHEN 'ciber' THEN 'ciberseguridad'
            WHEN 'ciberseguridad' THEN 'ciberseguridad'
            WHEN 'suguipq' THEN 'sugip'
            WHEN 'suguip' THEN 'sugip'
            WHEN 'sugip' THEN 'sugip'
            WHEN 'analista_ti' THEN 'analista_ti'
            ELSE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(role, ''))), '-', '_'), ' ', '_'))
        END
        WHERE ISNULL(LTRIM(RTRIM(role)), '') <> '';

        UPDATE dbo.user_roles
        SET role = CASE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(role, ''))), '-', '_'), ' ', '_'))
            WHEN 'admin' THEN 'administrador'
            WHEN 'administrador' THEN 'administrador'
            WHEN 'gestor_tic' THEN 'gestor_ti'
            WHEN 'gestor_ti' THEN 'gestor_ti'
            WHEN 'ciber' THEN 'ciberseguridad'
            WHEN 'ciberseguridad' THEN 'ciberseguridad'
            WHEN 'suguipq' THEN 'sugip'
            WHEN 'suguip' THEN 'sugip'
            WHEN 'sugip' THEN 'sugip'
            WHEN 'analista_ti' THEN 'analista_ti'
            ELSE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(role, ''))), '-', '_'), ' ', '_'))
        END;

        UPDATE dbo.cases
        SET assigned_team = CASE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(assigned_team, ''))), '-', '_'), ' ', '_'))
            WHEN 'gestor_tic' THEN 'gestor_ti'
            WHEN 'gestor_ti' THEN 'gestor_ti'
            WHEN 'ciber' THEN 'ciberseguridad'
            WHEN 'ciberseguridad' THEN 'ciberseguridad'
            WHEN 'suguipq' THEN 'sugip'
            WHEN 'suguip' THEN 'sugip'
            WHEN 'sugip' THEN 'sugip'
            WHEN 'analista_ti' THEN 'analista_ti'
            ELSE LOWER(REPLACE(REPLACE(LTRIM(RTRIM(ISNULL(assigned_team, ''))), '-', '_'), ' ', '_'))
        END
        WHERE ISNULL(LTRIM(RTRIM(assigned_team)), '') <> '';

        ;WITH dedup AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY user_id, role ORDER BY id) AS rn
            FROM dbo.user_roles
        )
        DELETE FROM dedup WHERE rn > 1;
        """
    )

    execute(
        """
        INSERT INTO dbo.user_roles(user_id, role, created_at, updated_at)
        SELECT u.id,
               LOWER(REPLACE(REPLACE(ISNULL(u.role, ''), ' ', '_'), '-', '_')),
               SYSDATETIME(),
               SYSDATETIME()
        FROM dbo.users u
        WHERE ISNULL(LTRIM(RTRIM(u.role)), '') <> ''
          AND NOT EXISTS (
              SELECT 1
              FROM dbo.user_roles ur
              WHERE ur.user_id = u.id
                AND ur.role = LOWER(REPLACE(REPLACE(ISNULL(u.role, ''), ' ', '_'), '-', '_'))
          );
        """
    )
    commit()
