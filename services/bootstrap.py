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
