Add-Migration Initial -Context ApplicationDbContext -OutputDir Data/ApplicationDb
Update-Database -Context ApplicationDbContext

Add-Migration PersistedGrantDbMigration -Context PersistedGrantDbContext -OutputDir Data/PersistedGrantDb
Update-Database -Context PersistedGrantDbContext

Add-Migration ConfigurationDbMigration -Context ConfigurationDbContext -OutputDir Data/ConfigurationDb
Update-Database -Context ConfigurationDbContext