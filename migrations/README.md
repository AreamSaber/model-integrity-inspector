# Database migrations

SQLite 与 PostgreSQL 使用相同迁移编号和 Repository 语义。M1-01 将实现 `schema_migrations`、迁移锁和首批 schema；在此之前不得加入未经双数据库验证的业务迁移。
