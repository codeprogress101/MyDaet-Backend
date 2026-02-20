CREATE TABLE IF NOT EXISTS posts (
  id VARCHAR(191) NOT NULL,
  type VARCHAR(64) NULL,
  category VARCHAR(128) NULL,
  doc_type VARCHAR(128) NULL,
  title VARCHAR(512) NULL,
  status VARCHAR(64) NULL,
  office_id VARCHAR(191) NULL,
  json_payload LONGTEXT NULL,
  updated_at DATETIME NULL,
  created_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_posts_status (status),
  KEY idx_posts_office (office_id),
  KEY idx_posts_updated_at (updated_at)
);

CREATE TABLE IF NOT EXISTS public_docs (
  id VARCHAR(191) NOT NULL,
  type VARCHAR(64) NULL,
  category VARCHAR(128) NULL,
  doc_type VARCHAR(128) NULL,
  title VARCHAR(512) NULL,
  status VARCHAR(64) NULL,
  office_id VARCHAR(191) NULL,
  json_payload LONGTEXT NULL,
  updated_at DATETIME NULL,
  created_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_public_docs_type (doc_type),
  KEY idx_public_docs_status (status),
  KEY idx_public_docs_office (office_id)
);

CREATE TABLE IF NOT EXISTS jobs (
  id VARCHAR(191) NOT NULL,
  type VARCHAR(64) NULL,
  category VARCHAR(128) NULL,
  doc_type VARCHAR(128) NULL,
  title VARCHAR(512) NULL,
  status VARCHAR(64) NULL,
  office_id VARCHAR(191) NULL,
  json_payload LONGTEXT NULL,
  updated_at DATETIME NULL,
  created_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_jobs_status (status),
  KEY idx_jobs_office (office_id)
);

CREATE TABLE IF NOT EXISTS doc_tracking (
  id VARCHAR(191) NOT NULL,
  type VARCHAR(64) NULL,
  category VARCHAR(128) NULL,
  doc_type VARCHAR(128) NULL,
  title VARCHAR(512) NULL,
  status VARCHAR(64) NULL,
  office_id VARCHAR(191) NULL,
  json_payload LONGTEXT NULL,
  updated_at DATETIME NULL,
  created_at DATETIME NULL,
  PRIMARY KEY (id),
  KEY idx_doc_tracking_status (status),
  KEY idx_doc_tracking_office (office_id),
  KEY idx_doc_tracking_updated_at (updated_at)
);

CREATE TABLE IF NOT EXISTS doc_tracking_timeline (
  tracking_id VARCHAR(191) NOT NULL,
  entry_id VARCHAR(191) NOT NULL,
  timestamp DATETIME NULL,
  action_type VARCHAR(128) NULL,
  office_id VARCHAR(191) NULL,
  public_note TEXT NULL,
  json_payload LONGTEXT NULL,
  PRIMARY KEY (tracking_id, entry_id),
  KEY idx_doc_tracking_timeline_ts (timestamp),
  KEY idx_doc_tracking_timeline_action (action_type),
  KEY idx_doc_tracking_timeline_office (office_id)
);
