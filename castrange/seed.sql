DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS access_log;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_md5 TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email TEXT
);

CREATE TABLE employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    department TEXT,
    title TEXT,
    bio TEXT
);

CREATE TABLE access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    status INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    remote_ip TEXT,
    payload_signature TEXT,
    vuln_triggered INTEGER DEFAULT 0,
    detected INTEGER DEFAULT 0
);

-- MD5 fixtures (intentionally weak, default creds for V5)
--   admin/admin       -> 21232f297a57a5a743894a0e4a801fc3
--   test/test         -> 098f6bcd4621d8b41dd00b4293bcdb23
--   alice/password123 -> 482c811da5d5b4bc6d497ffa98491e38
--   bob/hunter2       -> 2ab96390c7dbe3439de74d0c9b0b1767
INSERT INTO users (username, password_md5, role, email) VALUES
    ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', 'admin@castrange.local'),
    ('test',  '098f6bcd4621d8b41dd00b4293bcdb23', 'user',  'test@castrange.local'),
    ('alice', '482c811da5d5b4bc6d497ffa98491e38', 'user',  'alice@castrange.local'),
    ('bob',   '2ab96390c7dbe3439de74d0c9b0b1767', 'user',  'bob@castrange.local');

INSERT INTO employees (name, department, title, bio) VALUES
    ('Alice Johnson', 'Engineering', 'Software Engineer', 'Backend systems'),
    ('Bob Smith',     'Engineering', 'DevOps Lead',       'Infrastructure'),
    ('Carol Davis',   'HR',          'Recruiter',         'Talent acquisition'),
    ('Dan Wilson',    'Finance',     'Senior Analyst',    'Quarterly reports'),
    ('Eve Brown',     'Security',    'Pentester',         'Red team operations');
