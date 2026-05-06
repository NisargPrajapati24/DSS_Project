# 🛡️ SecureDB Watch — Database Activity Monitoring & Auditing System

A full-stack cybersecurity project that monitors, analyzes, and audits all database queries in real-time with threat detection and role-based access control.

---

## 🧰 Tech Stack

| Layer     | Technology              |
|-----------|-------------------------|
| Backend   | Python (Flask)          |
| Database  | SQLite                  |
| Frontend  | HTML, CSS, JavaScript   |
| Storage   | JSON (users, roles, logs, rules) |

---

## 📁 Project Structure

```
secured_watch/
│
├── app.py                 # Flask web server & REST API
├── main.py                # CLI terminal interface
├── auth.py                # Authentication module
├── database.py            # SQLite database layer
├── logger.py              # Audit logging system
├── query_analyzer.py      # Security / threat detection engine
├── rbac.py                # Role-Based Access Control
│
├── data.db                # SQLite database (auto-created)
├── audit_log.json         # Query audit trail
├── users.json             # User accounts
├── roles.json             # Role definitions
├── rules.json             # Custom detection rules
│
├── templates/
│   └── index.html         # Web dashboard
│
├── static/
│   ├── style.css          # Cyber-themed stylesheet
│   └── script.js          # Frontend logic
│
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

```bash
pip install flask
```

### Run Web Dashboard

```bash
python app.py
```

Open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### Run CLI Interface

```bash
python main.py
```

---

## 🔐 Default Users

| Username | Password  | Role   |
|----------|-----------|--------|
| admin    | admin123  | admin  |
| user1    | user123   | user1  |
| user2    | user123   | user2  |

---

## 🛡️ Role Permissions

| Role   | Allowed        | Blocked  |
|--------|----------------|----------|
| admin  | ALL            | —        |
| user1  | ALL            | DELETE   |
| user2  | SELECT only    | —        |

---

## 🔍 Security Features

### Query Analyzer detects:
- **SQL Injection**: `OR 1=1`, `UNION SELECT`, comment injection, stacked queries
- **Dangerous Commands**: `DROP`, `ALTER`, `TRUNCATE`, `DELETE` (without WHERE)
- **Custom Rules**: Add KEYWORD or REGEX-based rules via the web dashboard

### Threat Levels:
`SAFE` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

## 📜 Audit Logging

Every query attempt is logged with:
- Username, query text, timestamp
- Risk level assessment
- Execution status (SUCCESS / BLOCKED / ERROR)
- Contextual message

---

## 🌐 Web API Endpoints

| Method | Endpoint            | Access  | Description          |
|--------|---------------------|---------|----------------------|
| POST   | `/login`            | Public  | Authenticate user    |
| POST   | `/logout`           | Auth    | End session          |
| GET    | `/api/session`      | Public  | Check session status |
| POST   | `/api/query`        | Auth    | Execute SQL query    |
| GET    | `/api/logs`         | Admin   | Get audit logs       |
| GET    | `/api/logs/stats`   | Admin   | Get log statistics   |
| POST   | `/api/logs/clear`   | Admin   | Clear all logs       |
| GET    | `/api/users`        | Admin   | List users           |
| POST   | `/api/users`        | Admin   | Add user             |
| PUT    | `/api/users/<name>` | Admin   | Update user          |
| DELETE | `/api/users/<name>` | Admin   | Delete user          |
| GET    | `/api/roles`        | Admin   | List roles           |
| POST   | `/api/roles`        | Admin   | Add role             |
| PUT    | `/api/roles/<name>` | Admin   | Update role          |
| DELETE | `/api/roles/<name>` | Admin   | Delete role          |
| GET    | `/api/rules`        | Admin   | List rules           |
| POST   | `/api/rules`        | Admin   | Add rule             |
| PUT    | `/api/rules/<name>` | Admin   | Update rule          |
| DELETE | `/api/rules/<name>` | Admin   | Delete rule          |

---

## ⚙️ Backend Flow

```
User Query → Analyze (Threats?) → If unsafe: BLOCK
                                → If safe: RBAC Check
                                    → If unauthorized: BLOCK
                                    → If authorized: Execute → Return Results
→ Log Everything
```

---

## 🎨 UI Theme

- **Cyber dark theme** with glassmorphism panels
- **Neon violet accents** (`#8B5CF6`)
- **JetBrains Mono** monospace terminal font
- **Admin sidebar** with section navigation
- **Responsive** design for all screen sizes

---

## 📌 Notes

- Admin account and role are **protected** from deletion/modification
- All queries are logged regardless of outcome
- Session-based authentication via Flask
- Custom rules support both keyword matching and regex patterns

---

**Built by Nisarg Prajapati, Polisetti Sai Yadusreshta and Ved Patel**
