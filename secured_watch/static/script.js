/* ═══════════════════════════════════════════════════════════════════════════
   SecureDB Watch — Frontend Logic
   Handles authentication, navigation, query console, and admin panels.
   ═══════════════════════════════════════════════════════════════════════════ */

// ── State ───────────────────────────────────────────────────────────────────
let currentUser = null;
let currentSection = 'dashboard';

// ── DOM Ready ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    setupLoginForm();
    setupQueryConsole();
});

// ── Utilities ───────────────────────────────────────────────────────────────

async function api(url, options = {}) {
    try {
        const defaults = {
            headers: { 'Content-Type': 'application/json' },
        };
        const config = { ...defaults, ...options };
        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }
        const res = await fetch(url, config);
        const data = await res.json();
        return data;
    } catch (err) {
        console.error('API Error:', err);
        return { success: false, message: 'Network error. Please try again.' };
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4000);
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function getRiskBadge(risk) {
    const cls = (risk || 'safe').toLowerCase();
    return `<span class="badge badge-${cls}">${escapeHtml(risk)}</span>`;
}

function getStatusBadge(status) {
    const cls = (status || 'success').toLowerCase();
    return `<span class="badge badge-${cls}">${escapeHtml(status)}</span>`;
}

// ── Session / Auth ──────────────────────────────────────────────────────────

async function checkSession() {
    const data = await api('/api/session');
    if (data.logged_in && data.user) {
        currentUser = data.user;
        showApp();
    } else {
        showLogin();
    }
}

function setupLoginForm() {
    const form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value.trim();
        const errorEl = document.getElementById('login-error');

        if (!username || !password) {
            errorEl.textContent = 'Please enter both username and password.';
            errorEl.style.display = 'block';
            return;
        }

        const data = await api('/login', {
            method: 'POST',
            body: { username, password },
        });

        if (data.success) {
            currentUser = data.user;
            errorEl.style.display = 'none';
            showApp();
        } else {
            errorEl.textContent = data.message || 'Login failed.';
            errorEl.style.display = 'block';
        }
    });
}

async function logout() {
    await api('/logout', { method: 'POST' });
    currentUser = null;
    showLogin();
    showToast('Logged out successfully.', 'info');
}

function showLogin() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('app-container').style.display = 'none';
    // Clear form
    const form = document.getElementById('login-form');
    if (form) form.reset();
    const err = document.getElementById('login-error');
    if (err) err.style.display = 'none';
}

function showApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-container').style.display = 'block';

    const isAdmin = currentUser && currentUser.role === 'admin';

    // Sidebar visibility (admin only)
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const topbar = document.getElementById('topbar');
    const statsGrid = document.getElementById('stats-grid');

    if (sidebar) sidebar.style.display = isAdmin ? 'flex' : 'none';

    // Topbar visibility (non-admin only)
    if (topbar) topbar.style.display = isAdmin ? 'none' : 'flex';

    if (mainContent) {
        if (isAdmin) {
            mainContent.classList.remove('no-sidebar');
            mainContent.classList.remove('has-topbar');
        } else {
            mainContent.classList.add('no-sidebar');
            mainContent.classList.add('has-topbar');
        }
    }

    // Hide stats grid for non-admin
    if (statsGrid) statsGrid.style.display = isAdmin ? '' : 'none';

    // Update user info in sidebar (admin)
    const avatarEl = document.getElementById('user-avatar');
    const nameEl = document.getElementById('user-name');
    const roleEl = document.getElementById('user-role');
    if (avatarEl && currentUser) avatarEl.textContent = currentUser.username[0].toUpperCase();
    if (nameEl && currentUser) nameEl.textContent = currentUser.username;
    if (roleEl && currentUser) roleEl.textContent = currentUser.role;

    // Update user info in topbar (non-admin)
    const topbarAvatar = document.getElementById('topbar-avatar');
    const topbarName = document.getElementById('topbar-name');
    const topbarRole = document.getElementById('topbar-role');
    if (topbarAvatar && currentUser) topbarAvatar.textContent = currentUser.username[0].toUpperCase();
    if (topbarName && currentUser) topbarName.textContent = currentUser.username;
    if (topbarRole && currentUser) topbarRole.textContent = currentUser.role;

    // Show dashboard
    showSection('dashboard');
}

// ── Section Navigation ──────────────────────────────────────────────────────

function showSection(id) {
    currentSection = id;

    // Hide all sections
    document.querySelectorAll('.section').forEach(s => {
        s.style.display = 'none';
        s.classList.remove('active');
    });

    // Show target section
    const section = document.getElementById(id);
    if (section) {
        section.style.display = 'block';
        section.classList.add('active');
    }

    // Update sidebar nav active state
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.section === id) {
            item.classList.add('active');
        }
    });

    // Update topbar nav active state
    document.querySelectorAll('.topbar-link').forEach(link => {
        link.classList.remove('active');
        if (link.dataset.section === id) {
            link.classList.add('active');
        }
    });

    // Load section data
    switch (id) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'mylogs':
            loadMyLogs();
            break;
        case 'logs':
            loadLogs();
            break;
        case 'rules':
            loadRules();
            break;
        case 'users':
            loadUsers();
            break;
        case 'roles':
            loadRoles();
            break;
    }
}

// ── Dashboard ───────────────────────────────────────────────────────────────

async function loadDashboard() {
    if (currentUser && currentUser.role === 'admin') {
        const data = await api('/api/logs/stats');
        if (data.success && data.stats) {
            const s = data.stats;
            setText('stat-total', s.total_queries);
            setText('stat-success', s.successful);
            setText('stat-blocked', s.blocked);
            setText('stat-errors', s.errors);

            const rb = s.risk_breakdown || {};
            setText('stat-critical', rb.CRITICAL || 0);
        }
    }
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

// ── My Logs (Personal Activity) ─────────────────────────────────────────────

async function loadMyLogs() {
    const data = await api('/api/logs/me');
    const tbody = document.getElementById('mylogs-tbody');
    if (!tbody) return;

    if (!data.success || !data.logs || data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-text">No activity recorded yet. Execute some queries to see your history.</div></td></tr>`;
        return;
    }

    tbody.innerHTML = data.logs.map(log => `
        <tr>
            <td><span style="color: var(--accent-light); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">${escapeHtml(log.timestamp)}</span></td>
            <td><code style="color: var(--text-primary); font-size: 0.78rem; word-break: break-all;">${escapeHtml(log.query)}</code></td>
            <td>${getRiskBadge(log.risk_status)}</td>
            <td>${getStatusBadge(log.execution_status)}</td>
            <td style="font-size: 0.75rem; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</td>
        </tr>
    `).join('');
}

// ── Query Console ───────────────────────────────────────────────────────────

function setupQueryConsole() {
    const input = document.getElementById('query-input');
    if (!input) return;

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            executeQuery();
        }
    });
}

async function executeQuery() {
    const input = document.getElementById('query-input');
    const output = document.getElementById('console-output');
    if (!input || !output) return;

    const query = input.value.trim();
    if (!query) {
        showToast('Please enter a SQL query.', 'warning');
        return;
    }

    // Add query to console
    appendConsole(output, `SQL> ${query}`, 'accent');
    appendConsole(output, 'Analyzing query...', 'info');

    const data = await api('/api/query', {
        method: 'POST',
        body: { query },
    });

    if (data.success) {
        appendConsole(output, `✅ ${data.message}`, 'success');
        appendConsole(output, `Risk: ${data.risk_status} | Status: ${data.execution_status}`, 'info');

        // Display result data as table
        if (data.data && data.data.length > 0) {
            renderConsoleTable(output, data.data);
        }

        showToast('Query executed successfully.', 'success');
    } else {
        appendConsole(output, `❌ ${data.message}`, 'error');
        if (data.risk_status) {
            appendConsole(output, `Risk Level: ${data.risk_status}`, 'warning');
        }
        if (data.execution_status) {
            appendConsole(output, `Status: ${data.execution_status}`, 'warning');
        }
        if (data.threats && data.threats.length > 0) {
            appendConsole(output, 'Threats detected:', 'error');
            data.threats.forEach(t => {
                appendConsole(output, `  ⚠️ ${t.rule_name} [${t.threat_level}] — ${t.description}`, 'warning');
            });
        }
        showToast(data.message, 'error');
    }

    appendConsole(output, '─'.repeat(50), 'info');
    input.value = '';
    input.focus();

    // Refresh dashboard stats if admin
    if (currentUser && currentUser.role === 'admin' && currentSection === 'dashboard') {
        loadDashboard();
    }
}

function appendConsole(container, text, type = 'info') {
    const line = document.createElement('div');
    line.className = `console-line ${type}`;
    line.textContent = text;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}

function renderConsoleTable(container, data) {
    if (!data || data.length === 0) return;

    const columns = Object.keys(data[0]);
    let html = '<div class="result-table-wrapper"><table class="data-table"><thead><tr>';
    columns.forEach(col => {
        html += `<th>${escapeHtml(col)}</th>`;
    });
    html += '</tr></thead><tbody>';
    data.forEach(row => {
        html += '<tr>';
        columns.forEach(col => {
            html += `<td>${escapeHtml(row[col])}</td>`;
        });
        html += '</tr>';
    });
    html += '</tbody></table></div>';

    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    container.appendChild(wrapper);
    container.scrollTop = container.scrollHeight;
}

// ── Audit Logs ──────────────────────────────────────────────────────────────

async function loadLogs() {
    const data = await api('/api/logs');
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    if (!data.success || !data.logs || data.logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><div class="empty-state-icon">📜</div><div class="empty-state-text">No audit logs recorded yet.</div></td></tr>`;
        return;
    }

    tbody.innerHTML = data.logs.map(log => `
        <tr>
            <td><span style="color: var(--accent-light); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">${escapeHtml(log.timestamp)}</span></td>
            <td><span class="badge badge-role">${escapeHtml(log.username)}</span></td>
            <td><code style="color: var(--text-primary); font-size: 0.78rem; word-break: break-all;">${escapeHtml(log.query)}</code></td>
            <td>${getRiskBadge(log.risk_status)}</td>
            <td>${getStatusBadge(log.execution_status)}</td>
            <td style="font-size: 0.75rem; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</td>
        </tr>
    `).join('');
}

async function clearLogs() {
    if (!confirm('Are you sure you want to clear all audit logs?')) return;
    const data = await api('/api/logs/clear', { method: 'POST' });
    if (data.success) {
        showToast('Audit logs cleared.', 'success');
        loadLogs();
    } else {
        showToast(data.message, 'error');
    }
}

// ── Rules Engine ────────────────────────────────────────────────────────────

async function loadRules() {
    const data = await api('/api/rules');
    const tbody = document.getElementById('rules-tbody');
    if (!tbody) return;

    if (!data.success || !data.rules || data.rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state"><div class="empty-state-icon">⚙️</div><div class="empty-state-text">No custom rules defined. Add one above.</div></td></tr>`;
        return;
    }

    tbody.innerHTML = data.rules.map(rule => `
        <tr>
            <td style="font-weight: 600;">${escapeHtml(rule.name)}</td>
            <td><span class="chip">${escapeHtml(rule.type)}</span></td>
            <td><code style="font-size: 0.78rem; color: var(--accent-light);">${escapeHtml(rule.value)}</code></td>
            <td>${getRiskBadge(rule.threat_level)}</td>
            <td style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(rule.description)}</td>
            <td>
                <button class="btn btn-danger btn-sm" onclick="deleteRule('${escapeHtml(rule.name)}')">Delete</button>
            </td>
        </tr>
    `).join('');
}

function showAddRuleModal() {
    document.getElementById('modal-overlay').classList.add('active');
    document.getElementById('modal-title').textContent = '➕ Add Custom Rule';
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label>Rule Name</label>
            <input type="text" id="rule-name" placeholder="e.g., Block EXEC command">
        </div>
        <div class="form-group">
            <label>Type</label>
            <select id="rule-type">
                <option value="KEYWORD">KEYWORD</option>
                <option value="REGEX">REGEX</option>
            </select>
        </div>
        <div class="form-group">
            <label>Value (keyword or regex pattern)</label>
            <input type="text" id="rule-value" placeholder="e.g., EXEC or (?i)\\bEXEC\\b">
        </div>
        <div class="form-group">
            <label>Threat Level</label>
            <select id="rule-threat">
                <option value="LOW">LOW</option>
                <option value="MEDIUM" selected>MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
            </select>
        </div>
        <div class="form-group">
            <label>Description</label>
            <input type="text" id="rule-desc" placeholder="Describe what this rule detects">
        </div>
    `;
    document.getElementById('modal-submit').onclick = addRule;
    document.getElementById('modal-submit').textContent = 'Add Rule';
}

async function addRule() {
    const name = document.getElementById('rule-name').value.trim();
    const type = document.getElementById('rule-type').value;
    const value = document.getElementById('rule-value').value.trim();
    const threat_level = document.getElementById('rule-threat').value;
    const description = document.getElementById('rule-desc').value.trim();

    if (!name || !value) {
        showToast('Name and value are required.', 'warning');
        return;
    }

    const data = await api('/api/rules', {
        method: 'POST',
        body: { name, type, value, threat_level, description },
    });

    if (data.success) {
        closeModal();
        showToast(data.message, 'success');
        loadRules();
    } else {
        showToast(data.message, 'error');
    }
}

async function deleteRule(name) {
    if (!confirm(`Delete rule "${name}"?`)) return;
    const data = await api(`/api/rules/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (data.success) {
        showToast(data.message, 'success');
        loadRules();
    } else {
        showToast(data.message, 'error');
    }
}

// ── User Management ─────────────────────────────────────────────────────────

async function loadUsers() {
    const data = await api('/api/users');
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;

    if (!data.success || !data.users || data.users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state"><div class="empty-state-icon">👤</div><div class="empty-state-text">No users found.</div></td></tr>`;
        return;
    }

    tbody.innerHTML = data.users.map(user => `
        <tr>
            <td style="font-weight: 600;">${escapeHtml(user.username)}</td>
            <td><span class="badge badge-role">${escapeHtml(user.role)}</span></td>
            <td>${user.username === 'admin' ? '<span class="chip">🔒 Protected</span>' : ''}</td>
            <td>
                ${user.username !== 'admin' ? `
                    <button class="btn btn-ghost btn-sm" onclick="showEditUserModal('${escapeHtml(user.username)}', '${escapeHtml(user.role)}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteUserAction('${escapeHtml(user.username)}')">Delete</button>
                ` : '<span style="color: var(--text-muted); font-size: 0.78rem;">—</span>'}
            </td>
        </tr>
    `).join('');
}

async function showAddUserModal() {
    document.getElementById('modal-overlay').classList.add('active');
    document.getElementById('modal-title').textContent = '➕ Add User';

    // Fetch available roles for dropdown
    let roleOptions = '<option value="">-- Select Role --</option>';
    const rolesData = await api('/api/roles');
    if (rolesData.success && rolesData.roles) {
        rolesData.roles.forEach(r => {
            roleOptions += `<option value="${escapeHtml(r.name)}">${escapeHtml(r.name)}</option>`;
        });
    }

    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label>Username</label>
            <input type="text" id="new-username" placeholder="Enter username">
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" id="new-password" placeholder="Enter password">
        </div>
        <div class="form-group">
            <label>Role</label>
            <select id="new-role">${roleOptions}</select>
        </div>
    `;
    document.getElementById('modal-submit').onclick = addUserAction;
    document.getElementById('modal-submit').textContent = 'Add User';
}

async function addUserAction() {
    const username = document.getElementById('new-username').value.trim();
    const password = document.getElementById('new-password').value.trim();
    const role = document.getElementById('new-role').value.trim();

    if (!username || !password || !role) {
        showToast('All fields are required.', 'warning');
        return;
    }

    const data = await api('/api/users', {
        method: 'POST',
        body: { username, password, role },
    });

    if (data.success) {
        closeModal();
        showToast(data.message, 'success');
        loadUsers();
    } else {
        showToast(data.message, 'error');
    }
}

async function showEditUserModal(username, currentRole) {
    document.getElementById('modal-overlay').classList.add('active');
    document.getElementById('modal-title').textContent = `✏️ Edit User: ${username}`;

    // Fetch available roles for dropdown
    let roleOptions = '';
    const rolesData = await api('/api/roles');
    if (rolesData.success && rolesData.roles) {
        rolesData.roles.forEach(r => {
            const selected = r.name === currentRole ? 'selected' : '';
            roleOptions += `<option value="${escapeHtml(r.name)}" ${selected}>${escapeHtml(r.name)}</option>`;
        });
    }

    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label>New Password (leave blank to keep)</label>
            <input type="password" id="edit-password" placeholder="New password">
        </div>
        <div class="form-group">
            <label>Role</label>
            <select id="edit-role">${roleOptions}</select>
        </div>
    `;
    document.getElementById('modal-submit').onclick = () => updateUserAction(username);
    document.getElementById('modal-submit').textContent = 'Update User';
}

async function updateUserAction(username) {
    const password = document.getElementById('edit-password').value.trim();
    const role = document.getElementById('edit-role').value.trim();

    const body = {};
    if (password) body.password = password;
    if (role) body.role = role;

    const data = await api(`/api/users/${encodeURIComponent(username)}`, {
        method: 'PUT',
        body,
    });

    if (data.success) {
        closeModal();
        showToast(data.message, 'success');
        loadUsers();
    } else {
        showToast(data.message, 'error');
    }
}

async function deleteUserAction(username) {
    if (!confirm(`Delete user "${username}"?`)) return;
    const data = await api(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
    if (data.success) {
        showToast(data.message, 'success');
        loadUsers();
    } else {
        showToast(data.message, 'error');
    }
}

// ── Role Management ─────────────────────────────────────────────────────────

let rolesCache = {};

async function loadRoles() {
    const data = await api('/api/roles');
    const tbody = document.getElementById('roles-tbody');
    if (!tbody) return;

    if (!data.success || !data.roles || data.roles.length === 0) {
        rolesCache = {};
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">No roles defined.</div></td></tr>`;
        return;
    }

    // Cache role data for edit lookups
    rolesCache = {};
    data.roles.forEach(role => {
        rolesCache[role.name] = role;
    });

    tbody.innerHTML = data.roles.map(role => `
        <tr>
            <td style="font-weight: 600;">${escapeHtml(role.name)}</td>
            <td>${(role.allowed_commands || []).map(c => `<span class="chip">${escapeHtml(c)}</span>`).join(' ')}</td>
            <td>${(role.blocked_commands || []).length > 0
                ? role.blocked_commands.map(c => `<span class="badge badge-high">${escapeHtml(c)}</span>`).join(' ')
                : '<span style="color: var(--text-muted);">None</span>'
            }</td>
            <td>${role.name === 'admin' ? '<span class="chip">🔒 Protected</span>' : ''}</td>
            <td>
                ${role.name !== 'admin' ? `
                    <button class="btn btn-ghost btn-sm" onclick="showEditRoleModal('${escapeHtml(role.name)}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteRoleAction('${escapeHtml(role.name)}')">Delete</button>
                ` : '<span style="color: var(--text-muted); font-size: 0.78rem;">—</span>'}
            </td>
        </tr>
    `).join('');
}

function showAddRoleModal() {
    document.getElementById('modal-overlay').classList.add('active');
    document.getElementById('modal-title').textContent = '➕ Add Role';
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label>Role Name</label>
            <input type="text" id="role-name-input" placeholder="Enter role name">
        </div>
        <div class="form-group">
            <label>Allowed Commands (comma-separated, e.g. SELECT,INSERT or ALL)</label>
            <input type="text" id="role-allowed" placeholder="ALL">
        </div>
        <div class="form-group">
            <label>Blocked Commands (comma-separated, e.g. DELETE,DROP)</label>
            <input type="text" id="role-blocked" placeholder="Leave empty for none">
        </div>
    `;
    document.getElementById('modal-submit').onclick = addRoleAction;
    document.getElementById('modal-submit').textContent = 'Add Role';
}

async function addRoleAction() {
    const name = document.getElementById('role-name-input').value.trim();
    const allowedStr = document.getElementById('role-allowed').value.trim();
    const blockedStr = document.getElementById('role-blocked').value.trim();

    if (!name) {
        showToast('Role name is required.', 'warning');
        return;
    }

    const allowed = allowedStr ? allowedStr.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];
    const blocked = blockedStr ? blockedStr.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];

    const data = await api('/api/roles', {
        method: 'POST',
        body: { name, allowed_commands: allowed, blocked_commands: blocked },
    });

    if (data.success) {
        closeModal();
        showToast(data.message, 'success');
        loadRoles();
    } else {
        showToast(data.message, 'error');
    }
}

function showEditRoleModal(name) {
    const role = rolesCache[name];
    if (!role) {
        showToast('Role data not found. Please refresh.', 'error');
        return;
    }

    const allowed = role.allowed_commands || [];
    const blocked = role.blocked_commands || [];

    document.getElementById('modal-overlay').classList.add('active');
    document.getElementById('modal-title').textContent = `✏️ Edit Role: ${name}`;
    document.getElementById('modal-body').innerHTML = `
        <div class="form-group">
            <label>Allowed Commands (comma-separated)</label>
            <input type="text" id="edit-role-allowed" value="${allowed.join(', ')}" placeholder="ALL">
        </div>
        <div class="form-group">
            <label>Blocked Commands (comma-separated)</label>
            <input type="text" id="edit-role-blocked" value="${blocked.join(', ')}" placeholder="Leave empty for none">
        </div>
    `;
    document.getElementById('modal-submit').onclick = () => updateRoleAction(name);
    document.getElementById('modal-submit').textContent = 'Update Role';
}

async function updateRoleAction(name) {
    const allowedStr = document.getElementById('edit-role-allowed').value.trim();
    const blockedStr = document.getElementById('edit-role-blocked').value.trim();

    const allowed = allowedStr ? allowedStr.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];
    const blocked = blockedStr ? blockedStr.split(',').map(s => s.trim().toUpperCase()).filter(Boolean) : [];

    const data = await api(`/api/roles/${encodeURIComponent(name)}`, {
        method: 'PUT',
        body: { allowed_commands: allowed, blocked_commands: blocked },
    });

    if (data.success) {
        closeModal();
        showToast(data.message, 'success');
        loadRoles();
    } else {
        showToast(data.message, 'error');
    }
}

async function deleteRoleAction(name) {
    if (!confirm(`Delete role "${name}"?`)) return;
    const data = await api(`/api/roles/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (data.success) {
        showToast(data.message, 'success');
        loadRoles();
    } else {
        showToast(data.message, 'error');
    }
}

// ── Modal ───────────────────────────────────────────────────────────────────

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

// Close modal on overlay click
document.addEventListener('click', (e) => {
    if (e.target.id === 'modal-overlay') {
        closeModal();
    }
});

// Close modal on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModal();
});
