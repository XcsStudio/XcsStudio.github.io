// common.js - 公共安全模块与工具函数 (完全重写，修复所有缺陷)
(function(window) {
    // ---------- XSS 防护 ----------
    function sanitizeInput(str) {
        if (!str) return '';
        return str.replace(/[&<>]/g, function(m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        });
    }
    
    // ---------- 密码哈希 (Web Crypto API, 加盐) ----------
    async function hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    function generateSalt() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // ---------- 用户存储 (版本 v2, 哈希存储) ----------
    function getUsers() {
        const raw = localStorage.getItem('xcs_users_v2');
        return raw ? JSON.parse(raw) : [];
    }
    function saveUsers(users) {
        localStorage.setItem('xcs_users_v2', JSON.stringify(users));
    }
    
    // 生成会话 token (32字节随机)
    function generateToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // 会话管理 (有效期7天)
    const SESSION_EXPIRE_DAYS = 7;
    function setSession(nickname, token) {
        const expire = Date.now() + SESSION_EXPIRE_DAYS * 24 * 60 * 60 * 1000;
        const session = { nickname, token, expire };
        localStorage.setItem('xcs_session', JSON.stringify(session));
    }
    
    function getSession() {
        const raw = localStorage.getItem('xcs_session');
        if (!raw) return null;
        try {
            const session = JSON.parse(raw);
            if (session.expire && session.expire > Date.now()) {
                return session;
            } else {
                clearSession();
                return null;
            }
        } catch(e) { return null; }
    }
    
    function clearSession() {
        localStorage.removeItem('xcs_session');
    }
    
    // 验证 session 是否有效 (匹配用户存储中的 token)
    async function verifySession() {
        const session = getSession();
        if (!session || !session.nickname || !session.token) return false;
        const users = getUsers();
        const user = users.find(u => u.nickname === session.nickname);
        if (!user || user.sessionToken !== session.token) return false;
        return true;
    }
    
    // 登录逻辑
    async function login(nickname, password) {
        const users = getUsers();
        const user = users.find(u => u.nickname === nickname);
        if (!user) return { success: false, message: '用户不存在' };
        const hashedInput = await hashPassword(password, user.salt);
        if (hashedInput !== user.passwordHash) {
            return { success: false, message: '密码错误' };
        }
        // 更新 session token
        const newToken = generateToken();
        user.sessionToken = newToken;
        saveUsers(users);
        setSession(nickname, newToken);
        return { success: true, message: '登录成功' };
    }
    
    // 注册逻辑 (密码强度: 至少8位，同时包含字母和数字)
    async function register(nicknameRaw, password) {
        const nickname = sanitizeInput(nicknameRaw.trim());
        if (nickname.length < 2) return { success: false, message: '昵称至少需要2个字符' };
        if (password.length < 8) return { success: false, message: '密码至少需要8位' };
        const hasLetter = /[a-zA-Z]/.test(password);
        const hasNumber = /\d/.test(password);
        if (!hasLetter || !hasNumber) return { success: false, message: '密码必须同时包含字母和数字' };
        const users = getUsers();
        if (users.find(u => u.nickname === nickname)) {
            return { success: false, message: '昵称已被注册' };
        }
        const salt = generateSalt();
        const passwordHash = await hashPassword(password, salt);
        const newUser = {
            nickname,
            salt,
            passwordHash,
            createdAt: new Date().toISOString(),
            sessionToken: null
        };
        users.push(newUser);
        saveUsers(users);
        return { success: true, message: '注册成功' };
    }
    
    // 注销账户 (需要验证密码)
    async function deleteAccount(nickname, password) {
        const users = getUsers();
        const userIndex = users.findIndex(u => u.nickname === nickname);
        if (userIndex === -1) return { success: false, message: '用户不存在' };
        const user = users[userIndex];
        const hashedInput = await hashPassword(password, user.salt);
        if (hashedInput !== user.passwordHash) return { success: false, message: '密码错误' };
        users.splice(userIndex, 1);
        saveUsers(users);
        clearSession();
        return { success: true, message: '账户已注销' };
    }
    
    // 修改密码
    async function changePassword(nickname, oldPassword, newPassword) {
        if (newPassword.length < 8) return { success: false, message: '新密码至少8位' };
        const hasLetter = /[a-zA-Z]/.test(newPassword);
        const hasNumber = /\d/.test(newPassword);
        if (!hasLetter || !hasNumber) return { success: false, message: '新密码必须同时包含字母和数字' };
        const users = getUsers();
        const user = users.find(u => u.nickname === nickname);
        if (!user) return { success: false, message: '用户不存在' };
        const oldHash = await hashPassword(oldPassword, user.salt);
        if (oldHash !== user.passwordHash) return { success: false, message: '原密码错误' };
        const newSalt = generateSalt();
        const newHash = await hashPassword(newPassword, newSalt);
        user.salt = newSalt;
        user.passwordHash = newHash;
        // 重置 session token
        const newToken = generateToken();
        user.sessionToken = newToken;
        saveUsers(users);
        setSession(nickname, newToken);
        return { success: true, message: '密码已更新' };
    }
    
    // 获取当前登录用户详细信息 (不含密码)
    async function getCurrentUser() {
        const session = getSession();
        if (!session) return null;
        const users = getUsers();
        const user = users.find(u => u.nickname === session.nickname);
        if (!user || user.sessionToken !== session.token) return null;
        return { nickname: user.nickname, createdAt: user.createdAt };
    }
    
    // 主题工具
    function initThemeToggle(buttonId) {
        const toggle = document.getElementById(buttonId);
        if (!toggle) return;
        const sunIcon = toggle.querySelector('.sun-icon');
        const moonIcon = toggle.querySelector('.moon-icon');
        const applyTheme = (theme) => {
            if (theme === 'dark') {
                document.body.classList.add('dark');
                if (sunIcon && moonIcon) { sunIcon.style.display = 'none'; moonIcon.style.display = 'block'; }
            } else {
                document.body.classList.remove('dark');
                if (sunIcon && moonIcon) { sunIcon.style.display = 'block'; moonIcon.style.display = 'none'; }
            }
            localStorage.setItem('theme', theme);
        };
        const getStored = () => {
            const saved = localStorage.getItem('theme');
            if (saved) return saved;
            return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        };
        toggle.addEventListener('click', () => applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark'));
        applyTheme(getStored());
    }
    
    // 显示带关闭按钮的消息 (优化用户体验)
    function showMessage(element, text, type) {
        if (!element) return;
        element.textContent = '';
        element.className = `message ${type}`;
        const textSpan = document.createElement('span');
        textSpan.textContent = text;
        const closeBtn = document.createElement('span');
        closeBtn.textContent = '×';
        closeBtn.className = 'close-msg';
        closeBtn.style.cursor = 'pointer';
        closeBtn.onclick = () => { element.style.display = 'none'; };
        element.appendChild(textSpan);
        element.appendChild(closeBtn);
        element.style.display = 'flex';
        setTimeout(() => {
            if (element.style.display === 'flex') element.style.display = 'none';
        }, 5000);
    }
    
    // 导出公共接口
    window.xcsAuth = {
        sanitizeInput,
        hashPassword,
        generateSalt,
        getUsers,
        saveUsers,
        setSession,
        getSession,
        clearSession,
        verifySession,
        login,
        register,
        deleteAccount,
        changePassword,
        getCurrentUser,
        showMessage
    };
    window.themeUtils = { initThemeToggle };
})(window);