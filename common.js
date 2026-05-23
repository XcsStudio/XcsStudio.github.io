// common.js - 公共安全模块与工具函数 (性能优化 + 安全增强)
(function(window) {
    // Web Crypto 可用性检测
    let cryptoAvailable = false;
    try {
        cryptoAvailable = !!(window.crypto && window.crypto.subtle && window.crypto.subtle.digest);
    } catch(e) { cryptoAvailable = false; }
    
    if (!cryptoAvailable) {
        console.error('[XCSAuth] Web Crypto API 不可用');
        const dummy = { success: false, message: '当前环境不支持安全加密，请使用 HTTPS 访问' };
        window.xcsAuth = {
            verifySession: async () => false,
            getSession: () => null,
            clearSession: () => {},
            login: async () => dummy,
            register: async () => dummy,
            deleteAccount: async () => dummy,
            changePassword: async () => dummy,
            getCurrentUser: async () => null,
            showMessage: (el, text, type) => { if(el) { el.textContent = text; el.className = `message ${type}`; el.style.display = 'flex'; } }
        };
        window.themeUtils = { initThemeToggle: (id) => {} };
        return;
    }
    
    // XSS 防护 (HTML 转义)
    function sanitizeInput(str) {
        if (!str) return '';
        return str.replace(/[&<>]/g, function(m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        });
    }
    
    // PBKDF2 哈希
    async function hashPassword(password, salt, iterations = 10000) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: encoder.encode(salt), iterations, hash: 'SHA-256' },
            keyMaterial,
            256
        );
        const hashArray = Array.from(new Uint8Array(derivedBits));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    function generateSalt() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // 用户存储 (内存缓存减少 JSON 解析)
    let usersCache = null;
    let usersCacheTime = 0;
    const CACHE_TTL = 500;
    
    function getUsers() {
        const now = Date.now();
        if (usersCache && (now - usersCacheTime) < CACHE_TTL) return usersCache;
        const raw = localStorage.getItem('xcs_users_v2');
        usersCache = raw ? JSON.parse(raw) : [];
        usersCacheTime = now;
        return usersCache;
    }
    
    function saveUsers(users) {
        localStorage.setItem('xcs_users_v2', JSON.stringify(users));
        usersCache = users;
        usersCacheTime = Date.now();
    }
    
    function generateToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    const SESSION_EXPIRE_DAYS = 7;
    function setSession(nickname, token) {
        const expire = Date.now() + SESSION_EXPIRE_DAYS * 24 * 60 * 60 * 1000;
        localStorage.setItem('xcs_session', JSON.stringify({ nickname, token, expire }));
    }
    
    function getSession() {
        const raw = localStorage.getItem('xcs_session');
        if (!raw) return null;
        try {
            const session = JSON.parse(raw);
            if (session.expire && session.expire > Date.now()) return session;
            clearSession();
            return null;
        } catch(e) { return null; }
    }
    
    function clearSession() {
        localStorage.removeItem('xcs_session');
    }
    
    async function verifySession() {
        const session = getSession();
        if (!session?.nickname || !session.token) return false;
        const users = getUsers();
        const user = users.find(u => u.nickname === session.nickname);
        return !!(user && user.sessionToken === session.token);
    }
    
    async function login(nickname, password) {
        const users = getUsers();
        const user = users.find(u => u.nickname === nickname);
        if (!user) return { success: false, message: '用户不存在' };
        const hashedInput = await hashPassword(password, user.salt, user.iterations || 10000);
        if (hashedInput !== user.passwordHash) return { success: false, message: '密码错误' };
        const newToken = generateToken();
        user.sessionToken = newToken;
        saveUsers(users);
        setSession(nickname, newToken);
        return { success: true, message: '登录成功' };
    }
    
    async function register(nicknameRaw, password) {
        const nickname = sanitizeInput(nicknameRaw.trim());
        if (nickname.length < 2) return { success: false, message: '昵称至少需要2个字符' };
        if (password.length < 8) return { success: false, message: '密码至少需要8位' };
        const hasLetter = /[a-zA-Z]/.test(password);
        const hasNumber = /\d/.test(password);
        if (!hasLetter || !hasNumber) return { success: false, message: '密码必须同时包含字母和数字' };
        const users = getUsers();
        if (users.find(u => u.nickname === nickname)) return { success: false, message: '昵称已被注册' };
        const salt = generateSalt();
        const iterations = 10000;
        const passwordHash = await hashPassword(password, salt, iterations);
        const newUser = {
            nickname, salt, iterations, passwordHash,
            createdAt: new Date().toISOString(),
            sessionToken: null
        };
        users.push(newUser);
        saveUsers(users);
        return { success: true, message: '注册成功' };
    }
    
    async function deleteAccount(nickname, password) {
        const users = getUsers();
        const userIndex = users.findIndex(u => u.nickname === nickname);
        if (userIndex === -1) return { success: false, message: '用户不存在' };
        const user = users[userIndex];
        const hashedInput = await hashPassword(password, user.salt, user.iterations || 10000);
        if (hashedInput !== user.passwordHash) return { success: false, message: '密码错误' };
        users.splice(userIndex, 1);
        saveUsers(users);
        clearSession();
        return { success: true, message: '账户已注销' };
    }
    
    async function changePassword(nickname, oldPassword, newPassword) {
        if (newPassword.length < 8) return { success: false, message: '新密码至少8位' };
        const hasLetter = /[a-zA-Z]/.test(newPassword);
        const hasNumber = /\d/.test(newPassword);
        if (!hasLetter || !hasNumber) return { success: false, message: '新密码必须同时包含字母和数字' };
        const users = getUsers();
        const user = users.find(u => u.nickname === nickname);
        if (!user) return { success: false, message: '用户不存在' };
        const oldHash = await hashPassword(oldPassword, user.salt, user.iterations || 10000);
        if (oldHash !== user.passwordHash) return { success: false, message: '原密码错误' };
        const newSalt = generateSalt();
        const newHash = await hashPassword(newPassword, newSalt, 10000);
        user.salt = newSalt;
        user.passwordHash = newHash;
        user.iterations = 10000;
        const newToken = generateToken();
        user.sessionToken = newToken;
        saveUsers(users);
        setSession(nickname, newToken);
        return { success: true, message: '密码已更新' };
    }
    
    async function getCurrentUser() {
        const session = getSession();
        if (!session) return null;
        const users = getUsers();
        const user = users.find(u => u.nickname === session.nickname);
        if (!user || user.sessionToken !== session.token) return null;
        return { nickname: user.nickname, createdAt: user.createdAt };
    }
    
    // 清理旧版明文数据
    function cleanOldData() {
        const oldUsers = localStorage.getItem('xcs_users');
        if (oldUsers && !localStorage.getItem('xcs_users_v2')) {
            localStorage.removeItem('xcs_users');
            console.warn('[XCSAuth] 旧版明文数据已自动清除，请重新注册。');
            setTimeout(() => {
                if (window.location.pathname.includes('login.html') || window.location.pathname.includes('admin.html')) {
                    alert('为了账户安全，旧版数据已清除，请重新注册。');
                }
            }, 200);
        }
    }
    cleanOldData();
    
    // 主题工具
    function initThemeToggle(buttonId) {
        const toggle = document.getElementById(buttonId);
        if (!toggle) return;
        const sunIcon = toggle.querySelector('.sun-icon');
        const moonIcon = toggle.querySelector('.moon-icon');
        const applyTheme = (theme) => {
            const isDark = theme === 'dark';
            document.body.classList.toggle('dark', isDark);
            if (sunIcon && moonIcon) {
                sunIcon.style.display = isDark ? 'none' : 'block';
                moonIcon.style.display = isDark ? 'block' : 'none';
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
    
    // 增强消息提示
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
        let timer = setTimeout(() => {
            if (element.style.display === 'flex') element.style.display = 'none';
        }, 5000);
        element.addEventListener('mouseenter', () => clearTimeout(timer), { once: true });
    }
    
    window.xcsAuth = {
        sanitizeInput, hashPassword, generateSalt, getUsers, saveUsers,
        setSession, getSession, clearSession, verifySession,
        login, register, deleteAccount, changePassword, getCurrentUser,
        showMessage
    };
    window.themeUtils = { initThemeToggle };
})(window);