const API_URL = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? 'http://localhost:5000/api'
    : 'https://web-production-30866.up.railway.app/api';

function safeJsonParse(value, fallback = null) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function getCurrentUser() {
  return safeJsonParse(localStorage.getItem("user"), null);
}

function setCurrentUser(user) {
  if (!user) {
    localStorage.removeItem("user");
    sessionStorage.removeItem("backup-user");
  } else {
    localStorage.setItem("user", JSON.stringify(user));
    sessionStorage.setItem("backup-user", JSON.stringify(user));
  }
}

async function apiFetch(path, options = {}) {
  const cacheBuster = `_=${Date.now()}`;
  const url = path.startsWith("http") ? path : `${API_URL}${path.startsWith("/") ? "" : "/"}${path}`;
  const fetchUrl = url.includes('?') ? `${url}&${cacheBuster}` : `${url}?${cacheBuster}`;

  const headers = Object.assign({
    "Content-Type": "application/json",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache"
  }, options.headers || {});

  try {
    const res = await fetch(fetchUrl, {
      credentials: "include",
      mode: "cors",
      cache: "no-cache",
      ...options,
      headers,
    });

    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }

    if (!res.ok) {
      if (res.status === 401) {
        const err = new Error('Session expired or unauthorized');
        err.status = 401;
        err.data = data;
        throw err;
      }

      const msg = data?.error || data?.message || `Request failed (${res.status})`;
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }

    return data;
  } catch (error) {
    console.error('API Fetch Error:', error);
    throw error;
  }
}

async function syncUserFromSession() {
  // Always trust localStorage first — don't wipe it just because session fails
  const localUser = getCurrentUser();
  try {
    const me = await apiFetch("/auth/me", { method: "GET" });
    if (me && me.id) {
      setCurrentUser(me);
      return me;
    } else {
      return localUser || null;
    }
  } catch (e) {
    // If backend is unreachable or session expired, keep localStorage user
    return localUser || null;
  }
}

function showToast(message, isError = false) {
  const toast = document.createElement("div");
  toast.className = `toast-message${isError ? " error" : ""}`;

  const icon = document.createElement("i");
  icon.className = `fas ${isError ? "fa-exclamation-circle" : "fa-check-circle"}`;

  const text = document.createElement("span");
  text.textContent = message;

  toast.appendChild(icon);
  toast.appendChild(text);
  document.body.appendChild(toast);

  window.setTimeout(() => toast.remove(), 3000);
}

function initDarkModeToggle() {
  const darkModeToggle = document.getElementById("darkModeToggle");
  if (!darkModeToggle) return;

  const applyLabel = () => {
    const isDark = document.body.classList.contains("dark-mode");
    darkModeToggle.innerHTML = isDark ? '<i class="fas fa-sun"></i> Light Mode' : '<i class="fas fa-moon"></i> Dark Mode';
  };

  darkModeToggle.addEventListener("click", async () => {
    document.body.classList.toggle("dark-mode");
    const isDark = document.body.classList.contains("dark-mode");
    const theme = isDark ? "dark" : "light";
    localStorage.setItem("buildmatrix-dark-mode", theme);
    applyLabel();
    const user = getCurrentUser();
    if (user) {
      try { await apiFetch("/auth/theme", { method: "PUT", body: JSON.stringify({ theme }) }); } catch(_) {}
    }
  });

  const user = getCurrentUser();
  if (user && user.theme) {
    if (user.theme === "light") document.body.classList.remove("dark-mode");
    else document.body.classList.add("dark-mode");
    localStorage.setItem("buildmatrix-dark-mode", user.theme);
  } else {
    const saved = localStorage.getItem("buildmatrix-dark-mode");
    if (saved === "dark") document.body.classList.add("dark-mode");
  }
  applyLabel();
}

function updateAuthUI() {
  const user = getCurrentUser();
  const authBtn = document.getElementById("authBtn");
  const userInfo = document.getElementById("userInfo");
  const userNameText = document.getElementById("userNameText");

  if (!authBtn || !userInfo || !userNameText) return;

  if (user) {
    authBtn.style.display = "none";
    userInfo.style.display = "flex";
    userNameText.textContent = user.name || "User";
    checkAndShowAdminButton();
  } else {
    authBtn.style.display = "inline-flex";
    userInfo.style.display = "none";
    userNameText.textContent = "User";
    const adminBtn = document.getElementById('adminPanelBtn');
    if (adminBtn) adminBtn.style.display = 'none';
  }
}

function toggleUserMenu() {
  const menu = document.getElementById("userMenuContent");
  if (!menu) return;
  menu.classList.toggle("show");
}

function closeUserMenu() {
  const menu = document.getElementById("userMenuContent");
  if (!menu) return;
  menu.classList.remove("show");
}

function initUserMenuAutoClose() {
  document.addEventListener("click", (e) => {
    const menu = document.getElementById("userMenuContent");
    const userName = document.getElementById("userNameDisplay");

    if (!menu || !userName) return;
    if (!menu.classList.contains("show")) return;

    const clickedInside = userName.contains(e.target) || menu.contains(e.target);
    if (!clickedInside) menu.classList.remove("show");
  });
}

async function handleLogout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch {
  }

  setCurrentUser(null);
  updateAuthUI();
  if (typeof updateIndexAuthUI === 'function') updateIndexAuthUI(null);
  closeUserMenu();
  const dd = document.getElementById("userDropdown");
  if (dd) dd.classList.remove("show");
  showToast("Logged out successfully");

  if (!window.location.pathname.endsWith('index.html') && window.location.pathname !== '/') {
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 500);
  }
}

function goHome() {
  window.location.href = "index.html";
}

async function checkAndShowAdminButton() {
  try {
    const user = getCurrentUser();
    const adminBtn = document.getElementById('adminPanelBtn');

    if (!adminBtn) return;

    if (!user) {
      adminBtn.style.display = 'none';
      return;
    }

    try {
      const response = await apiFetch('/auth/me', { method: 'GET' });

      if (response && response.is_admin) {
        adminBtn.style.display = 'flex';
        setCurrentUser(response);
      } else {
        adminBtn.style.display = 'none';
      }
    } catch (err) {
      if (user.is_admin) {
        adminBtn.style.display = 'flex';
      } else {
        adminBtn.style.display = 'none';
      }
    }
  } catch (err) {
    const adminBtn = document.getElementById('adminPanelBtn');
    if (adminBtn) adminBtn.style.display = 'none';
  }
}

window.addEventListener('beforeunload', function() {
  const user = getCurrentUser();
  if (user) {
    sessionStorage.setItem('backup-user', JSON.stringify(user));
  }
});

window.addEventListener('load', function() {
  const user = getCurrentUser();
  const backup = sessionStorage.getItem('backup-user');

  if (!user && backup) {
    try {
      const backupUser = JSON.parse(backup);
      setCurrentUser(backupUser);
      updateAuthUI();
    } catch (e) {}
  }
});

window.API_URL = API_URL;
window.apiFetch = apiFetch;
window.syncUserFromSession = syncUserFromSession;
window.showToast = showToast;
window.toggleUserMenu = toggleUserMenu;
window.handleLogout = handleLogout;
window.goHome = goHome;
window.updateAuthUI = updateAuthUI;
window.initDarkModeToggle = initDarkModeToggle;
window.initUserMenuAutoClose = initUserMenuAutoClose;
window.getCurrentUser = getCurrentUser;
window.checkAndShowAdminButton = checkAndShowAdminButton;

function open2FASetup() {
  if (location.pathname.endsWith("index.html") || location.pathname === "/" ) {
    return;
  }
  showToast("Open Security Settings on the Builder page.");
  window.location.href = "index.html";
}

function showFavorites() {
  showToast("Favorites are not included in this version.");
  closeUserMenu();
}

window.open2FASetup = open2FASetup;
window.showFavorites = showFavorites;