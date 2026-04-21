/**
 * Shared Sidebar Component — injects sidebar + manages auth cache.
 *
 * Auth caching:
 * - /auth/me chỉ được gọi khi cache hết hạn (1 giờ) hoặc không có cache.
 * - Trong 1 giờ, user data được đọc từ localStorage cache.
 * → Không còn "flash" khi load page.
 */

const SIDEBAR_HTML = `
<aside class="w-60 bg-zinc-900 flex flex-col shrink-0 h-full">
  <div class="px-6 py-5 border-b border-zinc-800 shrink-0">
    <h1 class="text-white text-lg font-bold tracking-tight">
      Approve<span class="text-blue-400">Hub</span>
    </h1>
    <p class="text-zinc-500 text-xs mt-0.5">Internal System</p>
  </div>

  <nav class="flex-1 min-h-0 px-3 py-4 space-y-1 overflow-y-auto">
    <a href="index.html" data-nav="index" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-grip text-base w-5"></i> Dashboard
    </a>
    <a href="leave.html" data-nav="leave" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-calendar-check text-base w-5"></i> Leave Request
    </a>
    <a href="my-leaves.html" data-nav="my-leaves" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-list-check text-base w-5"></i> My Leaves
    </a>

    <a href="approvals.html" data-nav="approvals" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-clipboard-check text-base w-5"></i> Approvals
    </a>

    <a href="settings.html" data-nav="settings" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-gear text-base w-5"></i> Settings
    </a>

    <div class="my-2 border-t border-zinc-800"></div>

    <a href="rooms.html" data-nav="rooms" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-door-open text-base w-5"></i> Meeting Rooms
    </a>
    <a href="book-room.html" data-nav="book-room" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-calendar-plus text-base w-5"></i> Book Room
    </a>
    <a href="booking-dashboard.html" data-nav="booking-dashboard" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-list text-base w-5"></i> My Bookings
    </a>

    <a href="meeting-approvals.html" data-nav="meeting-approvals" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-user-check text-base w-5"></i> Room Approvals
    </a>
  </nav>

  <div class="px-3 py-4 border-t border-zinc-800 shrink-0">
    <a href="#" id="sidebarLogoutBtn" class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-right-from-bracket text-base w-5"></i> Sign Out
    </a>
  </div>
</aside>`;

// ─── Auth cache constants ───────────────────────
const AUTH_CACHE_KEY = "sidebar_user_cache";
const AUTH_CACHE_EXPIRY_KEY = "sidebar_user_expiry";
const AUTH_CACHE_TTL_MS = 60 * 60 * 1000; // 1 giờ

function getAPI_URL() {
  return (
    window.location.protocol === "file:" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1"
  )
    ? "http://localhost:3001/api"
    : "/api";
}

function clearSession(pendingApprovalToken) {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  localStorage.removeItem(AUTH_CACHE_KEY);
  localStorage.removeItem(AUTH_CACHE_EXPIRY_KEY);
  // Giữ approval token từ URL nếu có — để sau khi login vẫn quay lại đúng trang
  if (pendingApprovalToken) {
    sessionStorage.setItem("pendingApprovalToken", pendingApprovalToken);
    window.location.href = "login.html";
  } else {
    window.location.href = "login.html";
  }
}

// Lấy approval token từ URL (dùng cho redirect sau login)
function getApprovalTokenFromURL() {
  try {
    return new URLSearchParams(window.location.search).get("token");
  } catch {
    return null;
  }
}

// ─── Auth: cache-first, chỉ gọi /auth/me khi cache hết hạn ───
async function getCachedUser() {
  const token = localStorage.getItem("token");
  if (!token) {
    clearSession(getApprovalTokenFromURL());
    return null;
  }

  const cached = localStorage.getItem(AUTH_CACHE_KEY);
  const expiry = parseInt(localStorage.getItem(AUTH_CACHE_EXPIRY_KEY) || "0");
  const now = Date.now();

  // Cache còn hạn → dùng cache
  if (cached && now < expiry) {
    try {
      return JSON.parse(cached);
    } catch {
      localStorage.removeItem(AUTH_CACHE_KEY);
    }
  }

  // Cache hết hạn hoặc không có → validate qua API
  try {
    const res = await fetch(`${getAPI_URL()}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      clearSession(getApprovalTokenFromURL());
      return null;
    }
    const me = await res.json();
    const user = {
      id: me._id,
      name: me.name,
      email: me.email,
      department: me.department,
      role: me.role,
    };

    // Cache lại
    localStorage.setItem(AUTH_CACHE_KEY, JSON.stringify(user));
    localStorage.setItem(AUTH_CACHE_EXPIRY_KEY, String(now + AUTH_CACHE_TTL_MS));
    localStorage.setItem("user", JSON.stringify(user));

    return user;
  } catch {
    // Lỗi mạng → dùng cache cũ nếu có
    if (cached) {
      try {
        return JSON.parse(cached);
      } catch {
        clearSession(getApprovalTokenFromURL());
      }
    } else {
      clearSession(getApprovalTokenFromURL());
    }
    return null;
  }
}

// ─── Helpers ───────────────────────────────────
function getActivePageFromURL() {
  const filename = (window.location.pathname.split("/").pop() || "index.html");
  return filename.replace(".html", "");
}

function highlightSidebarActive(activePage) {
  document.querySelectorAll(".nav-item").forEach(link => {
    const isActive = link.getAttribute("data-nav") === activePage;
    if (isActive) {
      link.classList.add("bg-blue-600", "text-white");
      link.classList.remove("text-zinc-400");
    } else {
      link.classList.remove("bg-blue-600", "text-white");
      link.classList.add("text-zinc-400");
    }
  });
}

function applyRoleVisibility(role) {
  const alwaysVisible = ["index", "leave", "my-leaves", "rooms", "book-room", "booking-dashboard"];
  alwaysVisible.forEach(page => {
    const el = document.querySelector(`[data-nav="${page}"]`);
    if (el) { el.classList.add("flex"); el.classList.remove("hidden"); }
  });

  if (role === "manager" || role === "hr") {
    const el = document.querySelector('[data-nav="approvals"]');
    if (el) { el.classList.add("flex"); el.classList.remove("hidden"); }
  }
  if (role === "hr") {
    const el = document.querySelector('[data-nav="settings"]');
    if (el) { el.classList.add("flex"); el.classList.remove("hidden"); }
  }
  if (role === "manager") {
    const el = document.querySelector('[data-nav="meeting-approvals"]');
    if (el) { el.classList.add("flex"); el.classList.remove("hidden"); }
  }
}

// ─── Fade-in helper ─────────────────────────────
function fadeInMain() {
  const main = document.querySelector("main");
  if (!main) return;
  main.style.opacity = "0";
  main.style.transition = "opacity 0.2s ease";
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      main.style.opacity = "1";
    });
  });
}

// ─── Main init ─────────────────────────────────
async function initSidebar(opts = {}) {
  const container = document.getElementById("appSidebar");
  if (!container) {
    console.warn("[Sidebar] #appSidebar not found");
    return;
  }

  // Use passed user OR fetch from cache
  let user = opts.user;
  if (!user) {
    user = await getCachedUser();
  }
  if (!user) return; // redirect đã xảy ra trong getCachedUser

  const activePage = opts.activePage || getActivePageFromURL();
  const role = user.role || "";

  // Inject sidebar
  container.innerHTML = SIDEBAR_HTML;

  applyRoleVisibility(role);
  highlightSidebarActive(activePage);

  const nav = container.querySelector("nav");
  if (nav) {
    nav.style.scrollbarWidth = "thin";
    nav.style.scrollbarColor = "#3f3f46 transparent";
  }

  // Click handlers
  document.querySelectorAll(".nav-item").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const href = link.getAttribute("href");
      if (href && href !== "#") {
        window.location.href = href;
      }
    });
  });

  document.getElementById("sidebarLogoutBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    clearSession();
  });

  window.addEventListener("storage", (e) => {
    if (e.key === "user" || e.key === "token") {
      initSidebar({ activePage });
    }
  });

  // Fade-in main content
  fadeInMain();

  // Resolve promise để page script biết user đã load xong
  if (typeof opts.onReady === "function") {
    opts.onReady(user);
  }

  // Expose user globally để page scripts dùng
  window._sidebarUser = user;
  return user;
}
