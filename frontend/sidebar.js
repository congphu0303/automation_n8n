/**
 * Shared Sidebar Component — injects + manages sidebar across all pages.
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
</aside>
`;

/**
 * Get current active page from URL
 */
function getActivePageFromURL() {
  const path = window.location.pathname;
  const filename = path.split("/").pop() || "index.html";
  return filename.replace(".html", "");
}

/**
 * Highlight active nav link
 */
function highlightSidebarActive(activePage) {
  document.querySelectorAll(".nav-item").forEach(link => {
    const isActive = link.getAttribute("data-nav") === activePage;
    link.classList.toggle("bg-blue-600", isActive);
    link.classList.toggle("text-white", isActive);
    if (!isActive) {
      link.classList.add("text-zinc-400", "hover:bg-zinc-800", "hover:text-zinc-100");
      link.classList.remove("bg-zinc-800");
    } else {
      link.classList.remove("text-zinc-400", "hover:bg-zinc-800", "hover:text-zinc-100");
    }
  });
}

/**
 * Apply role-based visibility
 */
function applyRoleVisibility(role) {
  const alwaysVisible = ["index", "leave", "my-leaves", "rooms", "book-room", "booking-dashboard"];
  alwaysVisible.forEach(page => {
    const el = document.querySelector(`[data-nav="${page}"]`);
    if (el) {
      el.classList.add("flex");
      el.classList.remove("hidden");
    }
  });

  if (role === "manager" || role === "hr") {
    const el = document.querySelector('[data-nav="approvals"]');
    if (el) {
      el.classList.add("flex");
      el.classList.remove("hidden");
    }
  }

  if (role === "hr") {
    const el = document.querySelector('[data-nav="settings"]');
    if (el) {
      el.classList.add("flex");
      el.classList.remove("hidden");
    }
  }

  if (role === "manager") {
    const el = document.querySelector('[data-nav="meeting-approvals"]');
    if (el) {
      el.classList.add("flex");
      el.classList.remove("hidden");
    }
  }
}

/**
 * Main init — inject sidebar into #appSidebar
 */
function initSidebar(opts = {}) {
  const container = document.getElementById("appSidebar");
  if (!container) {
    console.warn("[Sidebar] #appSidebar not found");
    return;
  }

  const activePage = opts.activePage || getActivePageFromURL();
  const user = opts.user || JSON.parse(localStorage.getItem("user") || "{}");
  const role = user?.role || "";

  container.innerHTML = SIDEBAR_HTML;

  applyRoleVisibility(role);
  highlightSidebarActive(activePage);

  const nav = container.querySelector("nav");
  if (nav) {
    nav.style.scrollbarWidth = "thin";
    nav.style.scrollbarColor = "#3f3f46 transparent";
  }

  // Navigation handler - intercept clicks for smooth transition
  document.querySelectorAll(".nav-item").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const href = link.getAttribute("href");
      if (href && href !== "#") {
        window.location.href = href;
      }
    });
  });

  // Logout handler
  document.getElementById("sidebarLogoutBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "login.html";
  });

  // Listen for storage changes (cross-tab sync)
  window.addEventListener("storage", (e) => {
    if (e.key === "user" || e.key === "token") {
      initSidebar({ activePage, user: JSON.parse(localStorage.getItem("user") || "{}") });
    }
  });
}