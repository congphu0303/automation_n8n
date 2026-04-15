/**
 * Shared Sidebar Component — injects + manages sidebar across all pages.
 *
 * Cách dùng:
 *   1. Thêm vào mỗi trang HTML (thay thế aside):
 *        <div id="appSidebar"></div>
 *        <script src="sidebar.js"></script>
 *
 *   2. Gọi ở cuối <script>:
 *        initSidebar({ activePage: "index", user });
 *
 * Lưu ý: Mỗi trang đã có <div id="loadingOverlay"> riêng, giữ nguyên.
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
    <!-- Dashboard + Leave — luôn hiển thị -->
    <a href="index.html" data-nav="index" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-grip text-base w-5"></i> Dashboard
    </a>
    <a href="leave.html" data-nav="leave" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-calendar-check text-base w-5"></i> Leave Request
    </a>

    <!-- Approvals — manager + hr -->
    <a href="approvals.html" data-nav="approvals" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-clipboard-check text-base w-5"></i> Approvals
    </a>

    <!-- Settings — chỉ hr -->
    <a href="settings.html" data-nav="settings" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-gear text-base w-5"></i> Settings
    </a>

    <div class="my-2 border-t border-zinc-800"></div>

    <!-- Meeting Rooms — luôn hiển thị -->
    <a href="rooms.html" data-nav="rooms" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-door-open text-base w-5"></i> Meeting Rooms
    </a>
    <a href="book-room.html" data-nav="book-room" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-calendar-plus text-base w-5"></i> Book Room
    </a>
    <a href="booking-dashboard.html" data-nav="booking-dashboard" class="nav-item hidden flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors">
      <i class="fa-solid fa-list text-base w-5"></i> My Bookings
    </a>

    <!-- Room Approvals — chỉ manager -->
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
 * Highlight active nav link.
 * @param {string} activePage
 */
function highlightSidebarActive(activePage) {
  document.querySelectorAll(".nav-item").forEach(link => {
    const isActive = link.getAttribute("data-nav") === activePage;
    if (isActive) {
      link.classList.remove("text-zinc-400", "hover:bg-zinc-800", "hover:text-zinc-100");
      link.classList.add("bg-blue-600", "text-white");
    }
  });
}

/**
 * Main init — inject sidebar into #appSidebar, apply role visibility, highlight active.
 * @param {Object} opts
 * @param {string} opts.activePage  - "index" | "leave" | "approvals" | ...
 * @param {Object} opts.user         - user object { id, name, email, department, role }
 */
function initSidebar(opts = {}) {
  const container = document.getElementById("appSidebar");
  if (!container) return;

  // Inject sidebar HTML
  container.innerHTML = SIDEBAR_HTML;

  const role = opts.user?.role || "";
  const activePage = opts.activePage || "";

  // ── Role-based visibility ──
  // Dashboard + Leave — always visible
  ["index", "leave"].forEach(page => {
    document.querySelector(`[data-nav="${page}"]`)?.classList.add("flex");
    document.querySelector(`[data-nav="${page}"]`)?.classList.remove("hidden");
  });

  // Meeting Rooms — always visible
  ["rooms", "book-room", "booking-dashboard"].forEach(page => {
    document.querySelector(`[data-nav="${page}"]`)?.classList.add("flex");
    document.querySelector(`[data-nav="${page}"]`)?.classList.remove("hidden");
  });

  // Approvals — manager + hr
  if (role === "manager" || role === "hr") {
    document.querySelector('[data-nav="approvals"]')?.classList.add("flex");
    document.querySelector('[data-nav="approvals"]')?.classList.remove("hidden");
  }

  // Settings — only hr
  if (role === "hr") {
    document.querySelector('[data-nav="settings"]')?.classList.add("flex");
    document.querySelector('[data-nav="settings"]')?.classList.remove("hidden");
  }

  // Room Approvals — only manager
  if (role === "manager") {
    document.querySelector('[data-nav="meeting-approvals"]')?.classList.add("flex");
    document.querySelector('[data-nav="meeting-approvals"]')?.classList.remove("hidden");
  }

  // ── Highlight active ──
  highlightSidebarActive(activePage);

  // ── Sidebar custom scrollbar ──
  const nav = container.querySelector("nav");
  if (nav) {
    nav.style.scrollbarWidth = "thin";
    nav.style.scrollbarColor = "#3f3f46 transparent";
  }

  // ── Logout ──
  document.getElementById("sidebarLogoutBtn")?.addEventListener("click", (e) => {
    e.preventDefault();
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "login.html";
  });
}
