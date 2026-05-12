# Local Development Setup — ApproveHub

Hướng dẫn chạy project trên máy local (máy của bạn) để test trước khi deploy lên VPS.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                         LOCAL MACHINE                        │
│                                                              │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  FRONTEND   │───▶│   BACKEND    │───▶│   MONGODB     │  │
│  │  :3000      │    │  :3001       │    │   ATLAS       │  │
│  │  (React)    │    │  (Express)   │    │   (cloud)     │  │
│  └─────────────┘    └──────┬───────┘    └───────────────┘  │
│                             │                                │
│  ┌─────────────┐    ┌──────▼───────┐                       │
│  │  BROWSER    │◀───│  N8N         │                       │
│  │             │    │  :5678        │                       │
│  └─────────────┘    │  (Docker)     │                       │
│                      └──────────────┘                       │
└──────────────────────────────────────────────────────────────┘

  N8N:         Docker (docker-compose.local.yml)
  Backend:     Node.js direct (npm run dev) — hot-reload
  Frontend:    Vite dev server (npm run dev) — hot-reload
  Database:    MongoDB Atlas (cloud, shared với VPS)
  Ports used:  3000 (frontend), 3001 (backend), 5678 (n8n)
```

## Prerequisites

- **Docker Desktop** / Docker Engine
- **Node.js 18+** (`node -v` để kiểm tra)
- **Git** (để pull code mới nhất)

---

## IMPORTANT: Stop Production Containers First

Production containers (trên VPS hoặc máy bạn) đang chạy trên cùng ports. Phải stop trước khi chạy local.

```bash
# Stop tất cả production containers
docker stop approval_frontend approval_backend approval_n8n approval_postgres

# Hoặc stop toàn bộ container có tên "approval_*"
docker stop $(docker ps --format "{{.Names}}" | grep "^approval_")
```

Sau khi test xong, muốn chạy lại production:
```bash
cd ~/automation_n8n
docker-compose up -d
```

---

## Step 1: Pull Code Mới Nhất

```bash
cd ~/automation_n8n
git pull
```

---

## Step 2: Install Dependencies

```bash
# Backend
cd backend && npm install && cd ..

# Frontend
cd frontend && npm install && cd ..
```

---

## Step 3: Chạy N8N Local (Docker)

```bash
# Khởi động N8N + PostgreSQL
docker compose -f docker-compose.local.yml up -d

# Kiểm tra
docker ps | grep n8n_local
# → n8n_local  Up
```

Mở: **http://localhost:5678**

> Lần đầu chạy, N8N yêu cầu tạo tài khoản. Tạo tài khoản admin.

---

## Step 4: Import N8N Workflows

Các workflow files nằm trong thư mục `n8n/`:

| File | Tên Workflow | Webhook Path |
|------|-------------|-------------|
| `wf1-leave-request.json` | WF1 - Leave Request | `webhook/leave-create` |
| `wf2-manager-decision.json` | WF2 - Manager Decision | `webhook/manager-decision` |
| `wf3-hr-decision.json` | WF3 - HR Decision | `webhook/hr-decision` |
| `wf4-auto-approve.json` | WF4 - Auto Approve (AI) | `webhook/auto-approve` |
| `wf5-return-early.json` | WF5 - Return Early | `webhook/return-early` |
| `wf6-cancel-leave.json` | WF6 - Cancel Leave | `webhook/cancel-leave` |
| `wf7-leave-reminder.json` | WF7 - Leave Reminder | (Cron, no webhook) |
| `wf8-update-leave.json` | WF8 - Update Leave | `webhook/update-leave` |

**Cách import:**

1. Mở **http://localhost:5678**
2. Menu bên trái → **Workflows** → **Import from File** (biểu tượng Upload)
3. Chọn file `n8n/wf1-leave-request.json`
4. Lặp lại với tất cả file trong bảng trên
5. Với mỗi workflow: mở → kiểm tra webhook path (trong node Webhook) → **Activate** (toggle bên phải)

> **Quan trọng:** Sau khi import, mỗi workflow cần được **Activate** thì mới nhận webhook. Toggle nút màu xanh "Inactive" → "Active".

---

## Step 5: Chạy Backend

```bash
cd backend
npm run dev
```

Output:
```
🚀 Server running on http://localhost:3001
🔗 Database connected: MongoDB Atlas
```

Backend chạy tại: **http://localhost:3001**

> `npm run dev` dùng **nodemon** để auto-reload khi code thay đổi.

Kiểm tra health:
```bash
curl http://localhost:3001/api/health
# → {"status":"ok","timestamp":"..."}
```

---

## Step 6: Chạy Frontend

Mở terminal mới:

```bash
cd frontend
npm run dev
```

Output:
```
  VITE v5.x.x  ready in xxx ms

  ➜  Local:   http://localhost:3000/
  ➜  Network: http://192.168.x.x:3000/
```

Frontend chạy tại: **http://localhost:3000**

---

## Step 7: Tạo Admin Users

```bash
cd scripts
node create-admin-users.js
```

Script tạo 2 tài khoản:
- **HR**: `phupc.23ite@vku.udn.vn` / `Manager@123`
- **Manager**: `tjpeter020@gmail.com` / `Manager@123`

Nếu muốn tạo tài khoản employee mới, đăng ký qua UI tại http://localhost:3000/register

---

## Step 8: Cấu Hình Manager Emails (Settings)

N8N workflow cần biết gửi email đến manager/HR nào. Cần set Settings trong MongoDB:

1. Đăng nhập http://localhost:3000 với tài khoản HR
2. Vào **Settings** (biểu tượng ⚙️)
3. Điền email cho mỗi department:

```
Manager Emails:
  IT:        phupc.23ite@vku.udn.vn
  Marketing: phupc.23ite@vku.udn.vn
  Finance:   phupc.23ite@vku.udn.vn
  Sales:     phupc.23ite@vku.udn.vn
HR Email:   phupc.23ite@vku.udn.vn
```

4. Nhấn **Save**

> Hoặc có thể insert trực tiếp vào MongoDB:
> ```javascript
> db.settings.updateOne(
>   { key: "manager_emails" },
>   { $set: { value: { IT: "phupc.23ite@vku.udn.vn", Marketing: "...", Finance: "...", Sales: "...", hrEmail: "phupc.23ite@vku.udn.vn" } } },
>   { upsert: true }
> )
> ```

---

## Testing Flow

### Test 1: Tạo đơn nghỉ phép 1 ngày (AI auto-approve)

```
1. Đăng nhập http://localhost:3000 (tài khoản employee)
2. Vào Leave Request → Điền: 1 ngày, lý do "Khám bệnh"
3. Submit
4. Kiểm tra:
   ✅ Database có record mới (status: approved, autoApproved: true)
   ✅ Email thông báo được gửi đến employee (AI approved)
   ✅ N8N workflow wf4 chạy thành công
```

### Test 2: Tạo đơn 2–3 ngày (Manager approve)

```
1. Đăng nhập employee → Leave Request → Điền: 2 ngày
2. Submit
3. Kiểm tra:
   ✅ Email gửi đến manager
   ✅ N8N wf1 chạy, gửi email thông báo
4. Mở email → click link approve
5. Kiểm tra:
   ✅ Đơn chuyển sang approved (vì ≤3 ngày)
   ✅ Email gửi cho employee thông báo kết quả
```

### Test 3: Tạo đơn 4+ ngày (Manager → HR approve)

```
1. Employee tạo đơn 5 ngày
2. Manager approve (email link)
3. Kiểm tra:
   ✅ HR nhận email yêu cầu approve cuối cùng
   ✅ HR approve/reject
   ✅ Employee nhận email kết quả cuối cùng
```

### Test 4: Cancel đơn

```
1. Employee tạo đơn pending
2. Employee vào My Leaves → Cancel
3. Kiểm tra:
   ✅ Status = cancelled
   ✅ Email thông báo hủy gửi cho employee
```

### Test 5: Dashboard Manager/HR

```
1. Đăng nhập với tài khoản Manager hoặc HR
2. Trang Dashboard hiển thị:
   - Số đơn pending chờ duyệt
   - Nút Approve/Reject trực tiếp trên dashboard
3. Approve/Reject từ dashboard
4. Kiểm tra: Backend gọi N8N → N8N gửi email kết quả
```

---

## URLs Tổng Hợp

| Service | Local URL | VPS URL |
|---------|-----------|---------|
| Frontend | http://localhost:3000 | https://approvehub.internalautomation.io.vn |
| Backend API | http://localhost:3001 | https://api.internalautomation.io.vn |
| N8N Dashboard | http://localhost:5678 | https://n8n.internalautomation.io.vn |

---

## Troubleshooting

### Lỗi "Port already in use"

```bash
# Kiểm tra port nào đang dùng
lsof -i :3000
lsof -i :3001
lsof -i :5678

# Stop process chiếm port
kill -9 <PID>

# Hoặc stop Docker container
docker stop approval_frontend approval_backend approval_n8n
```

### Lỗi N8N không nhận webhook

```bash
# Kiểm tra N8N đang chạy
docker ps | grep n8n

# Xem logs
docker logs -f n8n_local

# Kiểm tra workflow đã Activate chưa
# Trong N8N UI: workflows → bật toggle "Active"
```

### Lỗi MongoDB Connection

```bash
# Kiểm tra MONGO_URI trong backend/.env
cat backend/.env | grep MONGO_URI

# Test connection
mongosh "mongodb+srv://n8n:automation_n8n@cluster0.tywp9et.mongodb.net/approval_system" --eval "db.adminCommand('ping')"
```

### Lỗi "Email Manager chưa được cấu hình"

→ Cần set Settings theo **Step 8** ở trên.

### Lỗi CORS khi test từ browser

Backend đã cấu hình CORS cho `http://localhost:3000`. Kiểm tra:
```bash
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     http://localhost:3001/api/health
```

### Kiểm tra N8N workflow đã được trigger

Trong N8N UI: **Executions** (menu trái) → xem danh sách các lần chạy workflow gần đây.

---

## Scripts Hữu Ích

```bash
# Stop local development
docker compose -f docker-compose.local.yml down

# Restart N8N
docker restart n8n_local

# Xem logs N8N real-time
docker logs -f n8n_local

# Backend: restart khi code thay đổi (nodemon tự làm)
# Frontend: restart khi code thay đổi (Vite tự làm)

# Reset N8N database (⚠️ MẤT TẤT CẢ workflows!)
docker compose -f docker-compose.local.yml down -v
docker compose -f docker-compose.local.yml up -d

# Stop và xóa tất cả
docker compose -f docker-compose.local.yml down -v

# Chạy lại production
cd ~/automation_n8n
docker-compose up -d
```

---

## Backend Hot-Reload

Backend dùng **nodemon** để tự restart khi code thay đổi:

```bash
cd backend
npm run dev
# Nodemon watch: src/**/*.js → restart tự động
```

---

## Deploy Lên VPS

Sau khi test local OK, deploy lên VPS:

```bash
# 1. Pull code mới lên VPS
git pull

# 2. Build lại Docker images
docker-compose build

# 3. Import workflows mới vào N8N trên VPS
#    (nếu có thay đổi trong n8n/*.json)

# 4. Restart
docker-compose up -d

# 5. Kiểm tra logs
docker-compose logs -f
```
