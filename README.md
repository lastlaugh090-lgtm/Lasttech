# Last Tech Backend

Real backend with SQLite database for the Last Tech app.

## Features
- User registration & login (JWT)
- Plans / Deposits (pending → admin approve)
- Withdrawals with date/time rules
- Tasks completion
- Referral system (₦200 when referral deposits)
- Admin panel API
- History & Support messages

## Quick Start (Local)

```bash
cd lasttech-backend
npm install
npm start
```

API runs at http://localhost:3000

## Deploy to Render (Free)

1. Create account at https://render.com
2. New → Web Service
3. Connect your GitHub repo (or upload)
4. Settings:
   - Build Command: `npm install`
   - Start Command: `npm start`
5. Add Environment Variables:
   - JWT_SECRET = (any long random text)
   - ADMIN_PASSWORD = admin123
6. Deploy

## Deploy to Railway

1. https://railway.app
2. New Project → Deploy from GitHub
3. Add the same environment variables
4. Deploy

## API Endpoints

### Auth
- POST /api/register
- POST /api/login
- POST /api/admin/login

### User
- GET /api/me
- POST /api/deposits
- POST /api/withdrawals
- POST /api/tasks/complete
- GET /api/tasks/completed
- GET /api/history
- POST /api/messages

### Admin
- GET /api/admin/stats
- GET /api/admin/deposits
- POST /api/admin/deposits/:id/approve
- POST /api/admin/deposits/:id/reject
- GET /api/admin/withdrawals
- POST /api/admin/withdrawals/:id/approve
- POST /api/admin/withdrawals/:id/reject
- GET /api/admin/users
- GET /api/admin/messages

## Admin Password
Default: admin123
Change it with ADMIN_PASSWORD environment variable.
