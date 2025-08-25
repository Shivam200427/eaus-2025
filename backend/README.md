# Backend - Flask API

## Setup

1. Install dependencies:
\`\`\`bash
pip install -r requirements.txt
\`\`\`

2. Copy environment variables:
\`\`\`bash
cp .env.example .env
\`\`\`

3. Fill in your credentials in `.env`

4. Run the server:
\`\`\`bash
python app.py
\`\`\`

## Environment Variables

See `.env.example` for all required variables.

## API Endpoints

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/profile` - Get user profile
- `GET /api/analytics/dashboard` - Admin dashboard data
- `GET /api/analytics/user-activity` - User activity logs
- `POST /api/analytics/track-login` - Track login event

## Deployment to Railway

1. Connect your GitHub repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy automatically on push to main branch
