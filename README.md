# Lost & Found Portal (Node.js + Express + SQLite)

## Run
1. Install Node.js 18+ from https://nodejs.org
2. Open this folder in VS Code, then open the terminal (Ctrl + `)
3. `npm install`
4. `npm start`
5. Open http://localhost:3000

## Admin
Click the Admin tab. Default password: `admin123`.
Change it before sharing:
- Windows PowerShell: `$env:ADMIN_PASSWORD="mypassword"; npm start`
- Mac/Linux: `ADMIN_PASSWORD=mypassword npm start`

## How it works
- New reports are saved as "pending" and appear publicly only after admin approval.
- Contact details are never in the public list; they load only when "Show contact" is tapped.
- Photos are saved in `uploads/`, data in `lostfound.db` (both created automatically).
