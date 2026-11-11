<<<<<<< HEAD
# Lost & Found Portal (Node.js + Express + SQLite, built into Node, no extra install)

## Run
1. Install Node.js 22.13 or newer (the LTS version is fine) from https://nodejs.org
=======
<<<<<<< HEAD
# Lost & Found Portal (Node.js + Express + SQLite)

## Run
1. Install Node.js 18+ from https://nodejs.org
>>>>>>> e95a1d5b7278d588c4f41dc76094a8e246cf4510
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
<<<<<<< HEAD
- The first screen is Log in. New users tap Sign up (name, email, phone, student/staff/public, department, password, security question); these details appear automatically in the Account tab and can be edited there.
- Forgot password: enter your email, answer your security question, set a new password. Admin login is a small link at the bottom of the login page.
- New reports and edits are "pending" until an admin approves them.
- Home page has quick Lost/Found buttons, a how-it-works guide, FAQ and safety tips; item pages suggest possible matches and can be shared on WhatsApp.
- Contact details are shown only to logged-in users, when "Show contact" is tapped.
- Photos are saved in `uploads/`, data in `lostfound.db` (both created automatically).
Hosting tip: set the DATA_DIR environment variable to a persistent disk path so the database and photos survive restarts.
=======
- New reports are saved as "pending" and appear publicly only after admin approval.
- Contact details are never in the public list; they load only when "Show contact" is tapped.
- Photos are saved in `uploads/`, data in `lostfound.db` (both created automatically).
=======
# lost-and-found-portal
>>>>>>> 7230f0c2b6ab15a6f4a0e441af04f1cb54f147d9
>>>>>>> e95a1d5b7278d588c4f41dc76094a8e246cf4510
