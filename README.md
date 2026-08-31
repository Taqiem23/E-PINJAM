# E-PINJAM

Flask + SQLite equipment borrowing system for an ASEAN English interface.

## Included features

- Student registration with:
  - Full name
  - Email
  - Matric number
  - Class
  - Strong password
  - Confirm password
- Login/logout
- Forgot password with automatic 6-digit OTP sent through Brevo SMTP
- OTP verification and password reset
- Multiple equipment selection before one borrowing transaction
- Borrow and return workflow
- Lecturer/admin dashboard and borrowing records
- Admin can add and delete lecturer accounts
- Admin can add and delete equipment
- Equipment location is not used
- No QR-related UI or container
- No photos, camera, borrow_photo, return_photo or uploads folder

## Default administrator

**Email:** `admin@epinjam.local`  
**Password:** `Admin123!`

Use these credentials for the local/development installation.

## Brevo setup

Create a `.env` file from `.env.example` and fill in:

```env
SECRET_KEY=replace-with-a-long-random-secret
MAIL_SERVER=smtp-relay.brevo.com
MAIL_PORT=587
MAIL_USERNAME=YOUR_BREVO_SMTP_LOGIN
MAIL_PASSWORD=YOUR_BREVO_SMTP_KEY
MAIL_DEFAULT_SENDER=your-verified-sender@example.com
```

`MAIL_USERNAME` and `MAIL_PASSWORD` must come from your Brevo account. The sender email must be verified in Brevo.

**Never share your SMTP key publicly.**

## Run on Windows

```powershell
py -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000`.

SQLite is created automatically in `instance/epinjam.db`.


## Inventory & Equipment Images

The latest version supports:
- Admin upload of equipment images when adding an item.
- PNG, JPG, JPEG, GIF and WEBP images.
- Maximum image upload size: 5 MB.
- Equipment total quantity and current available quantity.
- Equipment images and stock display on the student Equipment page.
- Equipment images and stock display on the Admin/Lecturer Dashboard.
- When a student borrows one unit, available quantity decreases by 1.
- When the loan is returned, available quantity increases by the borrowed quantity.
- Existing SQLite databases are migrated automatically when the app starts.

### Admin login
- Email: `admin@epinjam.local`
- Password: `Admin123!`


### Physical Unit IDs
Each equipment quantity automatically receives physical unit IDs in the format `CODE#NUMBER`, for example `EQ001#1`, `EQ001#2`, and `EQ001#3`. When a student borrows an equipment type, the system automatically assigns the first available physical unit ID and records that exact ID in the loan history.

## Supabase PostgreSQL

For cloud deployment, set `DATABASE_URL` to your Supabase PostgreSQL connection
string as an environment variable. Do not hard-code the password in `app.py`.

If `DATABASE_URL` is not set, the application keeps using the local SQLite
database so existing local testing is not broken.

The first start with the Supabase URL will run `db.create_all()` and create
the SQLAlchemy tables in the PostgreSQL database.
