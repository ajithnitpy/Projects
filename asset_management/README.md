# AssetTrack — Django Asset Management System

A comprehensive web-based asset management system built with Django 5 and Bootstrap 5.

---

## Features

- **Asset Inventory** — Auto-increment ID, inventory number/name, category, make/model, serial number, vendor, purchase details, image upload
- **Condition Tracking** — Working / Write Off / Condemned / Obsolete / Disposed
- **Warranty Calculation** — Active / Expiring Soon / Expired with exact days remaining
- **Incident Reporting** — Log and track asset incidents with severity levels
- **Upgrade History** — Record upgrades and modifications per asset
- **Department Scoping** — Users see only their assigned department's assets
- **Role-Based Access Control** — Administrator / Asset Manager / Editor / Viewer roles with granular permissions
- **User Management** — Create, edit, delete users with department and role assignment
- **Bulk Import/Export** — CSV & Excel for assets, categories, locations, departments
- **Download as ZIP** — Export all data + images in one archive
- **Activity Logs** — Full audit trail (create/edit/delete/import/export/login/logout)
- **Dashboard** — Charts, stats cards, recent activity feed
- **Custom Error Pages** — Branded 400/403/404/500 pages, no raw tracebacks

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation & Setup

### 1. Extract the project

```bash
unzip assettrack_project.zip
cd asset_management
```

### 2. Create and activate a virtual environment

**Windows:**
```powershell
python -m venv env
env\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv env
source env/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> If Pillow fails on Windows, install the pre-built binary:
> ```powershell
> pip install Pillow --only-binary=Pillow
> ```

### 4. Apply database migrations

```bash
python manage.py migrate
```

### 5. Create a superuser

```bash
python manage.py createsuperuser
```

Or load the sample data (creates `admin` / `admin@123` and 8 demo assets):

```bash
python manage.py loaddata initial_data.json
```

*(If no fixture file, the admin account must be created via `createsuperuser`.)*

### 6. Create the static directory (first run only)

```bash
mkdir -p static/css static/js
```

**Windows PowerShell:**
```powershell
New-Item -ItemType Directory -Force -Path static\css, static\js
```

### 7. Run the development server

```bash
python manage.py runserver
```

Open your browser at: **http://127.0.0.1:8000**

Default login: `admin` / `admin@123`

---

## Project Structure

```
asset_management/
├── asset_management/         # Project settings
│   ├── settings.py
│   ├── urls.py
│   ├── middleware.py         # Exception redirect middleware
│   └── wsgi.py
├── assets/                   # Core asset app
│   ├── models.py             # Asset, Category, Location, Department, ActivityLog
│   ├── views.py              # All asset views + department scoping
│   ├── forms.py              # Asset, filter, import forms
│   ├── resources.py          # Import/export resources
│   ├── admin.py              # Django admin config
│   ├── error_views.py        # Custom 400/403/404/500 handlers
│   └── templatetags/
│       └── asset_tags.py     # Custom template filters
├── accounts/                 # User & role management app
│   ├── models.py             # Role, UserProfile
│   ├── views.py              # Login/logout, user & role CRUD
│   ├── forms.py              # Login, user, role forms
│   ├── signals.py            # Auto-create UserProfile on User save
│   └── context_processors.py
├── templates/
│   ├── base.html             # Sidebar layout
│   ├── assets/               # Asset templates
│   ├── accounts/             # Auth & user templates
│   └── errors/               # 400/403/404/500 error pages
├── static/                   # Static files (CSS/JS)
├── media/                    # Uploaded asset images & avatars
├── requirements.txt
└── manage.py
```

---

## Default Roles & Permissions

| Permission | Administrator | Asset Manager | Editor | Viewer |
|---|:---:|:---:|:---:|:---:|
| View Assets | ✅ | ✅ | ✅ | ✅ |
| Add Assets | ✅ | ✅ | ✅ | ❌ |
| Edit Assets | ✅ | ✅ | ✅ | ❌ |
| Delete Assets | ✅ | ❌ | ❌ | ❌ |
| Import / Export | ✅ | ✅ | ❌ | ❌ |
| Manage Users | ✅ | ❌ | ❌ | ❌ |
| Manage Roles | ✅ | ❌ | ❌ | ❌ |
| View Logs | ✅ | ✅ | ❌ | ❌ |

> **Department Scoping:** Users with role type `Editor` or `Viewer` who have a department assigned will only see assets belonging to that department.

---

## Department-Based Access

1. Go to **Administration → Users → Edit User**
2. Set the **Department** dropdown to the user's department
3. The user will now see only that department's assets on the dashboard and asset list

Admin and Asset Manager roles always see all assets regardless of department setting.

---

## Bulk Import Format

### Assets (CSV/Excel columns)
```
inventory_number, inventory_name, category, make, model, serial_number,
date_of_purchase (YYYY-MM-DD), year_of_purchase, purchase_price, vendor,
location, department, assigned_to,
working_status (active/inactive/under_repair/in_store/transferred),
condition (working/write_off/condemned/obsolete/disposed),
warranty_years
```

### Categories
```
name, description
```

### Locations
```
name, building, floor, room, address
```

### Departments
```
name, head, description
```

---

## Key URLs

| URL | Description |
|-----|-------------|
| `/` | Dashboard |
| `/assets/` | Asset list |
| `/assets/create/` | Add new asset |
| `/import/` | Bulk import |
| `/export/?type=assets&format=xlsx` | Export assets as Excel |
| `/download-zip/` | Download all data + images as ZIP |
| `/logs/` | Activity logs |
| `/accounts/users/` | User management |
| `/accounts/roles/` | Role management |
| `/accounts/profile/` | My profile |
| `/admin/` | Django admin panel |

---

## Common Issues

### `ModuleNotFoundError: No module named 'crispy_forms'`
```bash
pip install -r requirements.txt
```

### `Cannot use ImageField because Pillow is not installed`
```bash
pip install Pillow
# Windows if above fails:
pip install Pillow --only-binary=Pillow
```

### `staticfiles.W004 — static directory does not exist`
```bash
mkdir -p static/css static/js   # Linux/Mac
# Windows:
New-Item -ItemType Directory -Force -Path static\css, static\js
```

### `No module named 'dateutil'`
```bash
pip install python-dateutil
```

### After pulling latest changes, run:
```bash
pip install -r requirements.txt
python manage.py migrate
```

---

## Production Notes

- Change `SECRET_KEY` in `settings.py` to a strong random value
- Set `ALLOWED_HOSTS` to your actual domain(s)
- Use PostgreSQL instead of SQLite for production
- Run `python manage.py collectstatic` before deploying
- Serve media files via Nginx/Apache in production
- `DEBUG = False` is already set (production-safe by default)
