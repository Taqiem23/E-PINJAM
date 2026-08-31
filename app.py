import os, random, smtplib, json, mimetypes, urllib.error, urllib.request, urllib.parse
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-secret-key')
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()

# Supabase provides a PostgreSQL URL. Keep SQLite as a local fallback so
# the project still runs on the laptop before DATABASE_URL is configured.
if DATABASE_URL:
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///epinjam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB per upload

# Supabase Storage configuration.
# When these variables are present, equipment images are stored in Supabase
# Storage instead of Render/local disk.
SUPABASE_URL = os.getenv('SUPABASE_URL', '').strip().rstrip('/')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', '').strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY', '').strip()

SUPABASE_STORAGE_BUCKET = os.getenv(
    'SUPABASE_STORAGE_BUCKET',
    'equipment-images'
).strip()


db = SQLAlchemy(app)
OTP_MINUTES = 10

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    matric_no = db.Column(db.String(50), unique=True, nullable=True)
    class_name = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    created_at = db.Column(db.DateTime, default=datetime.now)

    loans = db.relationship('Loan', backref='student', lazy=True)


class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default='')
    status = db.Column(db.String(20), nullable=False, default='Available')

    # Inventory quantity
    quantity = db.Column(db.Integer, nullable=False, default=1)
    available_quantity = db.Column(db.Integer, nullable=False, default=1)

    # Relative path inside /static
    image_filename = db.Column(db.String(255), nullable=True)

    # Comma-separated physical unit IDs, e.g. EQ001#1,EQ001#2
    unit_codes = db.Column(db.Text, nullable=False, default='')

    created_at = db.Column(db.DateTime, default=datetime.now)

    loan_items = db.relationship('LoanItem', backref='equipment', lazy=True)


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    borrowed_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    returned_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), nullable=False, default='Borrowed')

    items = db.relationship(
        'LoanItem',
        backref='loan',
        lazy=True,
        cascade='all, delete-orphan'
    )


class LoanItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    # Exact physical unit assigned to this loan item, e.g. EQ001#1
    unit_code = db.Column(db.String(80), nullable=True)


class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)


def current_user():
    return db.session.get(User, session.get('user_id')) if session.get('user_id') else None


@app.context_processor
def globals_():
    return {
        'current_user': current_user(),
        'equipment_image_url': equipment_image_url,
    }


def login_required(view):
    @wraps(view)
    def w(*a, **k):
        if not current_user():
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return view(*a, **k)
    return w


def role_required(*roles):
    def deco(view):
        @wraps(view)
        def w(*a, **k):
            u = current_user()
            if not u:
                flash('Please log in first.', 'error')
                return redirect(url_for('login'))
            if u.role not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return view(*a, **k)
        return w
    return deco


def send_otp_email(recipient, otp):
    server = os.getenv('MAIL_SERVER', 'smtp-relay.brevo.com')
    port = int(os.getenv('MAIL_PORT', '587'))
    username = os.getenv('MAIL_USERNAME', '')
    password = os.getenv('MAIL_PASSWORD', '')
    sender = os.getenv('MAIL_DEFAULT_SENDER', username)

    if not username or not password or not sender:
        return False, 'Email settings are not configured in .env.'

    msg = EmailMessage()
    msg['Subject'] = 'E-PINJAM Password Reset OTP'
    msg['From'] = sender
    msg['To'] = recipient
    msg.set_content(
        f'Hello,\n\n'
        f'Your E-PINJAM password reset OTP is:\n\n{otp}\n\n'
        f'This OTP will expire in {OTP_MINUTES} minutes.\n\n'
        f'If you did not request a password reset, please ignore this email.\n\n'
        f'Regards,\nE-PINJAM'
    )

    try:
        with smtplib.SMTP(server, port, timeout=20) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
        return True, 'OTP sent successfully.'
    except Exception as e:
        print('EMAIL ERROR:', e)
        return False, 'Unable to send the OTP email. Please check your Brevo settings.'


def allowed_image(filename):
    return (
        filename
        and '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def supabase_storage_enabled():
    return bool(
        SUPABASE_URL
        and SUPABASE_SERVICE_ROLE_KEY
        and SUPABASE_STORAGE_BUCKET
    )


def supabase_storage_headers(content_type='application/json'):
    return {
        'apikey': SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_ROLE_KEY}',
        'Content-Type': content_type,
    }


def supabase_storage_request(method, path, data=None, content_type='application/json'):
    """Call the Supabase Storage REST API using only Python's standard library."""
    url = (
        f'{SUPABASE_URL}/storage/v1/'
        f'{path.lstrip("/")}'
    )

    req = urllib.request.Request(
        url,
        data=data,
        headers=supabase_storage_headers(content_type),
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        raise RuntimeError(
            f'Supabase Storage HTTP {e.code}: {body[:500]}'
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            f'Unable to reach Supabase Storage: {e.reason}'
        ) from e


def ensure_supabase_bucket():
    """Create the equipment bucket if it does not exist yet."""
    if not supabase_storage_enabled():
        return

    payload = json.dumps({
        'id': SUPABASE_STORAGE_BUCKET,
        'name': SUPABASE_STORAGE_BUCKET,
        'public': True,
    }).encode('utf-8')

    try:
        supabase_storage_request(
            'POST',
            'bucket',
            data=payload,
            content_type='application/json',
        )
    except RuntimeError as e:
        # Supabase returns a conflict when the bucket already exists.
        # A pre-existing private bucket still needs to be made public
        # in Supabase Dashboard.
        if '409' not in str(e) and 'already exists' not in str(e).lower():
            print('SUPABASE BUCKET WARNING:', e)


def supabase_object_path_from_value(value):
    """Return the Storage object path when image_filename contains a cloud URL."""
    if not value:
        return None

    prefix = (
        f'{SUPABASE_URL}/storage/v1/object/public/'
        f'{SUPABASE_STORAGE_BUCKET}/'
    )

    if value.startswith(prefix):
        return value[len(prefix):].split('?', 1)[0]

    # Also accept a stored relative object path such as equipment/abc.jpg.
    if not value.startswith(('http://', 'https://')) and value.startswith('equipment/'):
        return value

    return None


def supabase_public_image_url(object_path):
    return (
        f'{SUPABASE_URL}/storage/v1/object/public/'
        f'{SUPABASE_STORAGE_BUCKET}/{object_path}'
    )


def upload_equipment_image_to_supabase(file):
    if not file or not file.filename:
        return None

    if not allowed_image(file.filename):
        raise ValueError('Image must be PNG, JPG, JPEG or WEBP.')

    original = secure_filename(file.filename)
    ext = original.rsplit('.', 1)[1].lower()

    object_name = (
        f'equipment/'
        f'equipment_{datetime.now().strftime("%Y%m%d%H%M%S%f")}.{ext}'
    )

    data = file.read()
    if not data:
        raise ValueError('The selected image is empty.')

    content_type = mimetypes.guess_type(original)[0] or 'application/octet-stream'

    supabase_storage_request(
        'POST',
        f'object/{urllib.parse.quote(SUPABASE_STORAGE_BUCKET, safe="")}/'
        f'{urllib.parse.quote(object_name, safe="/")}',
        data=data,
        content_type=content_type,
    )

    return supabase_public_image_url(object_name)


def save_equipment_image(file):
    """Save an equipment image to cloud storage, with local fallback for development."""
    if not file or not file.filename:
        return None

    if not allowed_image(file.filename):
        raise ValueError('Image must be PNG, JPG, JPEG or WEBP.')

    if supabase_storage_enabled():
        try:
            return upload_equipment_image_to_supabase(file)
        except RuntimeError as e:
            raise ValueError(
                'Unable to upload the equipment image to Supabase Storage. '
                'Please check the Supabase Storage environment variables and bucket.'
            ) from e

    # Local fallback: useful when running on the laptop without cloud variables.
    upload_dir = os.path.join(app.static_folder, 'uploads', 'equipment')
    os.makedirs(upload_dir, exist_ok=True)

    original = secure_filename(file.filename)
    ext = original.rsplit('.', 1)[1].lower()
    filename = (
        f"equipment_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.{ext}"
    )
    file.save(os.path.join(upload_dir, filename))

    return f'uploads/equipment/{filename}'


def equipment_image_url(item):
    """Return a browser-accessible image URL for both cloud and old local images."""
    value = item.image_filename
    if not value:
        return None

    if value.startswith(('http://', 'https://')):
        return value

    return url_for('static', filename=value)


def delete_equipment_image(item):
    if not item.image_filename:
        return

    # Cloud image
    object_path = supabase_object_path_from_value(item.image_filename)
    if object_path and supabase_storage_enabled():
        payload = json.dumps({
            'prefixes': [object_path]
        }).encode('utf-8')
        try:
            supabase_storage_request(
                'POST',
                f'object/remove/{urllib.parse.quote(SUPABASE_STORAGE_BUCKET, safe="")}',
                data=payload,
                content_type='application/json',
            )
        except RuntimeError as e:
            print('SUPABASE IMAGE DELETE WARNING:', e)
        return

    # Old local image fallback
    path = os.path.join(app.static_folder, item.image_filename)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def migrate_local_images_to_supabase():
    """
    Move existing images referenced by local static paths into Supabase Storage.
    This lets the images already uploaded on the laptop become cloud images
    after the Storage environment variables are configured.
    """
    if not supabase_storage_enabled():
        return

    changed = False

    for item in Equipment.query.filter(Equipment.image_filename.isnot(None)).all():
        value = item.image_filename

        # Already a cloud URL.
        if value.startswith(('http://', 'https://')):
            continue

        if not value.startswith('uploads/equipment/'):
            continue

        local_path = os.path.join(app.static_folder, value)
        if not os.path.isfile(local_path):
            continue

        try:
            with open(local_path, 'rb') as f:
                data = f.read()

            filename = os.path.basename(value)
            object_path = f'equipment/{filename}'
            content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

            supabase_storage_request(
                'POST',
                f'object/{urllib.parse.quote(SUPABASE_STORAGE_BUCKET, safe="")}/'
                f'{urllib.parse.quote(object_path, safe="/")}',
                data=data,
                content_type=content_type,
            )

            item.image_filename = supabase_public_image_url(object_path)
            changed = True
            print(f'Migrated equipment image to Supabase: {filename}')
        except Exception as e:
            print(f'IMAGE MIGRATION WARNING for {value}: {e}')

    if changed:
        db.session.commit()


        pass


def make_unit_codes(code, quantity):
    return [f'{code}#{i}' for i in range(1, quantity + 1)]


def get_unit_codes(item):
    existing = [x.strip() for x in (item.unit_codes or '').split(',') if x.strip()]
    desired = make_unit_codes(item.code, max(1, item.quantity))
    # Keep valid existing IDs, then fill missing IDs from the standard sequence.
    result = []
    for x in desired:
        if x in existing or not existing:
            result.append(x)
    for x in existing:
        if x not in result and len(result) < item.quantity:
            result.append(x)
    return result[:item.quantity]


def available_unit_codes(item):
    all_units = get_unit_codes(item)
    borrowed = {
        li.unit_code for li in LoanItem.query.join(Loan).filter(
            LoanItem.equipment_id == item.id,
            Loan.status == 'Borrowed',
            LoanItem.unit_code.isnot(None)
        ).all()
    }
    return [u for u in all_units if u not in borrowed]


def migrate_database():
    """Add new inventory/image columns to an existing SQLite database."""
    db.create_all()

    inspector = db.inspect(db.engine)

    equipment_columns = {c['name'] for c in inspector.get_columns('equipment')}
    if 'is_active' not in equipment_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE equipment ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE"
            )
    if 'quantity' not in equipment_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE equipment ADD COLUMN quantity INTEGER NOT NULL DEFAULT 1"
            )
    if 'available_quantity' not in equipment_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE equipment ADD COLUMN available_quantity INTEGER NOT NULL DEFAULT 1"
            )
    if 'image_filename' not in equipment_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE equipment ADD COLUMN image_filename VARCHAR(255)"
            )
    if 'unit_codes' not in equipment_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE equipment ADD COLUMN unit_codes TEXT NOT NULL DEFAULT ''"
            )

    loan_item_columns = {c['name'] for c in inspector.get_columns('loan_item')}
    if 'quantity' not in loan_item_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE loan_item ADD COLUMN quantity INTEGER NOT NULL DEFAULT 1"
            )
    if 'unit_code' not in loan_item_columns:
        with db.engine.begin() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE loan_item ADD COLUMN unit_code VARCHAR(80)"
            )

    # Existing records were previously single physical items.
    # Keep their old availability meaning when upgrading.
    db.session.expire_all()
    for item in Equipment.query.all():
        if item.quantity < 1:
            item.quantity = 1
        if item.available_quantity < 0 or item.available_quantity > item.quantity:
            item.available_quantity = 0 if item.status == 'Borrowed' else item.quantity

        # Preserve old status while making stock values consistent.
        if item.status == 'Borrowed':
            item.available_quantity = min(item.available_quantity, item.quantity - 1)
        else:
            item.available_quantity = item.quantity

        item.unit_codes = ','.join(get_unit_codes(item))

    db.session.flush()

    # Give older active loan records a physical unit ID where possible.
    for item in Equipment.query.all():
        used = {
            li.unit_code for li in LoanItem.query.join(Loan).filter(
                LoanItem.equipment_id == item.id,
                Loan.status == 'Borrowed',
                LoanItem.unit_code.isnot(None)
            ).all()
        }
        for li in LoanItem.query.join(Loan).filter(
            LoanItem.equipment_id == item.id,
            Loan.status == 'Borrowed',
            LoanItem.unit_code.is_(None)
        ).all():
            choices = [u for u in get_unit_codes(item) if u not in used]
            if choices:
                li.unit_code = choices[0]
                used.add(choices[0])

    db.session.commit()


@app.route('/')
def home():
    return render_template(
        'home.html',
        equipment=Equipment.query.filter_by(
            is_active=True
        ).order_by(Equipment.id).all()
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user():
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        matric = request.form.get('matric_no', '').strip()
        cls = request.form.get('class_name', '').strip()
        pw = request.form.get('password', '')
        cp = request.form.get('confirm_password', '')
        errors = []

        if not all([name, email, matric, cls]):
            errors.append('Please complete all required student details.')
        if '@' not in email:
            errors.append('Please enter a valid email address.')
        if (
            len(pw) < 8
            or not any(c.isupper() for c in pw)
            or not any(c.islower() for c in pw)
            or not any(c.isdigit() for c in pw)
        ):
            errors.append(
                'Password must be at least 8 characters and include uppercase, lowercase and a number.'
            )
        if pw != cp:
            errors.append('Passwords do not match.')
        if User.query.filter_by(email=email).first():
            errors.append('That email is already registered.')
        if User.query.filter_by(matric_no=matric).first():
            errors.append('That matric number is already registered.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html')

        db.session.add(
            User(
                name=name,
                email=email,
                matric_no=matric,
                class_name=cls,
                password_hash=generate_password_hash(pw),
                role='student'
            )
        )
        db.session.commit()
        flash('Registration successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user():
        return redirect(url_for('home'))

    if request.method == 'POST':
        u = User.query.filter_by(
            email=request.form.get('email', '').strip().lower()
        ).first()
        pw = request.form.get('password', '')

        if u and check_password_hash(u.password_hash, pw):
            session.clear()
            session['user_id'] = u.id
            flash('Login successful.', 'success')
            return redirect(
                url_for('dashboard' if u.role in ('admin', 'lecturer') else 'equipment')
            )

        flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        u = User.query.filter_by(email=email).first()

        if u:
            PasswordResetOTP.query.filter_by(
                user_id=u.id, used=False
            ).update({'used': True})

            otp = f'{random.randint(0, 999999):06d}'
            db.session.add(
                PasswordResetOTP(
                    user_id=u.id,
                    otp_hash=generate_password_hash(otp),
                    expires_at=datetime.now() + timedelta(minutes=OTP_MINUTES)
                )
            )
            db.session.commit()

            ok, msg = send_otp_email(u.email, otp)
            if ok:
                session['reset_user_id'] = u.id
                flash('A password reset OTP has been sent to your email.', 'success')
                return redirect(url_for('verify_otp'))

            flash(msg, 'error')
        else:
            flash(
                'If that email is registered, a password reset OTP has been sent.',
                'success'
            )

    return render_template('forgot_password.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    uid = session.get('reset_user_id')
    if not uid:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        rec = PasswordResetOTP.query.filter_by(
            user_id=uid, used=False
        ).order_by(PasswordResetOTP.id.desc()).first()
        otp = request.form.get('otp', '').strip()

        if not rec or rec.expires_at < datetime.now():
            flash(
                'The OTP is invalid or has expired. Please request a new OTP.',
                'error'
            )
            return render_template('verify_otp.html')

        if not check_password_hash(rec.otp_hash, otp):
            flash('Incorrect OTP.', 'error')
            return render_template('verify_otp.html')

        session['otp_verified'] = True
        session['otp_record_id'] = rec.id
        return redirect(url_for('reset_password'))

    return render_template('verify_otp.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not session.get('reset_user_id') or not session.get('otp_verified'):
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        pw = request.form.get('password', '')
        cp = request.form.get('confirm_password', '')

        if (
            len(pw) < 8
            or not any(c.isupper() for c in pw)
            or not any(c.islower() for c in pw)
            or not any(c.isdigit() for c in pw)
        ):
            flash(
                'Password must be at least 8 characters and include uppercase, lowercase and a number.',
                'error'
            )
            return render_template('reset_password.html')

        if pw != cp:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')

        u = db.session.get(User, session['reset_user_id'])
        rec = db.session.get(
            PasswordResetOTP,
            session.get('otp_record_id')
        )

        if not u or not rec or rec.used or rec.expires_at < datetime.now():
            flash(
                'The password reset session has expired. Please start again.',
                'error'
            )
            session.pop('reset_user_id', None)
            session.pop('otp_verified', None)
            session.pop('otp_record_id', None)
            return redirect(url_for('forgot_password'))

        u.password_hash = generate_password_hash(pw)
        rec.used = True
        db.session.commit()

        session.pop('reset_user_id', None)
        session.pop('otp_verified', None)
        session.pop('otp_record_id', None)

        flash('Password updated successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


def get_borrow_selections():
    """Return the student's borrowing list in the current unit-selection format."""
    raw = session.get('borrow_list', [])
    selections = []

    # Backward compatibility for an older session containing only equipment IDs.
    for entry in raw:
        if isinstance(entry, dict):
            try:
                equipment_id = int(entry.get('equipment_id'))
            except (TypeError, ValueError):
                continue
            unit_code = str(entry.get('unit_code', '')).strip()
            if equipment_id and unit_code:
                selections.append({
                    'equipment_id': equipment_id,
                    'unit_code': unit_code
                })
        else:
            try:
                equipment_id = int(entry)
            except (TypeError, ValueError):
                continue
            item = db.session.get(Equipment, equipment_id)
            if item:
                units = available_unit_codes(item)
                if units:
                    selections.append({
                        'equipment_id': equipment_id,
                        'unit_code': units[0]
                    })

    return selections


@app.route('/equipment')
@login_required
def equipment():
    items = Equipment.query.filter_by(is_active=True).order_by(Equipment.id).all()
    available_units = {item.id: available_unit_codes(item) for item in items}
    return render_template(
        'equipment.html',
        equipment=items,
        available_units=available_units
    )


@app.route('/equipment/<int:equipment_id>')
@login_required
def equipment_detail(equipment_id):
    item = Equipment.query.filter_by(is_active=True).filter_by(id=equipment_id).first_or_404()
    return render_template(
        'equipment_detail.html',
        item=item,
        available_units=available_unit_codes(item)
    )


@app.route('/borrow-list')
@login_required
def borrow_list():
    selections = get_borrow_selections()
    session['borrow_list'] = selections
    ids = [s['equipment_id'] for s in selections]
    items = Equipment.query.filter(Equipment.is_active == True, Equipment.id.in_(ids)).all() if ids else []
    selected_units = {s['equipment_id']: s['unit_code'] for s in selections}
    return render_template(
        'borrow_list.html',
        equipment=items,
        selected_units=selected_units
    )


@app.post('/borrow-list/add/<int:equipment_id>')
@login_required
def add_to_borrow_list(equipment_id):
    item = Equipment.query.filter_by(is_active=True).filter_by(id=equipment_id).first_or_404()
    selected_unit = request.form.get('unit_code', '').strip()

    units = available_unit_codes(item)
    if not units:
        flash('This equipment is currently unavailable.', 'error')
        return redirect(url_for('equipment'))

    if selected_unit not in units:
        flash('Please select an available unit.', 'error')
        return redirect(url_for('equipment'))

    selections = get_borrow_selections()

    # Keep one selected physical unit per equipment type.
    if any(s['equipment_id'] == item.id for s in selections):
        flash('This equipment is already in your borrowing list.', 'error')
        return redirect(url_for('equipment'))

    if any(s['unit_code'] == selected_unit for s in selections):
        flash('That unit is already selected.', 'error')
        return redirect(url_for('equipment'))

    selections.append({
        'equipment_id': item.id,
        'unit_code': selected_unit
    })
    session['borrow_list'] = selections
    flash(f'{item.name} ({selected_unit}) added to your borrowing list.', 'success')
    return redirect(url_for('equipment'))


@app.post('/borrow-list/remove/<int:equipment_id>')
@login_required
def remove_from_borrow_list(equipment_id):
    selections = get_borrow_selections()
    selections = [s for s in selections if s['equipment_id'] != equipment_id]
    session['borrow_list'] = selections
    return redirect(url_for('borrow_list'))


@app.post('/borrow')
@role_required('student')
def borrow():
    selections = get_borrow_selections()
    session['borrow_list'] = selections

    if not selections:
        flash('Your borrowing list is empty.', 'error')
        return redirect(url_for('equipment'))

    ids = [s['equipment_id'] for s in selections]
    items = Equipment.query.filter(Equipment.is_active == True, Equipment.id.in_(ids)).all()
    item_map = {item.id: item for item in items}

    if len(items) != len(set(ids)):
        flash('One or more selected equipment items could not be found.', 'error')
        return redirect(url_for('borrow_list'))

    # Re-check the exact physical units immediately before submitting.
    for selection in selections:
        item = item_map[selection['equipment_id']]
        units = available_unit_codes(item)
        if selection['unit_code'] not in units:
            flash(
                f'Unit {selection["unit_code"]} of {item.name} is no longer available. Please choose another unit.',
                'error'
            )
            return redirect(url_for('borrow_list'))

    loan = Loan(user_id=current_user().id, status='Borrowed')
    db.session.add(loan)
    db.session.flush()

    for selection in selections:
        item = item_map[selection['equipment_id']]
        selected_unit = selection['unit_code']

        item.available_quantity -= 1
        item.status = (
            'Available' if item.available_quantity > 0 else 'Borrowed'
        )

        db.session.add(
            LoanItem(
                loan_id=loan.id,
                equipment_id=item.id,
                quantity=1,
                unit_code=selected_unit
            )
        )

    db.session.commit()
    session['borrow_list'] = []
    flash('Borrowing transaction submitted successfully.', 'success')
    return redirect(url_for('my_loans'))


@app.route('/my-loans')
@role_required('student')
def my_loans():
    return render_template(
        'my_loans.html',
        loans=Loan.query.filter_by(
            user_id=current_user().id
        ).order_by(Loan.id.desc()).all()
    )


@app.post('/loan/<int:loan_id>/return')
@role_required('student')
def return_loan(loan_id):
    loan = Loan.query.filter_by(
        id=loan_id,
        user_id=current_user().id
    ).first_or_404()

    if loan.status != 'Borrowed':
        flash('This transaction has already been returned.', 'error')
        return redirect(url_for('my_loans'))

    loan.status = 'Returned'
    loan.returned_at = datetime.now()

    for line in loan.items:
        line.equipment.available_quantity = min(
            line.equipment.quantity,
            line.equipment.available_quantity + line.quantity
        )
        line.equipment.status = (
            'Available'
            if line.equipment.available_quantity > 0
            else 'Borrowed'
        )

    db.session.commit()
    flash('Equipment returned successfully.', 'success')
    return redirect(url_for('my_loans'))


@app.route('/dashboard')
@role_required('admin', 'lecturer')
def dashboard():
    items = Equipment.query.filter_by(is_active=True).order_by(Equipment.id).all()

    return render_template(
        'dashboard.html',
        total=Equipment.query.filter_by(is_active=True).count(),
        available=Equipment.query.filter(
            Equipment.is_active == True,
            Equipment.available_quantity > 0
        ).count(),
        borrowed=Equipment.query.filter(
            Equipment.is_active == True,
            Equipment.available_quantity < Equipment.quantity
        ).count(),
        total_units=sum(i.quantity for i in items),
        available_units=sum(i.available_quantity for i in items),
        loans=Loan.query.order_by(Loan.id.desc()).all(),
        equipment=items
    )


@app.route('/records')
@role_required('admin', 'lecturer')
def records():
    return render_template(
        'records.html',
        loans=Loan.query.order_by(Loan.id.desc()).all()
    )


@app.route('/admin/equipment', methods=['GET', 'POST'])
@role_required('admin')
def admin_equipment():
    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        quantity_raw = request.form.get('quantity', '1').strip()
        image = request.files.get('image')

        try:
            quantity = int(quantity_raw)
        except ValueError:
            quantity = 0

        if not code or not name:
            flash('Equipment code and name are required.', 'error')
        elif Equipment.query.filter_by(code=code).first():
            flash('That equipment code already exists.', 'error')
        elif quantity < 1:
            flash('Quantity must be at least 1.', 'error')
        else:
            image_filename = None

            try:
                image_filename = save_equipment_image(image)
            except ValueError as e:
                flash(str(e), 'error')
                return redirect(url_for('admin_equipment'))

            db.session.add(
                Equipment(
                    code=code,
                    name=name,
                    description=desc,
                    quantity=quantity,
                    available_quantity=quantity,
                    status='Available',
                    image_filename=image_filename,
                    unit_codes=','.join(make_unit_codes(code, quantity))
                )
            )
            db.session.commit()
            flash('Equipment added successfully.', 'success')
            return redirect(url_for('admin_equipment'))

    return render_template(
        'admin_equipment.html',
        equipment=Equipment.query.filter_by(is_active=True).order_by(Equipment.id).all()
    )


@app.post('/admin/equipment/<int:equipment_id>/delete')
@role_required('admin')
def delete_equipment(equipment_id):
    item = db.get_or_404(Equipment, equipment_id)

    if item.available_quantity < item.quantity:
        flash('Equipment cannot be deleted while any unit is borrowed.', 'error')
        return redirect(url_for('admin_equipment'))

    # Soft delete so existing LoanItem records keep a valid equipment_id.
    item.is_active = False
    item.status = 'Deleted'
    delete_equipment_image(item)
    item.image_filename = None
    db.session.commit()
    flash(f'{item.code} - {item.name} deleted successfully.', 'success')

    return redirect(url_for('admin_equipment'))


@app.route('/admin/lecturers', methods=['GET', 'POST'])
@role_required('admin')
def admin_lecturers():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        pw = request.form.get('password', '')

        if not name or not email or not pw:
            flash('Name, email and password are required.', 'error')
        elif (
            len(pw) < 8
            or not any(c.isupper() for c in pw)
            or not any(c.islower() for c in pw)
            or not any(c.isdigit() for c in pw)
        ):
            flash(
                'Password must be at least 8 characters and include uppercase, lowercase and a number.',
                'error'
            )
        elif User.query.filter_by(email=email).first():
            flash('That email is already registered.', 'error')
        else:
            db.session.add(
                User(
                    name=name,
                    email=email,
                    password_hash=generate_password_hash(pw),
                    role='lecturer'
                )
            )
            db.session.commit()
            flash('Lecturer account created successfully.', 'success')
            return redirect(url_for('admin_lecturers'))

    return render_template(
        'admin_lecturers.html',
        lecturers=User.query.filter_by(
            role='lecturer'
        ).order_by(User.name).all()
    )


@app.post('/admin/lecturers/<int:user_id>/delete')
@role_required('admin')
def delete_lecturer(user_id):
    u = User.query.filter_by(
        id=user_id,
        role='lecturer'
    ).first_or_404()

    if Loan.query.filter_by(user_id=user_id).first():
        flash(
            'This lecturer account has related records and cannot be deleted.',
            'error'
        )
    else:
        db.session.delete(u)
        db.session.commit()
        flash('Lecturer account deleted.', 'success')

    return redirect(url_for('admin_lecturers'))


def seed_database():
    migrate_database()

    admin_email = 'admin@epinjam.local'
    admin_password = 'Admin123!'
    admin = User.query.filter_by(email=admin_email).first()

    if not admin:
        db.session.add(
            User(
                name='System Admin',
                email=admin_email,
                password_hash=generate_password_hash(admin_password),
                role='admin'
            )
        )
    elif admin.role != 'admin':
        admin.role = 'admin'
        admin.name = 'System Admin'
        admin.password_hash = generate_password_hash(admin_password)

    if Equipment.query.count() == 0:
        db.session.add_all([
            Equipment(
                code='EQ001',
                name='Dell Laptop',
                description='Laptop for learning activities.',
                quantity=5,
                available_quantity=5,
                status='Available',
                unit_codes=','.join(make_unit_codes('EQ001', 5))
            ),
            Equipment(
                code='EQ002',
                name='Epson Projector',
                description='Projector for presentations.',
                quantity=2,
                available_quantity=2,
                status='Available',
                unit_codes=','.join(make_unit_codes('EQ002', 2))
            ),
            Equipment(
                code='EQ005',
                name='Extension Wire',
                description='Electrical extension cable.',
                quantity=10,
                available_quantity=10,
                status='Available',
                unit_codes=','.join(make_unit_codes('EQ005', 10))
            )
        ])

    db.session.commit()


with app.app_context():
    seed_database()
    if supabase_storage_enabled():
        ensure_supabase_bucket()
        migrate_local_images_to_supabase()

if __name__ == '__main__':
    app.run(debug=True)
