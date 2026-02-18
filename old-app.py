import os
import io
import csv
import enum
import secrets
from datetime import datetime, timedelta, date
from functools import wraps
from decimal import Decimal, ROUND_HALF_UP
from werkzeug.utils import secure_filename
from pathlib import Path


from flask import (
    Flask, request, jsonify, send_file, abort,
    render_template, redirect
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import or_ as sa_or

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_PATH = os.path.join(BASE_DIR, "restaurant.db")
print("USING DB:", DB_PATH)
print("DB EXISTS:", os.path.exists(DB_PATH))
print("DB SIZE:", os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else None)


app = Flask(
    __name__,
    template_folder=BASE_DIR,  # HTML files are here
    static_folder=os.path.join(BASE_DIR, "static") if os.path.isdir(os.path.join(BASE_DIR, "static")) else BASE_DIR,
    static_url_path="/static"
)
UPLOAD_DIR = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}


app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "api_login"

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def now_utc():
    return datetime.utcnow()


def money(x) -> Decimal:
    try:
        return Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def dec3(x) -> Decimal:
    try:
        return Decimal(str(x)).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.000")


def json_error(message, code=400):
    return jsonify({"success": False, "error": message}), code


def require_json():
    if not request.is_json:
        return json_error("Expected JSON body", 400)
    return None


def norm_role(role) -> str:
    return (role or "").strip().lower()


def role_is(*roles):
    if not current_user.is_authenticated:
        return False
    cur = norm_role(getattr(current_user, "role", ""))
    if cur == "admin":
        return True
    wanted = {norm_role(r) for r in roles}
    return cur in wanted


def require_roles(*roles):
    allowed = {norm_role(r) for r in roles}

    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            cur = norm_role(getattr(current_user, "role", ""))
            if cur != "admin" and cur not in allowed:
                return json_error("Forbidden: insufficient role", 403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def profile_page_for_role(role: str) -> str:
    r = norm_role(role)
    if r == "admin":
        return "/adminprofile.html"
    if r == "manager":
        return "/managerprofile.html"
    if r == "cashier":
        return "/cashierprofile.html"
    staff_roles = {"waiter", "staff", "chef/kitchen", "delivery rider"}
    if r in staff_roles:
        return "/staffprofile.html"
    return "/userprofile.html"


class TableStatus(str, enum.Enum):
    FREE = "free"
    OCCUPIED = "occupied"
    RESERVED = "reserved"
    CLEANING = "cleaning"


class OrderType(str, enum.Enum):
    DINE_IN = "dine_in"
    TAKEAWAY = "takeaway"
    DELIVERY = "delivery"


class OrderStatus(str, enum.Enum):
    DRAFT = "draft"
    PENDING = "pending"
    COOKING = "cooking"
    READY = "ready"
    SERVED = "served"
    CANCELLED = "cancelled"
    DELIVERING = "delivering"
    COMPLETED = "completed"


class TicketStatus(str, enum.Enum):
    RECEIVED = "received"
    COOKING = "cooking"
    READY = "ready"


class ReservationStatus(str, enum.Enum):
    BOOKED = "booked"
    ARRIVED = "arrived"
    NO_SHOW = "no_show"
    CANCELLED = "cancelled"


class DeliveryStatus(str, enum.Enum):
    ASSIGNED = "assigned"
    PICKED_UP = "picked_up"
    DELIVERED = "delivered"
    FAILED = "failed"


def order_status_ui(status_value, delivery_status_value=None):
    mapping = {
        OrderStatus.DRAFT.value: {"label": "Draft", "step": "draft"},
        OrderStatus.PENDING.value: {"label": "Order submitted", "step": "submitted"},
        OrderStatus.COOKING.value: {"label": "Preparing", "step": "preparing"},
        OrderStatus.READY.value: {"label": "Ready", "step": "ready"},
        OrderStatus.SERVED.value: {"label": "Served", "step": "served"},
        OrderStatus.DELIVERING.value: {"label": "Out for delivery", "step": "out_for_delivery"},
        OrderStatus.COMPLETED.value: {"label": "Delivered", "step": "delivered"},
        OrderStatus.CANCELLED.value: {"label": "Cancelled", "step": "cancelled"},
    }
    ui = mapping.get(status_value, {"label": status_value, "step": status_value})

    if status_value == OrderStatus.DELIVERING.value and delivery_status_value:
        if delivery_status_value == DeliveryStatus.ASSIGNED.value:
            ui = {"label": "Rider assigned", "step": "rider_assigned"}
        elif delivery_status_value == DeliveryStatus.PICKED_UP.value:
            ui = {"label": "Picked up", "step": "picked_up"}
        elif delivery_status_value == DeliveryStatus.DELIVERED.value:
            ui = {"label": "Delivered", "step": "delivered"}
        elif delivery_status_value == DeliveryStatus.FAILED.value:
            ui = {"label": "Delivery failed", "step": "delivery_failed"}

    return ui


# ---------------------------
# Models (including missing ones referenced later)
# ---------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40))
    email = db.Column(db.String(160), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="Waiter")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_utc)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_id(self):
        return str(self.id)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(80), nullable=False)
    entity = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.Integer)
    ip = db.Column(db.String(80))
    details_json = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=now_utc)


class Settings(db.Model):
    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.String(1000), nullable=False)


def setting_get(key, default=None):
    row = Settings.query.filter_by(key=str(key)).first()
    if not row:
        return default
    return row.value


def setting_set(key, value):
    k = str(key)
    v = "" if value is None else str(value)
    row = Settings.query.filter_by(key=k).first()
    if not row:
        row = Settings(key=k, value=v)
        db.session.add(row)
    else:
        row.value = v
    db.session.commit()
    return v


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False, unique=True)
    is_active = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=False)

    name = db.Column(db.String(180), nullable=False)
    description = db.Column(db.String(500))
    base_price = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    tax_class = db.Column(db.String(40), default="standard")
    cost_price = db.Column(db.Numeric(10, 2), default=0)

    image_path = db.Column(db.String(300))
    is_available = db.Column(db.Boolean, default=True)
    prep_minutes = db.Column(db.Integer, default=0)
    tags = db.Column(db.String(300))

    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class ItemVariant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class ModifierGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    min_select = db.Column(db.Integer, default=0)
    max_select = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)


class ModifierOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("modifier_group.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    is_active = db.Column(db.Boolean, default=True)


class ItemModifierLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("modifier_group.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("item_id", "group_id", name="uq_item_group"),)


class Combo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    fixed_price = db.Column(db.Numeric(10, 2), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class ComboItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    combo_id = db.Column(db.Integer, db.ForeignKey("combo.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"), nullable=False)
    qty = db.Column(db.Integer, default=1)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    phone = db.Column(db.String(40))
    email = db.Column(db.String(160), index=True)
    loyalty_points = db.Column(db.Integer, default=0)
    notes = db.Column(db.String(600))
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_utc)


class DiningTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(40), nullable=False, unique=True)
    capacity = db.Column(db.Integer, default=2)
    status = db.Column(db.String(30), default=TableStatus.FREE.value)
    notes = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=now_utc)
    updated_at = db.Column(db.DateTime, default=now_utc)


class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey("dining_table.id"), nullable=False)
    guest_name = db.Column(db.String(140), nullable=False)
    phone = db.Column(db.String(40))
    party_size = db.Column(db.Integer, default=2)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    deposit = db.Column(db.Numeric(10, 2), default=0)
    status = db.Column(db.String(30), default=ReservationStatus.BOOKED.value)
    created_at = db.Column(db.DateTime, default=now_utc)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(60), unique=True, index=True)
    order_type = db.Column(db.String(30), default=OrderType.DINE_IN.value)
    status = db.Column(db.String(30), default=OrderStatus.DRAFT.value)

    table_id = db.Column(db.Integer, db.ForeignKey("dining_table.id"))
    waiter_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"))

    discount_type = db.Column(db.String(20), default="none")
    discount_value = db.Column(db.Numeric(10, 2), default=0)
    service_charge = db.Column(db.Numeric(10, 2), default=0)
    vat_rate = db.Column(db.Numeric(6, 4), default=0)

    delivery_address = db.Column(db.String(500))
    delivery_maps_link = db.Column(db.String(500))
    delivery_fee = db.Column(db.Numeric(10, 2), default=0)
    rider_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    delivery_status = db.Column(db.String(30))

    subtotal = db.Column(db.Numeric(10, 2), default=0)
    tax_total = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)

    created_at = db.Column(db.DateTime, default=now_utc)
    confirmed_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    cancelled_reason = db.Column(db.String(300))


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)

    item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"))
    combo_id = db.Column(db.Integer, db.ForeignKey("combo.id"))
    variant_id = db.Column(db.Integer, db.ForeignKey("item_variant.id"))

    name_snapshot = db.Column(db.String(200), nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    qty = db.Column(db.Integer, default=1)
    note = db.Column(db.String(300))

    is_void = db.Column(db.Boolean, default=False)
    void_reason = db.Column(db.String(300))

    created_at = db.Column(db.DateTime, default=now_utc)


class OrderItemModifier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_item_id = db.Column(db.Integer, db.ForeignKey("order_item.id"), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey("modifier_option.id"), nullable=False)
    name_snapshot = db.Column(db.String(160), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False, default=0)


class KitchenTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    status = db.Column(db.String(30), default=TicketStatus.RECEIVED.value)
    created_at = db.Column(db.DateTime, default=now_utc)
    updated_at = db.Column(db.DateTime, default=now_utc)


class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    phone = db.Column(db.String(60))
    email = db.Column(db.String(160))
    address = db.Column(db.String(400))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_utc)


class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), unique=True, nullable=False)
    unit = db.Column(db.String(30), default="pcs")
    stock_qty = db.Column(db.Numeric(14, 3), default=0)
    low_stock_threshold = db.Column(db.Numeric(14, 3), default=0)
    is_active = db.Column(db.Boolean, default=True)


class StockLedger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ingredient_id = db.Column(db.Integer, db.ForeignKey("ingredient.id"), nullable=False)
    change_qty = db.Column(db.Numeric(14, 3), nullable=False, default=0)
    reason = db.Column(db.String(80), nullable=False)
    ref_type = db.Column(db.String(50))
    ref_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=now_utc)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("menu_item.id"), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=now_utc)


class RecipeLine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey("recipe.id"), nullable=False)
    ingredient_id = db.Column(db.Integer, db.ForeignKey("ingredient.id"), nullable=False)
    qty_per_item = db.Column(db.Numeric(14, 3), nullable=False, default=0)


class PurchaseOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("supplier.id"), nullable=False)
    status = db.Column(db.String(30), default="open")
    total_cost = db.Column(db.Numeric(12, 2), default=0)
    invoice_path = db.Column(db.String(400))
    created_at = db.Column(db.DateTime, default=now_utc)
    received_at = db.Column(db.DateTime)


class PurchaseOrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    po_id = db.Column(db.Integer, db.ForeignKey("purchase_order.id"), nullable=False)
    ingredient_id = db.Column(db.Integer, db.ForeignKey("ingredient.id"), nullable=False)
    qty = db.Column(db.Numeric(14, 3), nullable=False)
    unit_cost = db.Column(db.Numeric(12, 2), nullable=False)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False, index=True)
    method = db.Column(db.String(40), nullable=False, default="cash")
    amount = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    reference = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=now_utc)


# ---------------------------
# Auth wiring
# ---------------------------

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


@login_manager.unauthorized_handler
def _unauthorized():
    if request.path.startswith("/api/"):
        return json_error("Authentication required", 401)
    return redirect("/")


@app.errorhandler(403)
def _err_403(_e):
    if request.path.startswith("/api/"):
        return json_error("Forbidden", 403)
    return render_template("index.html"), 403


@app.errorhandler(404)
def _err_404(_e):
    if request.path.startswith("/api/"):
        return json_error("Not found", 404)
    return render_template("index.html"), 404


def audit(action, entity, entity_id=None, details=None):
    try:
        uid = int(current_user.id) if current_user and getattr(current_user, "is_authenticated", False) else None
    except Exception:
        uid = None

    log = AuditLog(
        user_id=uid,
        action=action,
        entity=entity,
        entity_id=entity_id,
        ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        details_json=(details or {}),
        created_at=now_utc()
    )
    db.session.add(log)
    db.session.commit()


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return "", 204


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/adminprofile.html", methods=["GET"])
@login_required
def page_admin_profile():
    if not role_is("Admin"):
        abort(403)
    return render_template("adminprofile.html")


@app.route("/managerprofile.html", methods=["GET"])
@login_required
def page_manager_profile():
    if not role_is("Manager", "Admin"):
        abort(403)
    return render_template("managerprofile.html")


@app.route("/cashierprofile.html", methods=["GET"])
@login_required
def page_cashier_profile():
    if not role_is("Cashier", "Manager", "Admin"):
        abort(403)
    return render_template("cashierprofile.html")


@app.route("/staffprofile.html", methods=["GET"])
@login_required
def page_staff_profile():
    if not role_is("Waiter", "Staff", "Chef/Kitchen", "Delivery Rider", "Manager", "Admin"):
        abort(403)
    return render_template("staffprofile.html")


@app.route("/profile", methods=["GET"])
@login_required
def page_profile_redirect():
    return redirect(profile_page_for_role(current_user.role), code=302)


@app.route("/userprofile.html", methods=["GET"])
@login_required
def page_user_profile():
    return render_template("userprofile.html")


@app.get("/manage-items.html")
@login_required
def manage_items_page():
    return render_template("manage-items.html")


# ---------------------------
# Helpers
# ---------------------------

def customer_record_for_user(create_if_missing=True):
    if not current_user.is_authenticated:
        return None
    if norm_role(current_user.role) != "customer":
        return None
    email = (current_user.email or "").strip().lower()
    if not email:
        return None
    c = Customer.query.filter(db.func.lower(Customer.email) == email).first()
    if c:
        changed = False
        if current_user.name and c.name != current_user.name:
            c.name = current_user.name
            changed = True
        if current_user.phone and c.phone != current_user.phone:
            c.phone = current_user.phone
            changed = True
        if changed:
            db.session.commit()
        return c
    if not create_if_missing:
        return None
    c = Customer(
        name=current_user.name or "Customer",
        phone=current_user.phone,
        email=email,
        notes="",
        is_blocked=False
    )
    db.session.add(c)
    db.session.commit()
    return c


def order_accessible_to_current_user(order: Order) -> bool:
    if role_is("Manager", "Admin", "Cashier"):
        return True
    r = norm_role(current_user.role)
    if r == "delivery rider":
        return order.rider_id == current_user.id
    if r == "waiter":
        return order.waiter_id == current_user.id
    if r == "chef/kitchen":
        return order.status in (OrderStatus.PENDING.value, OrderStatus.COOKING.value, OrderStatus.READY.value)
    if r == "customer":
        c = customer_record_for_user(create_if_missing=False)
        return bool(c and order.customer_id == c.id)
    return False


def orders_query_for_current_user(q):
    if role_is("Manager", "Admin", "Cashier"):
        return q
    r = norm_role(current_user.role)
    if r == "delivery rider":
        return q.filter(Order.rider_id == current_user.id)
    if r == "waiter":
        return q.filter(Order.waiter_id == current_user.id)
    if r == "chef/kitchen":
        return q.filter(Order.status.in_([OrderStatus.PENDING.value, OrderStatus.COOKING.value, OrderStatus.READY.value]))
    if r == "customer":
        c = customer_record_for_user(create_if_missing=False)
        if not c:
            return q.filter(Order.id == -1)
        return q.filter(Order.customer_id == c.id)
    return q.filter(Order.id == -1)


def compute_order_totals(order: Order):
    items = OrderItem.query.filter_by(order_id=order.id).all()
    subtotal = Decimal("0.00")

    for oi in items:
        if oi.is_void:
            continue
        line = money(oi.unit_price) * Decimal(int(oi.qty))
        mods = OrderItemModifier.query.filter_by(order_item_id=oi.id).all()
        for m in mods:
            line += money(m.price) * Decimal(int(oi.qty))
        subtotal += line

    discount = Decimal("0.00")
    if order.discount_type == "percent":
        discount = (subtotal * money(order.discount_value) / Decimal("100.00")).quantize(Decimal("0.01"))
    elif order.discount_type == "fixed":
        discount = money(order.discount_value)

    after_discount = max(Decimal("0.00"), subtotal - discount)
    service_charge = money(order.service_charge or 0)
    vat_rate = Decimal(str(order.vat_rate or 0))
    tax_base = after_discount + service_charge + money(order.delivery_fee or 0)
    tax_total = (tax_base * vat_rate).quantize(Decimal("0.01"))

    total = (after_discount + service_charge + money(order.delivery_fee or 0) + tax_total).quantize(Decimal("0.01"))

    order.subtotal = subtotal
    order.tax_total = tax_total
    order.total = total

    return {
        "subtotal": str(subtotal),
        "discount": str(discount),
        "service_charge": str(service_charge),
        "delivery_fee": str(money(order.delivery_fee or 0)),
        "tax_total": str(tax_total),
        "total": str(total),
        "vat_rate": str(vat_rate)
    }


def next_order_no():
    prefix = setting_get("invoice_prefix", f"INV-{date.today().year}-")
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    count_today = Order.query.filter(Order.created_at >= today_start).count()
    return f"{prefix}{count_today + 1:06d}"


def stock_adjust(ingredient_id, change_qty, reason, ref_type="", ref_id=None):
    ing = Ingredient.query.get_or_404(ingredient_id)
    ing.stock_qty = (Decimal(str(ing.stock_qty)) + Decimal(str(change_qty))).quantize(Decimal("0.001"))
    db.session.add(StockLedger(
        ingredient_id=ingredient_id,
        change_qty=dec3(change_qty),
        reason=reason,
        ref_type=ref_type,
        ref_id=ref_id,
        created_at=now_utc()
    ))
    db.session.commit()


def apply_recipe_deduction(order: Order):
    items = OrderItem.query.filter_by(order_id=order.id).all()
    for oi in items:
        if oi.is_void or not oi.item_id:
            continue
        rec = Recipe.query.filter_by(item_id=oi.item_id).first()
        if not rec:
            continue
        lines = RecipeLine.query.filter_by(recipe_id=rec.id).all()
        for line in lines:
            qty = Decimal(str(line.qty_per_item)) * Decimal(int(oi.qty))
            stock_adjust(line.ingredient_id, -qty, "recipe", "order", order.id)


def paid_total_for_order(order_id: int) -> Decimal:
    rows = Payment.query.filter_by(order_id=order_id).all()
    total_paid = sum([money(p.amount) for p in rows], Decimal("0.00"))
    return total_paid.quantize(Decimal("0.01"))


def maybe_complete_order(o: Order):
    compute_order_totals(o)
    db.session.commit()
    total_paid = paid_total_for_order(o.id)
    if total_paid + Decimal("0.0001") >= money(o.total):
        if o.status not in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
            o.status = OrderStatus.COMPLETED.value
            o.completed_at = now_utc()
            db.session.commit()
            try:
                apply_recipe_deduction(o)
            except Exception:
                db.session.rollback()
            audit("complete", "order", o.id, {"paid": str(total_paid), "total": str(o.total)})
    return total_paid


def build_voucher_pdf_bytes(o: Order):
    if not REPORTLAB_OK:
        return None

    compute_order_totals(o)
    db.session.commit()

    items = OrderItem.query.filter_by(order_id=o.id).order_by(OrderItem.id.asc()).all()
    payments = Payment.query.filter_by(order_id=o.id).order_by(Payment.id.asc()).all()
    paid_total = paid_total_for_order(o.id)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    w, h = letter

    x = 48
    y = h - 48
    lh = 14

    restaurant_name = setting_get("restaurant_name", "My Restaurant")
    vat_rate = str(o.vat_rate or setting_get("vat_rate", "0.20"))

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x, y, str(restaurant_name))
    y -= 22

    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Order No: {o.order_no}")
    y -= lh
    c.drawString(x, y, f"Created: {o.created_at.isoformat() if o.created_at else ''}")
    y -= lh
    c.drawString(x, y, f"Type: {o.order_type}   Status: {o.status}")
    y -= lh

    if o.table_id:
        c.drawString(x, y, f"Table ID: {o.table_id}")
        y -= lh

    if o.delivery_address:
        c.drawString(x, y, "Delivery Address:")
        y -= lh
        c.setFont("Helvetica", 9)
        for line in str(o.delivery_address).splitlines():
            c.drawString(x + 14, y, line[:110])
            y -= 12
        c.setFont("Helvetica", 10)

    y -= 6
    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, "Items")
    y -= lh

    c.setFont("Helvetica", 10)
    for oi in items:
        if oi.is_void:
            continue
        line_total = money(oi.unit_price) * Decimal(int(oi.qty))
        mods = OrderItemModifier.query.filter_by(order_item_id=oi.id).order_by(OrderItemModifier.id.asc()).all()
        mod_total = sum([money(m.price) for m in mods], Decimal("0.00")) * Decimal(int(oi.qty))
        line_total = (line_total + mod_total).quantize(Decimal("0.01"))

        txt = f"{oi.qty} x {oi.name_snapshot} @ {money(oi.unit_price)} = {line_total}"
        c.drawString(x, y, txt[:110])
        y -= lh

        for m in mods:
            c.setFont("Helvetica", 9)
            c.drawString(x + 16, y, f"- {m.name_snapshot} ({money(m.price)})"[:110])
            y -= 12
            c.setFont("Helvetica", 10)

        if y < 90:
            c.showPage()
            y = h - 48
            c.setFont("Helvetica", 10)

    y -= 10
    totals = compute_order_totals(o)
    db.session.commit()

    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, "Totals")
    y -= lh
    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Subtotal: {totals['subtotal']}")
    y -= lh
    c.drawString(x, y, f"Discount: {totals['discount']}")
    y -= lh
    c.drawString(x, y, f"Service Charge: {totals['service_charge']}")
    y -= lh
    c.drawString(x, y, f"Delivery Fee: {totals['delivery_fee']}")
    y -= lh
    c.drawString(x, y, f"VAT Rate: {vat_rate}")
    y -= lh
    c.drawString(x, y, f"Tax Total: {totals['tax_total']}")
    y -= lh
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x, y, f"Grand Total: {totals['total']}")
    y -= 18

    c.setFont("Helvetica", 10)
    c.drawString(x, y, f"Paid Total: {paid_total}")
    y -= lh

    if payments:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(x, y, "Payments")
        y -= lh
        c.setFont("Helvetica", 10)
        for p in payments:
            c.drawString(x, y, f"{p.method}  {money(p.amount)}  {p.reference or ''}".strip()[:110])
            y -= lh
            if y < 90:
                c.showPage()
                y = h - 48
                c.setFont("Helvetica", 10)

    c.setFont("Helvetica", 9)
    c.drawString(x, 48, "Thank you.")
    c.showPage()
    c.save()

    buf.seek(0)
    return buf.getvalue()


# ---------------------------
# System init and seeding
# ---------------------------

@app.route("/api/system/init", methods=["POST"])
def api_system_init():
    db.create_all()

    if not setting_get("vat_rate"):
        setting_set("vat_rate", "0.20")
    if not setting_get("service_charge_enabled"):
        setting_set("service_charge_enabled", "false")
    if not setting_get("restaurant_name"):
        setting_set("restaurant_name", "My Restaurant")
    if not setting_get("invoice_prefix"):
        setting_set("invoice_prefix", f"INV-{date.today().year}-")

    if User.query.count() == 0:
        admin = User(name="Admin", email="admin@local", role="Admin", phone="")
        admin.set_password("admin12345")
        db.session.add(admin)
        db.session.commit()
        audit("seed", "user", admin.id, {"note": "Default admin created"})
        return jsonify({"success": True, "message": "Initialized. Default admin: admin@local / admin12345"})

    return jsonify({"success": True, "message": "Already initialized"})


@app.route("/api/system/seed-menu", methods=["POST"])
@require_roles("Admin", "Manager")
def api_seed_menu():
    db.create_all()

    if Category.query.filter_by(is_deleted=False).count() == 0:
        cats = ["Burgers", "Chicken", "Sides", "Drinks", "Desserts"]
        for nm in cats:
            db.session.add(Category(name=nm, is_active=True))
        db.session.commit()

    cat_map = {c.name: c.id for c in Category.query.filter_by(is_deleted=False).all()}

    if MenuItem.query.filter_by(is_deleted=False).count() == 0:
        items = [
            ("Burgers", "Classic Smash Burger", "Beef patty, cheese, sauce", "7.99", "smash,beef,cheese"),
            ("Burgers", "Double Smash Burger", "Two patties, extra cheese", "10.99", "double,beef,cheese"),
            ("Chicken", "Crispy Chicken Burger", "Crispy chicken, mayo, lettuce", "8.49", "chicken,crispy"),
            ("Sides", "Fries", "Salted fries", "3.49", "fries,sides"),
            ("Sides", "Loaded Fries", "Cheese, jalapeno, sauce", "5.99", "fries,loaded"),
            ("Drinks", "Cola", "330ml can", "1.99", "drink,cola"),
            ("Desserts", "Ice Cream", "Vanilla cup", "2.99", "dessert,icecream"),
        ]
        for cat_name, nm, desc, price, tags in items:
            db.session.add(MenuItem(
                category_id=cat_map.get(cat_name),
                name=nm,
                description=desc,
                base_price=money(price),
                tags=tags,
                is_available=True,
                prep_minutes=8 if cat_name in ("Burgers", "Chicken") else 2
            ))
        db.session.commit()

    if ModifierGroup.query.count() == 0:
        g1 = ModifierGroup(name="Add-ons", min_select=0, max_select=5, is_active=True)
        g2 = ModifierGroup(name="Sauces", min_select=0, max_select=3, is_active=True)
        db.session.add_all([g1, g2])
        db.session.commit()

        opts = [
            (g1.id, "Extra Cheese", "1.00"),
            (g1.id, "Bacon", "1.50"),
            (g1.id, "Jalapeno", "0.70"),
            (g2.id, "Ketchup", "0.00"),
            (g2.id, "Mayo", "0.00"),
            (g2.id, "Smash Sauce", "0.50"),
        ]
        for gid, nm, pr in opts:
            db.session.add(ModifierOption(group_id=gid, name=nm, price=money(pr), is_active=True))
        db.session.commit()

    burger = MenuItem.query.filter(MenuItem.name.like("%Burger%"), MenuItem.is_deleted.is_(False)).all()
    add_on = ModifierGroup.query.filter_by(name="Add-ons").first()
    sauces = ModifierGroup.query.filter_by(name="Sauces").first()
    for it in burger:
        for g in [add_on, sauces]:
            if g and not ItemModifierLink.query.filter_by(item_id=it.id, group_id=g.id).first():
                db.session.add(ItemModifierLink(item_id=it.id, group_id=g.id))
    db.session.commit()

    audit("seed", "menu", None, {"categories": Category.query.count(), "items": MenuItem.query.count()})
    return jsonify({"success": True})


# ---------------------------
# Auth
# ---------------------------

@app.route("/api/system/seed-admin", methods=["POST"])
def api_seed_admin_alias():
    return api_system_init()


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    pw = data.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if not user or not user.is_active or not user.check_password(pw):
        return json_error("Invalid credentials", 401)

    login_user(user)
    audit("login", "user", user.id)

    if norm_role(user.role) == "customer":
        customer_record_for_user(create_if_missing=True)

    return jsonify({
        "success": True,
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
        "redirect_url": profile_page_for_role(user.role)
    })


@app.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    audit("logout", "user", current_user.id)
    logout_user()
    return jsonify({"success": True})


@app.route("/api/auth/register", methods=["POST"])
def api_register():
    bad = require_json()
    if bad:
        return bad

    data = request.get_json()
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw = data.get("password") or ""

    if not name:
        return json_error("Name required", 400)
    if not email:
        return json_error("Email required", 400)
    if len(pw) < 8:
        return json_error("Password must be at least 8 characters", 400)
    if User.query.filter_by(email=email).first():
        return json_error("Email already used", 400)

    u = User(
        name=name,
        email=email,
        phone=None,
        role="Customer",
        is_active=True
    )
    u.set_password(pw)
    db.session.add(u)
    db.session.commit()
    audit("register", "user", u.id)

    login_user(u)
    audit("login", "user", u.id, {"note": "auto-login after register"})
    customer_record_for_user(create_if_missing=True)

    return jsonify({
        "success": True,
        "id": u.id,
        "user": {"id": u.id, "name": u.name, "email": u.email, "role": u.role},
        "redirect_url": profile_page_for_role(u.role)
    })


@app.route("/api/auth/me", methods=["GET"])
@login_required
def api_me():
    return jsonify({
        "success": True,
        "user": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "phone": current_user.phone,
            "role": current_user.role
        }
    })


@app.route("/api/profile", methods=["PUT"])
@login_required
def api_update_profile():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    current_user.name = data.get("name", current_user.name)
    current_user.phone = data.get("phone", current_user.phone)
    db.session.commit()
    if norm_role(current_user.role) == "customer":
        customer_record_for_user(create_if_missing=True)
    audit("update_profile", "user", current_user.id)
    return jsonify({"success": True})


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 8:
        return json_error("Password must be at least 8 characters", 400)
    if not current_user.check_password(old_pw):
        return json_error("Old password incorrect", 400)
    current_user.set_password(new_pw)
    db.session.commit()
    audit("change_password", "user", current_user.id)
    return jsonify({"success": True})


@app.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": True, "message": "If the account exists, a reset token was generated"})
    token = serializer.dumps({"uid": user.id, "email": user.email})
    audit("forgot_password", "user", user.id)
    return jsonify({"success": True, "reset_token": token})


@app.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    token = data.get("token") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 8:
        return json_error("Password must be at least 8 characters", 400)
    try:
        payload = serializer.loads(token, max_age=3600)
        user = User.query.get(int(payload["uid"]))
        if not user:
            return json_error("Invalid token", 400)
        user.set_password(new_pw)
        db.session.commit()
        audit("reset_password", "user", user.id)
        return jsonify({"success": True})
    except SignatureExpired:
        return json_error("Token expired", 400)
    except BadSignature:
        return json_error("Invalid token", 400)


# ---------------------------
# Users and staff CRUD
# ---------------------------

@app.route("/api/users", methods=["GET"])
@require_roles("Admin", "Manager")
def api_users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    out = []
    for u in users:
        out.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    return jsonify({"success": True, "users": out})


@app.route("/api/staff", methods=["GET"])
@require_roles("Admin", "Manager")
def api_staff_list():
    users = User.query.order_by(User.created_at.desc()).all()
    out = [{"id": u.id, "name": u.name, "email": u.email, "phone": u.phone, "role": u.role, "is_active": u.is_active} for u in users]
    return jsonify({"success": True, "users": out})


@app.route("/api/staff", methods=["POST"])
@require_roles("Admin", "Manager")
def api_staff_create():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    if not email or User.query.filter_by(email=email).first():
        return json_error("Email invalid or already used", 400)

    role = data.get("role") or "Waiter"
    pw = data.get("password") or "ChangeMe123"

    u = User(
        name=(data.get("name") or role),
        phone=data.get("phone"),
        email=email,
        role=role,
        is_active=bool(data.get("is_active", True))
    )
    u.set_password(pw)
    db.session.add(u)
    db.session.commit()
    audit("create", "user", u.id, {"role": role})
    return jsonify({"success": True, "id": u.id})


@app.route("/api/staff/<int:user_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_staff_update(user_id):
    bad = require_json()
    if bad:
        return bad
    u = User.query.get_or_404(user_id)
    data = request.get_json()
    u.name = data.get("name", u.name)
    u.phone = data.get("phone", u.phone)
    if "role" in data:
        u.role = data["role"]
    if "is_active" in data:
        u.is_active = bool(data["is_active"])
    if data.get("password"):
        u.set_password(data["password"])
    db.session.commit()
    audit("update", "user", u.id)
    return jsonify({"success": True})


@app.route("/api/users/<int:user_id>/active", methods=["PUT"])
@require_roles("Admin")
def api_user_set_active(user_id):
    bad = require_json()
    if bad:
        return bad
    u = User.query.get_or_404(user_id)

    data = request.get_json(silent=True) or {}
    if "is_active" not in data:
        return jsonify({"success": False, "error": "is_active is required"}), 400

    if u.id == current_user.id:
        return jsonify({"success": False, "error": "You cannot change your own active status"}), 400

    if norm_role(getattr(u, "role", "")) == "admin":
        return jsonify({"success": False, "error": "Admin account cannot be deactivated"}), 400

    u.is_active = bool(data["is_active"])
    db.session.commit()
    audit("set_active", "user", u.id, {"is_active": u.is_active})

    return jsonify({
        "success": True,
        "user": {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None
        }
    })


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_roles("Admin")
def api_user_delete_permanent(user_id):
    u = User.query.get_or_404(user_id)

    if u.id == current_user.id:
        return jsonify({"success": False, "error": "You cannot delete your own account"}), 400

    if norm_role(getattr(u, "role", "")) == "admin":
        return jsonify({"success": False, "error": "Admin account cannot be deleted"}), 400

    db.session.delete(u)
    db.session.commit()
    audit("delete", "user", user_id)
    return jsonify({"success": True})


# ---------------------------
# Shifts
# ---------------------------

@app.route("/api/shifts", methods=["GET"])
@require_roles("Admin", "Manager")
def api_shift_list():
    shifts = Shift.query.order_by(Shift.id.desc()).all()
    return jsonify({"success": True, "shifts": [{"id": s.id, "name": s.name, "start_time": s.start_time, "end_time": s.end_time, "is_active": s.is_active} for s in shifts]})


@app.route("/api/shifts", methods=["POST"])
@require_roles("Admin", "Manager")
def api_shift_create():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json()
    s = Shift(name=d["name"], start_time=d["start_time"], end_time=d["end_time"], is_active=True)
    db.session.add(s)
    db.session.commit()
    audit("create", "shift", s.id)
    return jsonify({"success": True, "id": s.id})


@app.route("/api/shifts/<int:shift_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_shift_update(shift_id):
    bad = require_json()
    if bad:
        return bad
    s = Shift.query.get_or_404(shift_id)
    d = request.get_json()
    if "name" in d:
        s.name = d["name"]
    if "start_time" in d:
        s.start_time = d["start_time"]
    if "end_time" in d:
        s.end_time = d["end_time"]
    if "is_active" in d:
        s.is_active = bool(d["is_active"])
    db.session.commit()
    audit("update", "shift", s.id)
    return jsonify({"success": True})


@app.route("/api/shifts/<int:shift_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_shift_delete(shift_id):
    s = Shift.query.get_or_404(shift_id)
    db.session.delete(s)
    db.session.commit()
    audit("delete", "shift", shift_id)
    return jsonify({"success": True})


# ---------------------------
# Settings
# ---------------------------

@app.route("/api/settings", methods=["GET"])
@require_roles("Admin", "Manager")
def api_settings_get():
    keys = [
        "restaurant_name", "vat_rate", "service_charge_enabled", "service_charge_default",
        "vat_rules_note", "invoice_prefix"
    ]
    return jsonify({"success": True, "settings": {k: setting_get(k) for k in keys}})


@app.route("/api/settings", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_settings_put():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json()
    for k, v in d.items():
        setting_set(str(k), str(v))
    audit("update", "settings", None, {"keys": list(d.keys())})
    return jsonify({"success": True})


# ---------------------------
# Categories CRUD
# ---------------------------

@app.route("/api/categories", methods=["GET"])
@login_required
def api_categories_list():
    cats = (
        Category.query
        .filter(sa_or(Category.is_deleted.is_(False), Category.is_deleted.is_(None)))
        .order_by(Category.name.asc())
        .all()
    )
    return jsonify({
        "success": True,
        "categories": [
            {"id": c.id, "name": c.name, "is_active": c.is_active}
            for c in cats
        ]
    })


@app.route("/api/categories", methods=["POST"])
@require_roles("Admin", "Manager")
def api_categories_create():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json()
    name = (d.get("name") or "").strip()
    if not name:
        return json_error("Name required", 400)
    if Category.query.filter(db.func.lower(Category.name) == name.lower(), Category.is_deleted.is_(False)).first():
        return json_error("Category name already exists", 400)
    c = Category(name=name, is_active=bool(d.get("is_active", True)))
    db.session.add(c)
    db.session.commit()
    audit("create", "category", c.id)
    return jsonify({"success": True, "id": c.id})


@app.route("/api/categories/<int:cat_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_categories_update(cat_id):
    bad = require_json()
    if bad:
        return bad
    c = Category.query.get_or_404(cat_id)
    d = request.get_json()
    if "name" in d:
        nm = (d["name"] or "").strip()
        if not nm:
            return json_error("Name required", 400)
        other = Category.query.filter(db.func.lower(Category.name) == nm.lower(), Category.id != c.id, Category.is_deleted.is_(False)).first()
        if other:
            return json_error("Category name already exists", 400)
        c.name = nm
    if "is_active" in d:
        c.is_active = bool(d["is_active"])
    db.session.commit()
    audit("update", "category", c.id)
    return jsonify({"success": True})


@app.route("/api/categories/<int:cat_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_categories_delete(cat_id):
    c = Category.query.get_or_404(cat_id)
    c.is_deleted = True
    db.session.commit()
    audit("delete", "category", c.id)
    return jsonify({"success": True})


# ---------------------------
# Items CRUD and menu query
# ---------------------------

@app.route("/api/menu", methods=["GET"])
@login_required
def api_menu_grouped():
    cats = (
        Category.query
        .filter(sa_or(Category.is_deleted.is_(False), Category.is_deleted.is_(None)))
        .order_by(Category.name.asc())
        .all()
    )

    out = []
    for c in cats:
        items = (
            MenuItem.query
            .filter(
                MenuItem.category_id == c.id,
                sa_or(MenuItem.is_deleted.is_(False), MenuItem.is_deleted.is_(None))
            )
            .order_by(MenuItem.name.asc())
            .all()
        )

        out.append({
            "id": c.id,
            "name": c.name,
            "is_active": c.is_active,
            "items": [{
                "id": it.id,
                "name": it.name,
                "description": it.description,
                "base_price": str(it.base_price),
                "is_available": it.is_available,
                "image_path": it.image_path,
                "prep_minutes": it.prep_minutes,
                "tags": it.tags
            } for it in items]
        })

    return jsonify({"success": True, "categories": out})


@app.route("/api/items", methods=["GET"])
@login_required
def api_items_list():
    q = MenuItem.query.filter(sa_or(MenuItem.is_deleted.is_(False), MenuItem.is_deleted.is_(None)))
    cat_id = request.args.get("category_id")
    if cat_id:
        try:
            q = q.filter(MenuItem.category_id == int(cat_id))
        except Exception:
            return json_error("Invalid category_id", 400)
    if request.args.get("q"):
        like = f"%{request.args['q']}%"
        q = q.filter(sa_or(MenuItem.name.like(like), MenuItem.description.like(like)))
    rows = q.order_by(MenuItem.name.asc()).limit(1000).all()
    return jsonify({"success": True, "items": [{
        "id": it.id,
        "category_id": it.category_id,
        "name": it.name,
        "description": it.description,
        "base_price": str(it.base_price),
        "tax_class": it.tax_class,
        "cost_price": str(it.cost_price),
        "image_path": it.image_path,
        "is_available": it.is_available,
        "prep_minutes": it.prep_minutes,
        "tags": it.tags
    } for it in rows]})


@app.route("/api/items", methods=["POST"])
@require_roles("Admin", "Manager")
def api_items_create():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json()

    cat_id = int(d.get("category_id") or 0)
    if not Category.query.filter_by(id=cat_id, is_deleted=False).first():
        return json_error("Invalid category_id", 400)

    nm = (d.get("name") or "").strip()
    if not nm:
        return json_error("Name required", 400)

    it = MenuItem(
        category_id=cat_id,
        name=nm,
        description=d.get("description"),
        base_price=money(d.get("base_price")),
        tax_class=d.get("tax_class", "standard"),
        cost_price=money(d.get("cost_price")),
        image_path=d.get("image_path"),
        is_available=bool(d.get("is_available", True)),
        prep_minutes=int(d.get("prep_minutes") or 0),
        tags=d.get("tags", "")
    )
    db.session.add(it)
    db.session.commit()
    audit("create", "menu_item", it.id)
    return jsonify({"success": True, "id": it.id})


@app.route("/api/items/<int:item_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_items_update(item_id):
    bad = require_json()
    if bad:
        return bad
    it = MenuItem.query.get_or_404(item_id)
    d = request.get_json()

    if "category_id" in d:
        cat_id = int(d["category_id"] or 0)
        if not Category.query.filter_by(id=cat_id, is_deleted=False).first():
            return json_error("Invalid category_id", 400)
        it.category_id = cat_id

    for field in ["name", "description", "tax_class", "image_path", "tags"]:
        if field in d:
            val = d[field]
            if field == "name":
                val = (val or "").strip()
                if not val:
                    return json_error("Name required", 400)
            setattr(it, field, val)

    if "base_price" in d:
        it.base_price = money(d["base_price"])
    if "cost_price" in d:
        it.cost_price = money(d["cost_price"])
    if "is_available" in d:
        it.is_available = bool(d["is_available"])
    if "prep_minutes" in d:
        it.prep_minutes = int(d["prep_minutes"] or 0)

    db.session.commit()
    audit("update", "menu_item", it.id)
    return jsonify({"success": True})


@app.route("/api/items/<int:item_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_items_delete(item_id):
    it = MenuItem.query.get_or_404(item_id)
    it.is_deleted = True
    db.session.commit()
    audit("delete", "menu_item", it.id)
    return jsonify({"success": True})


# ---------------------------
# Variants CRUD
# ---------------------------

@app.route("/api/items/<int:item_id>/variants", methods=["GET"])
@login_required
def api_variants_list(item_id):
    vs = ItemVariant.query.filter_by(item_id=item_id).order_by(ItemVariant.id.asc()).all()
    return jsonify({"success": True, "variants": [{"id": v.id, "name": v.name, "price": str(v.price), "is_active": v.is_active} for v in vs]})


@app.route("/api/items/<int:item_id>/variants", methods=["POST"])
@require_roles("Admin", "Manager")
def api_variants_create(item_id):
    bad = require_json()
    if bad:
        return bad
    if not MenuItem.query.filter_by(id=item_id, is_deleted=False).first():
        return json_error("Invalid item_id", 400)

    d = request.get_json()
    nm = (d.get("name") or "").strip()
    if not nm:
        return json_error("Variant name required", 400)

    v = ItemVariant(item_id=item_id, name=nm, price=money(d.get("price")), is_active=bool(d.get("is_active", True)))
    db.session.add(v)
    db.session.commit()
    audit("create", "item_variant", v.id, {"item_id": item_id})
    return jsonify({"success": True, "id": v.id})


@app.route("/api/variants/<int:variant_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_variants_update(variant_id):
    bad = require_json()
    if bad:
        return bad
    v = ItemVariant.query.get_or_404(variant_id)
    d = request.get_json()
    if "name" in d:
        nm = (d["name"] or "").strip()
        if not nm:
            return json_error("Variant name required", 400)
        v.name = nm
    if "price" in d:
        v.price = money(d["price"])
    if "is_active" in d:
        v.is_active = bool(d["is_active"])
    db.session.commit()
    audit("update", "item_variant", v.id)
    return jsonify({"success": True})


@app.route("/api/variants/<int:variant_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_variants_delete(variant_id):
    v = ItemVariant.query.get_or_404(variant_id)
    db.session.delete(v)
    db.session.commit()
    audit("delete", "item_variant", variant_id)
    return jsonify({"success": True})


# ---------------------------
# Modifier groups and options CRUD
# ---------------------------

@app.route("/api/modifier-groups", methods=["GET"])
@login_required
def api_modifier_groups_list():
    gs = ModifierGroup.query.order_by(ModifierGroup.id.desc()).all()
    return jsonify({"success": True, "groups": [{"id": g.id, "name": g.name, "min_select": g.min_select, "max_select": g.max_select, "is_active": g.is_active} for g in gs]})


@app.route("/api/modifier-groups", methods=["POST"])
@require_roles("Admin", "Manager")
def api_modifier_groups_create():
    bad = require_json()
    if bad:
        return bad
    d = request.get_json()
    nm = (d.get("name") or "").strip()
    if not nm:
        return json_error("Name required", 400)
    if ModifierGroup.query.filter(db.func.lower(ModifierGroup.name) == nm.lower()).first():
        return json_error("Group name already exists", 400)

    g = ModifierGroup(
        name=nm,
        min_select=int(d.get("min_select", 0)),
        max_select=int(d.get("max_select", 1)),
        is_active=bool(d.get("is_active", True))
    )
    db.session.add(g)
    db.session.commit()
    audit("create", "modifier_group", g.id)
    return jsonify({"success": True, "id": g.id})


@app.route("/api/modifier-groups/<int:group_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_modifier_groups_update(group_id):
    bad = require_json()
    if bad:
        return bad
    g = ModifierGroup.query.get_or_404(group_id)
    d = request.get_json()
    if "name" in d:
        nm = (d["name"] or "").strip()
        if not nm:
            return json_error("Name required", 400)
        other = ModifierGroup.query.filter(db.func.lower(ModifierGroup.name) == nm.lower(), ModifierGroup.id != g.id).first()
        if other:
            return json_error("Group name already exists", 400)
        g.name = nm
    if "min_select" in d:
        g.min_select = int(d["min_select"])
    if "max_select" in d:
        g.max_select = int(d["max_select"])
    if "is_active" in d:
        g.is_active = bool(d["is_active"])
    db.session.commit()
    audit("update", "modifier_group", g.id)
    return jsonify({"success": True})


@app.route("/api/modifier-groups/<int:group_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_modifier_groups_delete(group_id):
    g = ModifierGroup.query.get_or_404(group_id)
    ItemModifierLink.query.filter_by(group_id=g.id).delete()
    ModifierOption.query.filter_by(group_id=g.id).delete()
    db.session.commit()
    db.session.delete(g)
    db.session.commit()
    audit("delete", "modifier_group", group_id)
    return jsonify({"success": True})


@app.route("/api/modifier-groups/<int:group_id>/options", methods=["GET"])
@login_required
def api_modifier_options_list(group_id):
    opts = ModifierOption.query.filter_by(group_id=group_id).order_by(ModifierOption.id.asc()).all()
    return jsonify({"success": True, "options": [{"id": o.id, "name": o.name, "price": str(o.price), "is_active": o.is_active} for o in opts]})


@app.route("/api/modifier-groups/<int:group_id>/options", methods=["POST"])
@require_roles("Admin", "Manager")
def api_modifier_options_create(group_id):
    bad = require_json()
    if bad:
        return bad
    if not ModifierGroup.query.get(group_id):
        return json_error("Invalid group_id", 400)
    d = request.get_json()
    nm = (d.get("name") or "").strip()
    if not nm:
        return json_error("Option name required", 400)

    o = ModifierOption(
        group_id=group_id,
        name=nm,
        price=money(d.get("price", 0)),
        is_active=bool(d.get("is_active", True))
    )
    db.session.add(o)
    db.session.commit()
    audit("create", "modifier_option", o.id, {"group_id": group_id})
    return jsonify({"success": True, "id": o.id})


@app.route("/api/modifier-options/<int:option_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_modifier_option_update(option_id):
    bad = require_json()
    if bad:
        return bad
    o = ModifierOption.query.get_or_404(option_id)
    d = request.get_json()
    if "name" in d:
        nm = (d["name"] or "").strip()
        if not nm:
            return json_error("Option name required", 400)
        o.name = nm
    if "price" in d:
        o.price = money(d["price"])
    if "is_active" in d:
        o.is_active = bool(d["is_active"])
    db.session.commit()
    audit("update", "modifier_option", o.id)
    return jsonify({"success": True})


@app.route("/api/modifier-options/<int:option_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_modifier_option_delete(option_id):
    o = ModifierOption.query.get_or_404(option_id)
    OrderItemModifier.query.filter_by(option_id=o.id).delete()
    db.session.commit()
    db.session.delete(o)
    db.session.commit()
    audit("delete", "modifier_option", option_id)
    return jsonify({"success": True})


@app.route("/api/items/<int:item_id>/modifier-groups", methods=["POST"])
@require_roles("Admin", "Manager")
def api_item_link_modifier_group(item_id):
    bad = require_json()
    if bad:
        return bad
    if not MenuItem.query.filter_by(id=item_id, is_deleted=False).first():
        return json_error("Invalid item_id", 400)
    d = request.get_json()
    group_id = int(d.get("group_id") or 0)
    if not ModifierGroup.query.get(group_id):
        return json_error("Invalid group_id", 400)
    if not ItemModifierLink.query.filter_by(item_id=item_id, group_id=group_id).first():
        db.session.add(ItemModifierLink(item_id=item_id, group_id=group_id))
        db.session.commit()
    audit("link", "item_modifier_group", None, {"item_id": item_id, "group_id": group_id})
    return jsonify({"success": True})


@app.route("/api/items/<int:item_id>/modifier-groups/<int:group_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_item_unlink_modifier_group(item_id, group_id):
    ItemModifierLink.query.filter_by(item_id=item_id, group_id=group_id).delete()
    db.session.commit()
    audit("unlink", "item_modifier_group", None, {"item_id": item_id, "group_id": group_id})
    return jsonify({"success": True})


@app.route("/api/items/<int:item_id>/modifier-groups", methods=["GET"])
@login_required
def api_item_modifier_groups(item_id):
    links = ItemModifierLink.query.filter_by(item_id=item_id).all()
    group_ids = [l.group_id for l in links]
    groups = ModifierGroup.query.filter(ModifierGroup.id.in_(group_ids)).all() if group_ids else []
    return jsonify({"success": True, "groups": [{"id": g.id, "name": g.name, "min_select": g.min_select, "max_select": g.max_select, "is_active": g.is_active} for g in groups]})



# ---------------------------
# Orders
# ---------------------------

@app.route("/api/orders", methods=["GET"])
@login_required
def api_orders_list():
    q = orders_query_for_current_user(Order.query)

    status = request.args.get("status")
    if status:
        q = q.filter_by(status=status)
    otype = request.args.get("order_type")
    if otype:
        q = q.filter_by(order_type=otype)

    orders = q.order_by(Order.created_at.desc()).limit(200).all()
    out = []
    for o in orders:
        ui = order_status_ui(o.status, o.delivery_status)
        out.append({
            "id": o.id,
            "order_no": o.order_no,
            "order_type": o.order_type,
            "status": o.status,
            "status_label": ui["label"],
            "status_step": ui["step"],
            "table_id": o.table_id,
            "waiter_id": o.waiter_id,
            "customer_id": o.customer_id,
            "subtotal": str(o.subtotal),
            "tax_total": str(o.tax_total),
            "total": str(o.total),
            "created_at": o.created_at.isoformat()
        })
    return jsonify({"success": True, "orders": out})


@app.route("/api/orders", methods=["POST"])
@require_roles("Waiter", "Cashier", "Admin", "Manager", "Customer")
def api_orders_create():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json()
    otype = d.get("order_type", OrderType.DINE_IN.value)
    table_id = d.get("table_id")
    customer_id = d.get("customer_id")

    if norm_role(current_user.role) == "customer":
        if otype not in (OrderType.TAKEAWAY.value, OrderType.DELIVERY.value):
            return json_error("Customers can create takeaway or delivery orders only", 400)
        c = customer_record_for_user(create_if_missing=True)
        if not c or c.is_blocked:
            return json_error("Customer account not available", 403)
        customer_id = c.id
        table_id = None

    vat_rate = Decimal(str(money(setting_get("vat_rate", "0.20"))))

    o = Order(
        order_no=next_order_no(),
        order_type=otype,
        status=OrderStatus.DRAFT.value,
        table_id=int(table_id) if table_id else None,
        waiter_id=int(d.get("waiter_id") or current_user.id),
        customer_id=int(customer_id) if customer_id else None,
        discount_type=d.get("discount_type", "none"),
        discount_value=money(d.get("discount_value", 0)),
        service_charge=money(d.get("service_charge", 0)),
        vat_rate=vat_rate,
        delivery_address=d.get("delivery_address"),
        delivery_maps_link=d.get("delivery_maps_link"),
        delivery_fee=money(d.get("delivery_fee", 0))
    )
    db.session.add(o)
    db.session.commit()

    if o.table_id:
        t = DiningTable.query.get(o.table_id)
        if t:
            t.status = TableStatus.OCCUPIED.value
            t.updated_at = now_utc()
            db.session.commit()

    compute_order_totals(o)
    db.session.commit()
    audit("create", "order", o.id, {"order_no": o.order_no})
    return jsonify({"success": True, "id": o.id, "order_no": o.order_no})


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@login_required
def api_order_get(order_id):
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)

    compute_order_totals(o)
    db.session.commit()

    items = OrderItem.query.filter_by(order_id=o.id).order_by(OrderItem.id.asc()).all()
    out_items = []
    for it in items:
        mods = OrderItemModifier.query.filter_by(order_item_id=it.id).order_by(OrderItemModifier.id.asc()).all()
        out_items.append({
            "id": it.id,
            "item_id": it.item_id,
            "variant_id": it.variant_id,
            "combo_id": it.combo_id,
            "name_snapshot": it.name_snapshot,
            "unit_price": str(it.unit_price),
            "qty": it.qty,
            "note": it.note,
            "is_void": it.is_void,
            "void_reason": it.void_reason,
            "modifiers": [{"id": m.id, "option_id": m.option_id, "name_snapshot": m.name_snapshot, "price": str(m.price)} for m in mods]
        })

    total_paid = paid_total_for_order(o.id)
    ui = order_status_ui(o.status, o.delivery_status)
    return jsonify({
        "success": True,
        "order": {
            "id": o.id,
            "order_no": o.order_no,
            "order_type": o.order_type,
            "status": o.status,
            "status_label": ui["label"],
            "status_step": ui["step"],
            "table_id": o.table_id,
            "waiter_id": o.waiter_id,
            "customer_id": o.customer_id,
            "delivery_address": o.delivery_address,
            "delivery_fee": str(o.delivery_fee),
            "subtotal": str(o.subtotal),
            "tax_total": str(o.tax_total),
            "total": str(o.total),
            "paid_total": str(total_paid),
            "created_at": o.created_at.isoformat(),
            "items": out_items
        }
    })


@app.route("/api/orders/<int:order_id>/items", methods=["POST"])
@login_required
def api_order_add_item(order_id):
    bad = require_json()
    if bad:
        return bad

    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json()
    item_id = int(d.get("item_id") or 0)
    qty = int(d.get("qty") or 1)
    variant_id = d.get("variant_id")
    note = d.get("note")

    if qty <= 0:
        return json_error("qty must be positive", 400)

    mi = MenuItem.query.filter_by(id=item_id, is_deleted=False).first()
    if not mi or not mi.is_available:
        return json_error("Item not available", 400)

    unit_price = money(mi.base_price)

    v_id = None
    if variant_id:
        v = ItemVariant.query.filter_by(id=int(variant_id), item_id=mi.id, is_active=True).first()
        if not v:
            return json_error("Invalid variant", 400)
        unit_price = money(v.price)
        v_id = v.id

    oi = OrderItem(
        order_id=o.id,
        item_id=mi.id,
        variant_id=v_id,
        name_snapshot=mi.name,
        unit_price=unit_price,
        qty=qty,
        note=note
    )
    db.session.add(oi)
    db.session.commit()

    compute_order_totals(o)
    db.session.commit()

    audit("add_item", "order", o.id, {"order_item_id": oi.id, "item_id": mi.id, "qty": qty})
    return jsonify({"success": True, "order_item_id": oi.id})


@app.route("/api/orders/<int:order_id>/combos", methods=["POST"])
@login_required
def api_order_add_combo(order_id):
    bad = require_json()
    if bad:
        return bad

    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json()
    combo_id = int(d.get("combo_id") or 0)
    qty = int(d.get("qty") or 1)
    note = d.get("note")

    if qty <= 0:
        return json_error("qty must be positive", 400)

    c = Combo.query.get(combo_id)
    if not c or not bool(c.is_active):
        return json_error("Combo not available", 400)

    oi = OrderItem(
        order_id=o.id,
        combo_id=c.id,
        name_snapshot=c.name,
        unit_price=money(c.fixed_price),
        qty=qty,
        note=note
    )
    db.session.add(oi)
    db.session.commit()

    compute_order_totals(o)
    db.session.commit()

    audit("add_combo", "order", o.id, {"order_item_id": oi.id, "combo_id": c.id, "qty": qty})
    return jsonify({"success": True, "order_item_id": oi.id})


@app.route("/api/order-items/<int:order_item_id>", methods=["PUT"])
@login_required
def api_order_item_update(order_item_id):
    bad = require_json()
    if bad:
        return bad

    oi = OrderItem.query.get_or_404(order_item_id)
    o = Order.query.get_or_404(oi.order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json()
    if "qty" in d:
        q = int(d["qty"] or 0)
        if q <= 0:
            return json_error("qty must be positive", 400)
        oi.qty = q
    if "note" in d:
        oi.note = d["note"]

    db.session.commit()
    compute_order_totals(o)
    db.session.commit()
    audit("update_item", "order", o.id, {"order_item_id": oi.id})
    return jsonify({"success": True})


@app.route("/api/order-items/<int:order_item_id>", methods=["DELETE"])
@login_required
def api_order_item_void(order_item_id):
    bad = require_json()
    if bad:
        return bad

    oi = OrderItem.query.get_or_404(order_item_id)
    o = Order.query.get_or_404(oi.order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json()
    reason = (d.get("reason") or "void").strip()

    oi.is_void = True
    oi.void_reason = reason
    db.session.commit()

    compute_order_totals(o)
    db.session.commit()
    audit("void_item", "order", o.id, {"order_item_id": oi.id, "reason": reason})
    return jsonify({"success": True})


@app.route("/api/order-items/<int:order_item_id>/modifiers", methods=["POST"])
@login_required
def api_order_item_add_modifier(order_item_id):
    bad = require_json()
    if bad:
        return bad

    oi = OrderItem.query.get_or_404(order_item_id)
    o = Order.query.get_or_404(oi.order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)
    if oi.is_void:
        return json_error("Order item is void", 400)

    d = request.get_json()
    option_id = int(d.get("option_id") or 0)
    opt = ModifierOption.query.filter_by(id=option_id, is_active=True).first()
    if not opt:
        return json_error("Invalid option_id", 400)

    m = OrderItemModifier(
        order_item_id=oi.id,
        option_id=opt.id,
        name_snapshot=opt.name,
        price=money(opt.price)
    )
    db.session.add(m)
    db.session.commit()

    compute_order_totals(o)
    db.session.commit()
    audit("add_modifier", "order", o.id, {"order_item_id": oi.id, "option_id": opt.id})
    return jsonify({"success": True, "id": m.id})


@app.route("/api/order-item-modifiers/<int:mod_id>", methods=["DELETE"])
@login_required
def api_order_item_remove_modifier(mod_id):
    m = OrderItemModifier.query.get_or_404(mod_id)
    oi = OrderItem.query.get_or_404(m.order_item_id)
    o = Order.query.get_or_404(oi.order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    db.session.delete(m)
    db.session.commit()

    compute_order_totals(o)
    db.session.commit()
    audit("remove_modifier", "order", o.id, {"order_item_id": oi.id, "mod_id": mod_id})
    return jsonify({"success": True})


@app.route("/api/orders/<int:order_id>/submit", methods=["POST"])
@login_required
def api_order_submit(order_id):
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status != OrderStatus.DRAFT.value:
        return json_error("Only draft orders can be submitted", 400)

    has_items = OrderItem.query.filter_by(order_id=o.id).filter(OrderItem.is_void.is_(False)).count() > 0
    if not has_items:
        return json_error("Order must have at least one item", 400)

    o.status = OrderStatus.PENDING.value
    o.confirmed_at = now_utc()

    db.session.add(KitchenTicket(order_id=o.id, status=TicketStatus.RECEIVED.value))
    compute_order_totals(o)
    db.session.commit()

    audit("submit", "order", o.id)
    return jsonify({"success": True})


@app.route("/api/orders/<int:order_id>/cancel", methods=["POST"])
@login_required
def api_order_cancel(order_id):
    bad = require_json()
    if bad:
        return bad
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json()
    reason = (d.get("reason") or "cancelled").strip()

    o.status = OrderStatus.CANCELLED.value
    o.cancelled_reason = reason

    if o.table_id:
        t = DiningTable.query.get(o.table_id)
        if t and t.status == TableStatus.OCCUPIED.value:
            t.status = TableStatus.FREE.value
            t.updated_at = now_utc()

    db.session.commit()

    audit("cancel", "order", o.id, {"reason": reason})
    return jsonify({"success": True})


@app.route("/api/orders/<int:order_id>/status", methods=["POST"])
@require_roles("Admin", "Manager", "Chef/Kitchen", "Waiter", "Cashier", "Delivery Rider")
def api_order_set_status(order_id):
    bad = require_json()
    if bad:
        return bad
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)

    d = request.get_json()
    new_status = (d.get("status") or "").strip()
    if new_status not in [s.value for s in OrderStatus]:
        return json_error("Invalid status", 400)

    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    o.status = new_status

    if new_status == OrderStatus.COOKING.value:
        kt = KitchenTicket.query.filter_by(order_id=o.id).order_by(KitchenTicket.id.desc()).first()
        if kt:
            kt.status = TicketStatus.COOKING.value
            kt.updated_at = now_utc()
    if new_status == OrderStatus.READY.value:
        kt = KitchenTicket.query.filter_by(order_id=o.id).order_by(KitchenTicket.id.desc()).first()
        if kt:
            kt.status = TicketStatus.READY.value
            kt.updated_at = now_utc()
    if new_status == OrderStatus.COMPLETED.value:
        o.completed_at = now_utc()

    db.session.commit()
    audit("status", "order", o.id, {"status": new_status})
    return jsonify({"success": True})


@app.route("/api/orders/<int:order_id>/assign-rider", methods=["POST"])
@require_roles("Admin", "Manager")
def api_order_assign_rider(order_id):
    bad = require_json()
    if bad:
        return bad
    o = Order.query.get_or_404(order_id)
    d = request.get_json()
    rider_id = int(d.get("rider_id") or 0)
    rider = User.query.get(rider_id)
    if not rider or norm_role(rider.role) != "delivery rider":
        return json_error("Invalid rider_id", 400)

    o.rider_id = rider_id
    o.delivery_status = DeliveryStatus.ASSIGNED.value
    o.status = OrderStatus.DELIVERING.value
    db.session.commit()

    audit("assign_rider", "order", o.id, {"rider_id": rider_id})
    return jsonify({"success": True})


# ---------------------------
# Payments (minimal, used by voucher and completion)
# ---------------------------

@app.route("/api/orders/<int:order_id>/payments", methods=["GET"])
@login_required
def api_payments_list(order_id):
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    rows = Payment.query.filter_by(order_id=o.id).order_by(Payment.id.asc()).all()
    return jsonify({"success": True, "payments": [{
        "id": p.id,
        "method": p.method,
        "amount": str(p.amount),
        "reference": p.reference,
        "created_at": p.created_at.isoformat() if p.created_at else None
    } for p in rows]})


@app.route("/api/orders/<int:order_id>/payments", methods=["POST"])
@login_required
def api_payments_add(order_id):
    bad = require_json()
    if bad:
        return bad

    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)
    if o.status == OrderStatus.CANCELLED.value:
        return json_error("Order is cancelled", 400)

    d = request.get_json()
    method = (d.get("method") or "cash").strip().lower()
    amount = money(d.get("amount"))
    reference = d.get("reference")

    if amount <= Decimal("0.00"):
        return json_error("amount must be positive", 400)

    p = Payment(order_id=o.id, method=method, amount=amount, reference=reference)
    db.session.add(p)
    db.session.commit()

    audit("payment", "order", o.id, {"payment_id": p.id, "method": method, "amount": str(amount)})
    maybe_complete_order(o)

    return jsonify({"success": True, "id": p.id})


@app.route("/api/orders/<int:order_id>/voucher.pdf", methods=["GET"])
@login_required
def api_voucher_pdf(order_id):
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)

    pdf_bytes = build_voucher_pdf_bytes(o)
    if not pdf_bytes:
        return json_error("PDF generation not available", 400)

    audit("voucher_pdf", "order", o.id)
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"voucher_{o.order_no}.pdf"
    )


# ---------------------------
# Reports and audit
# ---------------------------

@app.route("/api/audit-logs", methods=["GET"])
@require_roles("Admin", "Manager")
def api_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    out = []
    for l in logs:
        out.append({
            "id": l.id, "user_id": l.user_id, "action": l.action, "entity": l.entity,
            "entity_id": l.entity_id, "ip": l.ip, "details": l.details_json,
            "created_at": l.created_at.isoformat()
        })
    return jsonify({"success": True, "logs": out})


@app.route("/api/system/backup-db", methods=["GET"])
@require_roles("Admin", "Manager")
def api_backup_db():
    if not os.path.exists(DB_PATH):
        return json_error("Database not found", 404)
    audit("backup_db", "system", None, {"path": DB_PATH})
    return send_file(DB_PATH, mimetype="application/octet-stream", as_attachment=True, download_name="restaurant_backup.db")


# ---------------------------
# Combos CRUD
# ---------------------------

@app.route("/api/combos", methods=["GET"])
@login_required
def api_combos_list():
    rows = Combo.query.order_by(Combo.id.desc()).all()
    return jsonify({
        "success": True,
        "combos": [{
            "id": c.id,
            "name": c.name,
            "fixed_price": str(c.fixed_price),
            "is_active": bool(c.is_active),
        } for c in rows]
    })


@app.route("/api/combos", methods=["POST"])
@require_roles("Admin", "Manager")
def api_combos_create():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json()
    name = (d.get("name") or "").strip()
    if not name:
        return json_error("Name required", 400)

    fixed_price = d.get("fixed_price")
    if fixed_price is None:
        return json_error("fixed_price is required", 400)

    c = Combo(
        name=name,
        fixed_price=money(fixed_price),
        is_active=bool(d.get("is_active", True))
    )
    db.session.add(c)
    db.session.commit()
    audit("create", "combo", c.id)

    return jsonify({"success": True, "id": c.id})


@app.route("/api/combos/<int:combo_id>", methods=["GET"])
@login_required
def api_combo_get(combo_id):
    c = Combo.query.get_or_404(combo_id)

    lines = (
        ComboItem.query
        .filter_by(combo_id=c.id)
        .order_by(ComboItem.id.asc())
        .all()
    )

    item_ids = [li.item_id for li in lines]
    items_map = {}
    if item_ids:
        items = MenuItem.query.filter(MenuItem.id.in_(item_ids)).all()
        items_map = {it.id: it for it in items}

    return jsonify({
        "success": True,
        "combo": {
            "id": c.id,
            "name": c.name,
            "fixed_price": str(c.fixed_price),
            "is_active": bool(c.is_active),
            "items": [{
                "id": li.id,
                "item_id": li.item_id,
                "qty": int(li.qty or 1),
                "item_name": (items_map.get(li.item_id).name if items_map.get(li.item_id) else f"Item #{li.item_id}")
            } for li in lines]
        }
    })


@app.route("/api/combos/<int:combo_id>", methods=["PUT"])
@require_roles("Admin", "Manager")
def api_combo_update(combo_id):
    bad = require_json()
    if bad:
        return bad

    c = Combo.query.get_or_404(combo_id)
    d = request.get_json()

    if "name" in d:
        nm = (d.get("name") or "").strip()
        if not nm:
            return json_error("Name required", 400)
        c.name = nm

    if "fixed_price" in d:
        c.fixed_price = money(d.get("fixed_price"))

    if "is_active" in d:
        c.is_active = bool(d.get("is_active"))

    db.session.commit()
    audit("update", "combo", c.id)
    return jsonify({"success": True})


@app.route("/api/combos/<int:combo_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_combo_delete(combo_id):
    c = Combo.query.get_or_404(combo_id)
    ComboItem.query.filter_by(combo_id=c.id).delete()
    db.session.commit()
    db.session.delete(c)
    db.session.commit()
    audit("delete", "combo", combo_id)
    return jsonify({"success": True})


# ---------------------------
# Combo items
# ---------------------------

@app.route("/api/combos/<int:combo_id>/items", methods=["POST"])
@require_roles("Admin", "Manager")
def api_combo_add_item(combo_id):
    bad = require_json()
    if bad:
        return bad

    c = Combo.query.get_or_404(combo_id)
    d = request.get_json()

    item_id = int(d.get("item_id") or 0)
    qty = int(d.get("qty") or 1)
    if item_id <= 0:
        return json_error("item_id is required", 400)
    if qty <= 0:
        return json_error("qty must be positive", 400)

    it = MenuItem.query.filter_by(id=item_id).first()
    if not it or bool(getattr(it, "is_deleted", False)):
        return json_error("Invalid item_id", 400)

    existing = ComboItem.query.filter_by(combo_id=c.id, item_id=item_id).first()
    if existing:
        existing.qty = int(existing.qty or 1) + qty
        db.session.commit()
        audit("update", "combo_item", existing.id, {"combo_id": c.id, "item_id": item_id, "qty": existing.qty})
        return jsonify({"success": True, "id": existing.id, "qty": int(existing.qty)})

    ci = ComboItem(combo_id=c.id, item_id=item_id, qty=qty)
    db.session.add(ci)
    db.session.commit()
    audit("create", "combo_item", ci.id, {"combo_id": c.id, "item_id": item_id, "qty": qty})
    return jsonify({"success": True, "id": ci.id})


@app.route("/api/combos/<int:combo_id>/items/<int:combo_item_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_combo_remove_item(combo_id, combo_item_id):
    c = Combo.query.get_or_404(combo_id)
    ci = ComboItem.query.get_or_404(combo_item_id)
    if ci.combo_id != c.id:
        return json_error("Combo item does not belong to this combo", 400)

    db.session.delete(ci)
    db.session.commit()
    audit("delete", "combo_item", combo_item_id, {"combo_id": c.id})
    return jsonify({"success": True})

@app.route("/api/uploads/image", methods=["POST"])
@require_roles("Admin", "Manager")
def api_upload_image():
    if "file" not in request.files:
        return json_error("file is required (multipart/form-data)", 400)

    f = request.files["file"]
    if not f or not f.filename:
        return json_error("No file selected", 400)

    original = secure_filename(f.filename)
    ext = Path(original).suffix.lower()

    if ext not in ALLOWED_IMAGE_EXTS:
        return json_error("Only jpg, jpeg, png, webp are allowed", 400)

    # Unique filename
    fname = f"{secrets.token_hex(12)}{ext}"
    abs_path = os.path.join(UPLOAD_DIR, fname)
    f.save(abs_path)

    rel_path = f"/static/uploads/{fname}"

    audit("upload", "image", None, {"path": rel_path, "original": original})
    return jsonify({"success": True, "path": rel_path})


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"success": True, "time": now_utc().isoformat()})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
