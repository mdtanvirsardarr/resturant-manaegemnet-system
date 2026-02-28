# app.py
import os
import io
import csv
import secrets
from datetime import datetime, timedelta, date
from functools import wraps
from decimal import Decimal
from pathlib import Path

from werkzeug.utils import secure_filename

from flask import (
    Flask, request, jsonify, send_file, abort,
    render_template, redirect
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy import or_ as sa_or, and_ as sa_and, text

from database import (
    db,
    now_utc, money, dec3,
    setting_get, setting_set,
    TableStatus, OrderType, OrderStatus, TicketStatus, ReservationStatus, DeliveryStatus,
    User, AuditLog, Settings,
    ImageAsset,
    Category, MenuItem, ItemVariant,
    ModifierGroup, ModifierOption, ItemModifierLink,
    Combo, ComboItem,
    Customer, DiningTable, Reservation,
    Order, OrderItem, OrderItemModifier,
    KitchenTicket,
    Shift,
    ShiftAssignment,
    Supplier, Ingredient, StockLedger, Recipe, RecipeLine,
    PurchaseOrder, PurchaseOrderItem,
    Payment
)

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
    template_folder=BASE_DIR,
    static_folder=os.path.join(BASE_DIR, "static") if os.path.isdir(os.path.join(BASE_DIR, "static")) else BASE_DIR,
    static_url_path="/static"
)

UPLOAD_DIR = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "api_login"

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def json_error(message, code=400):
    return jsonify({"success": False, "error": message}), code


def require_json():
    if not request.is_json:
        return json_error("Expected JSON body", 400)
    return None


def norm_role(role) -> str:
    r = (role or "").strip().lower()
    if not r:
        return ""

    r = r.replace("_", " ").replace("-", " ")
    r = " ".join(r.split())

    r = r.replace(" / ", "/").replace(" /", "/").replace("/ ", "/")
    r = " ".join(r.split())

    aliases = {
        "administrator": "admin",
        "system admin": "admin",
        "system administrator": "admin",
        "mgr": "manager",
        "cashier staff": "cashier",
        "chef": "chef/kitchen",
        "kitchen": "chef/kitchen",
        "cook": "chef/kitchen",
        "chef kitchen": "chef/kitchen",
        "chef / kitchen": "chef/kitchen",
        "delivery": "delivery rider",
        "rider": "delivery rider",
        "driver": "delivery rider",
        "deliveryrider": "delivery rider",
        "delivery-rider": "delivery rider",
        "delivery_rider": "delivery rider",
        "server": "waiter",
    }
    if r in aliases:
        r = aliases[r]

    if r in {"chef kitchen"}:
        r = "chef/kitchen"
    if r in {"deliveryrider"}:
        r = "delivery rider"

    return r


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
    if r == "chef/kitchen":
        return "/chefprofile.html"
    if r == "delivery rider":
        return "/driverprofile.html"
    if r in {"waiter", "staff"}:
        return "/staffprofile.html"
    return "/userprofile.html"


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


def _sqlite_table_cols(table_name: str):
    rows = db.session.execute(text(f"PRAGMA table_info('{table_name}')")).fetchall()
    cols = [r[1] for r in rows] if rows else []
    return set(cols)


def _sqlite_add_col(table: str, col: str, ddl: str):
    cols = _sqlite_table_cols(table)
    if col in cols:
        return
    db.session.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {ddl}'))
    db.session.commit()


def ensure_order_assignment_schema():
    cols_order = _sqlite_table_cols("order")
    if "chef_id" not in cols_order:
        _sqlite_add_col("order", "chef_id", "chef_id INTEGER")


def upsert_image_asset_by_path(path: str, original_name: str = None, content_type: str = None, size_bytes: int = None, uploaded_by_user_id=None):
    p = (path or "").strip()
    if not p:
        return None

    row = ImageAsset.query.filter_by(file_path=p).first()
    if row:
        if not row.original_name and original_name:
            row.original_name = original_name
        if not row.content_type and content_type:
            row.content_type = content_type
        if (row.size_bytes is None or row.size_bytes == 0) and size_bytes:
            row.size_bytes = int(size_bytes)
        if row.uploaded_by_user_id is None and uploaded_by_user_id:
            row.uploaded_by_user_id = int(uploaded_by_user_id)
        db.session.commit()
        return row

    row = ImageAsset(
        file_path=p,
        original_name=original_name,
        content_type=content_type,
        size_bytes=int(size_bytes) if size_bytes is not None else None,
        uploaded_by_user_id=int(uploaded_by_user_id) if uploaded_by_user_id else None,
        created_at=now_utc(),
        is_active=True
    )
    db.session.add(row)
    db.session.commit()
    return row


def backfill_image_assets_from_paths():
    items = MenuItem.query.filter(MenuItem.image_path.isnot(None)).all()
    for it in items:
        if getattr(it, "image_id", None):
            continue
        p = (it.image_path or "").strip()
        if not p:
            continue
        asset = upsert_image_asset_by_path(p)
        if asset:
            it.image_id = asset.id
    db.session.commit()

    combos = Combo.query.filter(Combo.image_path.isnot(None)).all()
    for c in combos:
        if getattr(c, "image_id", None):
            continue
        p = (c.image_path or "").strip()
        if not p:
            continue
        asset = upsert_image_asset_by_path(p)
        if asset:
            c.image_id = asset.id
    db.session.commit()

    users = User.query.filter(User.profile_image_path.isnot(None)).all()
    for u in users:
        if getattr(u, "profile_image_id", None):
            continue
        p = (u.profile_image_path or "").strip()
        if not p:
            continue
        asset = upsert_image_asset_by_path(p, uploaded_by_user_id=u.id)
        if asset:
            u.profile_image_id = asset.id
    db.session.commit()


def ensure_image_schema():
    db.create_all()

    cols_user = _sqlite_table_cols("user")
    if "profile_image_id" not in cols_user:
        _sqlite_add_col("user", "profile_image_id", "profile_image_id INTEGER")
    if "profile_image_path" not in cols_user:
        _sqlite_add_col("user", "profile_image_path", "profile_image_path TEXT")

    cols_item = _sqlite_table_cols("menu_item")
    if "image_id" not in cols_item:
        _sqlite_add_col("menu_item", "image_id", "image_id INTEGER")
    if "image_path" not in cols_item:
        _sqlite_add_col("menu_item", "image_path", "image_path TEXT")

    cols_combo = _sqlite_table_cols("combo")
    if "image_id" not in cols_combo:
        _sqlite_add_col("combo", "image_id", "image_id INTEGER")
    if "image_path" not in cols_combo:
        _sqlite_add_col("combo", "image_path", "image_path TEXT")

    cols_cat = _sqlite_table_cols("category")
    if "image_id" not in cols_cat:
        _sqlite_add_col("category", "image_id", "image_id INTEGER")
    if "image_path" not in cols_cat:
        _sqlite_add_col("category", "image_path", "image_path TEXT")

    ensure_order_assignment_schema()
    backfill_image_assets_from_paths()


def _order_extra_cols_map(order_ids, cols):
    if not order_ids:
        return {}
    table_cols = _sqlite_table_cols("order")
    wanted = [c for c in cols if c in table_cols]
    if not wanted:
        return {}

    params = {}
    ph = []
    for i, oid in enumerate(order_ids):
        k = f"id{i}"
        params[k] = int(oid)
        ph.append(f":{k}")

    select_cols = ", ".join([f'"{c}"' for c in wanted])
    sql = f'SELECT id, {select_cols} FROM "order" WHERE id IN ({",".join(ph)})'
    rows = db.session.execute(text(sql), params).fetchall()

    out = {}
    for r in rows:
        rid = int(r[0])
        out[rid] = {}
        for idx, c in enumerate(wanted, start=1):
            out[rid][c] = r[idx]
    return out


def _order_set_extra_col(order_id: int, col: str, value):
    ensure_order_assignment_schema()
    table_cols = _sqlite_table_cols("order")
    if col not in table_cols:
        return
    db.session.execute(
        text(f'UPDATE "order" SET "{col}" = :v WHERE id = :id'),
        {"v": value, "id": int(order_id)}
    )
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


@app.route("/chefprofile.html", methods=["GET"])
@login_required
def page_chef_profile():
    if not role_is("Chef/Kitchen", "Manager", "Admin"):
        abort(403)
    return render_template("chefprofile.html")


@app.route("/driverprofile.html", methods=["GET"])
@login_required
def page_driver_profile():
    if not role_is("Delivery Rider", "Manager", "Admin"):
        abort(403)
    return render_template("driverprofile.html")


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
        if order.status not in (OrderStatus.PENDING.value, OrderStatus.COOKING.value, OrderStatus.READY.value):
            return False
        extra = _order_extra_cols_map([order.id], ["chef_id"]).get(order.id, {})
        chef_id = extra.get("chef_id")
        return (chef_id is None) or (int(chef_id) == int(current_user.id))
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
        q = q.filter(Order.status.in_([OrderStatus.PENDING.value, OrderStatus.COOKING.value, OrderStatus.READY.value]))
        return q
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


@app.get("/manage-orders.html")
@login_required
@require_roles("Admin", "Manager", "Cashier")
def manage_orders_page():
    return render_template("manage-orders.html")


@app.route("/api/system/init", methods=["POST"])
def api_system_init():
    db.create_all()
    ensure_image_schema()

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
    ensure_image_schema()

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
            "role": current_user.role,
            "profile_image_path": current_user.effective_profile_image_path
        }
    })


@app.route("/api/uploads/profile-image", methods=["POST"])
@login_required
def api_upload_profile_image():
    if "file" not in request.files:
        return json_error("file is required (multipart/form-data)", 400)

    f = request.files["file"]
    if not f or not f.filename:
        return json_error("No file selected", 400)

    original = secure_filename(f.filename)
    ext = Path(original).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTS:
        return json_error("Only jpg, jpeg, png, webp are allowed", 400)

    profiles_dir = os.path.join(UPLOAD_DIR, "profiles")
    os.makedirs(profiles_dir, exist_ok=True)

    fname = f"{secrets.token_hex(12)}{ext}"
    abs_path = os.path.join(profiles_dir, fname)
    f.save(abs_path)

    rel_path = f"/static/uploads/profiles/{fname}"
    size_bytes = os.path.getsize(abs_path) if os.path.exists(abs_path) else None
    content_type = getattr(f, "mimetype", None)

    asset = upsert_image_asset_by_path(
        rel_path,
        original_name=original,
        content_type=content_type,
        size_bytes=size_bytes,
        uploaded_by_user_id=current_user.id
    )

    audit("upload", "profile_image", asset.id if asset else None, {"path": rel_path, "original": original})
    return jsonify({"success": True, "path": rel_path, "image_id": asset.id if asset else None})


@app.route("/api/profile", methods=["PUT"])
@login_required
def api_update_profile():
    bad = require_json()
    if bad:
        return bad
    data = request.get_json()

    current_user.name = data.get("name", current_user.name)
    current_user.phone = data.get("phone", current_user.phone)

    if "profile_image_id" in data:
        try:
            pid = int(data.get("profile_image_id") or 0)
        except Exception:
            pid = 0
        current_user.profile_image_id = pid if pid > 0 else None
        if current_user.profile_image_id:
            asset = ImageAsset.query.get(current_user.profile_image_id)
            current_user.profile_image_path = asset.file_path if asset else current_user.profile_image_path
        else:
            current_user.profile_image_path = None

    if "profile_image_path" in data:
        p = (data.get("profile_image_path") or "").strip() or None
        current_user.profile_image_path = p
        if p:
            asset = upsert_image_asset_by_path(p, uploaded_by_user_id=current_user.id)
            current_user.profile_image_id = asset.id if asset else current_user.profile_image_id

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
            "profile_image_path": u.effective_profile_image_path,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })
    return jsonify({"success": True, "users": out})


@app.route("/api/staff", methods=["GET"])
@require_roles("Admin", "Manager")
def api_staff_list():
    users = User.query.order_by(User.created_at.desc()).all()
    out = [{
        "id": u.id,
        "name": u.name,
        "email": u.email,
        "phone": u.phone,
        "role": u.role,
        "is_active": u.is_active,
        "profile_image_path": u.effective_profile_image_path
    } for u in users]
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

    if "profile_image_id" in data:
        try:
            pid = int(data.get("profile_image_id") or 0)
        except Exception:
            pid = 0
        u.profile_image_id = pid if pid > 0 else None
        if u.profile_image_id:
            asset = ImageAsset.query.get(u.profile_image_id)
            u.profile_image_path = asset.file_path if asset else u.profile_image_path
        else:
            u.profile_image_path = None

    if "profile_image_path" in data:
        p = (data.get("profile_image_path") or "").strip() or None
        u.profile_image_path = p
        if p:
            asset = upsert_image_asset_by_path(p, uploaded_by_user_id=u.id)
            u.profile_image_id = asset.id if asset else u.profile_image_id

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
            "profile_image_path": u.effective_profile_image_path,
            "created_at": u.created_at.isoformat() if u.created_at else None
        }
    })


@app.get("/manage-shift.html")
@login_required
@require_roles("Admin", "Manager")
def manage_shift_page():
    return render_template("manage-shift.html")


@app.route("/api/shift-assignments", methods=["GET"])
@require_roles("Admin", "Manager")
def api_shift_assignments_list():
    date_s = (request.args.get("date") or "").strip()
    if not date_s:
        return json_error("date is required", 400)

    try:
        d = datetime.strptime(date_s, "%Y-%m-%d").date()
    except Exception:
        return json_error("date must be YYYY-MM-DD", 400)

    rows = (
        ShiftAssignment.query
        .filter(ShiftAssignment.shift_date == d)
        .order_by(ShiftAssignment.id.desc())
        .all()
    )

    shift_ids = [r.shift_id for r in rows]
    user_ids = [r.user_id for r in rows]

    shifts = Shift.query.filter(Shift.id.in_(shift_ids)).all() if shift_ids else []
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []

    shift_map = {s.id: s for s in shifts}
    user_map = {u.id: u for u in users}

    out = []
    for r in rows:
        s = shift_map.get(r.shift_id)
        u = user_map.get(r.user_id)
        out.append({
            "id": r.id,
            "shift_date": r.shift_date.isoformat(),
            "start_time": r.start_time,
            "end_time": r.end_time,
            "notes": r.notes,
            "shift": {
                "id": s.id,
                "name": s.name,
                "start_time": s.start_time,
                "end_time": s.end_time,
                "is_active": s.is_active
            } if s else None,
            "user": u.to_dict() if u else None
        })

    return jsonify({"success": True, "assignments": out})


@app.route("/api/shift-assignments", methods=["POST"])
@require_roles("Admin", "Manager")
def api_shift_assignments_create():
    bad = require_json()
    if bad:
        return bad

    payload = request.get_json() or {}
    date_s = (payload.get("date") or "").strip()
    shift_id = int(payload.get("shift_id") or 0)
    user_ids = payload.get("user_ids") or []
    notes = (payload.get("notes") or "").strip() or None

    if not date_s:
        return json_error("date is required", 400)

    try:
        d = datetime.strptime(date_s, "%Y-%m-%d").date()
    except Exception:
        return json_error("date must be YYYY-MM-DD", 400)

    if shift_id <= 0:
        return json_error("shift_id is required", 400)

    if not isinstance(user_ids, list) or not user_ids:
        return json_error("user_ids must be a non-empty list", 400)

    shift = Shift.query.get(shift_id)
    if not shift:
        return json_error("Invalid shift_id", 400)

    created = 0
    for uid in user_ids:
        try:
            u_id = int(uid)
        except Exception:
            continue

        u = User.query.get(u_id)
        if not u or not bool(u.is_active):
            continue

        exists = ShiftAssignment.query.filter_by(shift_id=shift_id, user_id=u_id, shift_date=d).first()
        if exists:
            continue

        row = ShiftAssignment(
            shift_id=shift_id,
            user_id=u_id,
            shift_date=d,
            start_time=shift.start_time,
            end_time=shift.end_time,
            role_snapshot=u.role,
            notes=notes
        )
        db.session.add(row)
        created += 1

    db.session.commit()
    audit("assign_shift", "shift_assignment", None, {"date": date_s, "shift_id": shift_id, "count": created})
    return jsonify({"success": True, "message": f"Assigned {created} staff member(s)."})


@app.route("/api/shift-assignments/<int:assignment_id>", methods=["DELETE"])
@require_roles("Admin", "Manager")
def api_shift_assignments_delete(assignment_id):
    row = ShiftAssignment.query.get_or_404(assignment_id)
    db.session.delete(row)
    db.session.commit()
    audit("delete", "shift_assignment", assignment_id)
    return jsonify({"success": True})


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
            {"id": c.id, "name": c.name, "is_active": c.is_active, "image_path": c.effective_image_path}
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

    if d.get("image_id"):
        try:
            c.image_id = int(d.get("image_id") or 0) or None
        except Exception:
            c.image_id = None
        if c.image_id:
            asset = ImageAsset.query.get(c.image_id)
            c.image_path = asset.file_path if asset else c.image_path

    if d.get("image_path"):
        p = (d.get("image_path") or "").strip() or None
        c.image_path = p
        if p:
            asset = upsert_image_asset_by_path(p)
            c.image_id = asset.id if asset else c.image_id

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

    if "image_id" in d:
        try:
            c.image_id = int(d.get("image_id") or 0) or None
        except Exception:
            c.image_id = None
        if c.image_id:
            asset = ImageAsset.query.get(c.image_id)
            c.image_path = asset.file_path if asset else c.image_path
        else:
            c.image_path = None

    if "image_path" in d:
        p = (d.get("image_path") or "").strip() or None
        c.image_path = p
        if p:
            asset = upsert_image_asset_by_path(p)
            c.image_id = asset.id if asset else c.image_id
        else:
            c.image_id = None

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
                "image_path": it.effective_image_path,
                "prep_minutes": it.prep_minutes,
                "tags": it.tags
            } for it in items]
        })

    return jsonify({"success": True, "categories": out})


@app.route("/api/public/menu", methods=["GET"])
def api_public_menu_grouped():
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
                "image_path": it.effective_image_path,
                "prep_minutes": it.prep_minutes,
                "tags": it.tags
            } for it in items]
        })

    return jsonify({"success": True, "categories": out})


@app.route("/api/public/combos", methods=["GET"])
def api_public_combos_list():
    rows = Combo.query.order_by(Combo.id.desc()).all()
    out = []

    for c in rows:
        preview_path = c.effective_image_path

        if not preview_path:
            lines = (
                ComboItem.query
                .filter_by(combo_id=c.id)
                .order_by(ComboItem.id.asc())
                .all()
            )
            for li in lines:
                if not li.item_id:
                    continue
                it = MenuItem.query.get(li.item_id)
                if it and it.effective_image_path:
                    preview_path = it.effective_image_path
                    break

        out.append({
            "id": c.id,
            "name": c.name,
            "fixed_price": str(c.fixed_price),
            "is_active": bool(c.is_active),
            "preview_image_path": preview_path
        })

    return jsonify({"success": True, "combos": out})


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
        "image_path": it.effective_image_path,
        "image_id": it.image_id,
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

    image_path = (d.get("image_path") or "").strip() or None
    image_id = d.get("image_id")

    it = MenuItem(
        category_id=cat_id,
        name=nm,
        description=d.get("description"),
        base_price=money(d.get("base_price")),
        tax_class=d.get("tax_class", "standard"),
        cost_price=money(d.get("cost_price")),
        image_path=image_path,
        is_available=bool(d.get("is_available", True)),
        prep_minutes=int(d.get("prep_minutes") or 0),
        tags=d.get("tags", "")
    )

    if image_id:
        try:
            it.image_id = int(image_id) or None
        except Exception:
            it.image_id = None
        if it.image_id:
            asset = ImageAsset.query.get(it.image_id)
            if asset:
                it.image_path = asset.file_path

    if image_path:
        asset = upsert_image_asset_by_path(image_path, uploaded_by_user_id=current_user.id if current_user.is_authenticated else None)
        if asset:
            it.image_id = asset.id

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

    for field in ["name", "description", "tax_class", "tags"]:
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

    if "image_id" in d:
        try:
            it.image_id = int(d.get("image_id") or 0) or None
        except Exception:
            it.image_id = None
        if it.image_id:
            asset = ImageAsset.query.get(it.image_id)
            it.image_path = asset.file_path if asset else it.image_path
        else:
            it.image_path = None

    if "image_path" in d:
        p = (d.get("image_path") or "").strip() or None
        it.image_path = p
        if p:
            asset = upsert_image_asset_by_path(p, uploaded_by_user_id=current_user.id if current_user.is_authenticated else None)
            it.image_id = asset.id if asset else it.image_id
        else:
            it.image_id = None

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
    extra_map = _order_extra_cols_map([o.id for o in orders], ["chef_id"])

    out = []
    for o in orders:
        ui = order_status_ui(o.status, o.delivery_status)
        extra = extra_map.get(o.id, {})
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
            "chef_id": extra.get("chef_id"),
            "rider_id": o.rider_id,
            "subtotal": str(o.subtotal),
            "tax_total": str(o.tax_total),
            "total": str(o.total),
            "created_at": o.created_at.isoformat()
        })
    return jsonify({"success": True, "orders": out})


@app.route("/api/orders", methods=["POST"])
@login_required
@require_roles("Customer", "Waiter", "Manager", "Admin")
def api_orders_create():
    payload = request.get_json(silent=True) or {}

    order_type = (payload.get("order_type") or OrderType.TAKEAWAY.value).strip().lower()
    delivery_address = (payload.get("delivery_address") or "").strip() or None

    if order_type == OrderType.DELIVERY.value and not delivery_address:
        return jsonify({"success": False, "message": "Delivery address required"}), 400

    role = norm_role(getattr(current_user, "role", ""))

    waiter_id = None
    customer_id = None

    if role == "customer":
        c = customer_record_for_user(create_if_missing=True)
        if not c:
            return json_error("Customer profile not found", 400)
        customer_id = c.id
    else:
        waiter_id = current_user.id

    o = Order(
        order_no=None,
        order_type=order_type,
        status=OrderStatus.DRAFT.value,
        table_id=None,
        waiter_id=waiter_id,
        customer_id=customer_id,
        discount_type="none",
        discount_value=0,
        service_charge=0,
        vat_rate=Decimal("0.2"),
        delivery_address=delivery_address,
        delivery_fee=0,
        subtotal=0,
        tax_total=0,
        total=0,
        created_at=now_utc(),
    )

    db.session.add(o)
    db.session.flush()

    year = datetime.utcnow().year
    o.order_no = f"INV-{year}-{o.id:06d}"

    db.session.commit()

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
    extra = _order_extra_cols_map([o.id], ["chef_id"]).get(o.id, {})

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
            "chef_id": extra.get("chef_id"),
            "rider_id": o.rider_id,
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


@app.route("/api/orders/<int:order_id>/assign-chef", methods=["POST"])
@require_roles("Admin", "Manager")
def api_order_assign_chef(order_id):
    bad = require_json()
    if bad:
        return bad

    o = Order.query.get_or_404(order_id)
    if o.status in (OrderStatus.CANCELLED.value, OrderStatus.COMPLETED.value):
        return json_error("Order is closed", 400)

    d = request.get_json() or {}
    chef_id = int(d.get("chef_id") or 0)
    chef = User.query.get(chef_id)
    if not chef or not bool(chef.is_active) or norm_role(getattr(chef, "role", "")) != "chef/kitchen":
        return json_error("Invalid chef_id", 400)

    _order_set_extra_col(o.id, "chef_id", chef_id)

    if o.status == OrderStatus.PENDING.value:
        o.status = OrderStatus.COOKING.value

    kt = KitchenTicket.query.filter_by(order_id=o.id).order_by(KitchenTicket.id.desc()).first()
    if kt:
        kt.status = TicketStatus.COOKING.value
        kt.updated_at = now_utc()

    db.session.commit()
    audit("assign_chef", "order", o.id, {"chef_id": chef_id})
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


@app.route("/api/orders/<int:order_id>", methods=["DELETE"])
@login_required
@require_roles("Admin", "Manager", "Cashier")
def api_order_delete(order_id):
    o = Order.query.get_or_404(order_id)

    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)

    payload = request.get_json(silent=True) or {}
    reason = (payload.get("reason") or "removed").strip()

    total_paid = paid_total_for_order(o.id)
    if o.status == OrderStatus.COMPLETED.value or total_paid > Decimal("0.00"):
        return json_error("Cannot delete a completed or paid order.", 400)

    if o.table_id:
        t = DiningTable.query.get(o.table_id)
        if t and t.status == TableStatus.OCCUPIED.value:
            t.status = TableStatus.FREE.value
            t.updated_at = now_utc()

    order_items = OrderItem.query.filter_by(order_id=o.id).all()
    order_item_ids = [x.id for x in order_items]

    if order_item_ids:
        OrderItemModifier.query.filter(
            OrderItemModifier.order_item_id.in_(order_item_ids)
        ).delete(synchronize_session=False)

        OrderItem.query.filter(
            OrderItem.id.in_(order_item_ids)
        ).delete(synchronize_session=False)

    KitchenTicket.query.filter_by(order_id=o.id).delete(synchronize_session=False)
    Payment.query.filter_by(order_id=o.id).delete(synchronize_session=False)

    db.session.delete(o)
    db.session.commit()

    audit("delete", "order", order_id, {"reason": reason})
    return jsonify({"success": True})


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


def build_voucher_pdf_bytes(order: Order):
    if not REPORTLAB_OK:
        return None

    try:
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, height - 50, setting_get("restaurant_name", "My Restaurant"))

        c.setFont("Helvetica", 10)
        c.drawString(40, height - 70, f"Order: {order.order_no}")
        c.drawString(40, height - 85, f"Type: {order.order_type}")
        c.drawString(40, height - 100, f"Status: {order.status}")

        y = height - 130
        c.setFont("Helvetica-Bold", 10)
        c.drawString(40, y, "Item")
        c.drawString(330, y, "Qty")
        c.drawString(380, y, "Unit")
        c.drawString(450, y, "Line")
        y -= 12
        c.line(40, y, 560, y)
        y -= 14

        items = OrderItem.query.filter_by(order_id=order.id).order_by(OrderItem.id.asc()).all()
        c.setFont("Helvetica", 10)
        for oi in items:
            if oi.is_void:
                continue
            line_total = (money(oi.unit_price) * Decimal(int(oi.qty))).quantize(Decimal("0.01"))
            c.drawString(40, y, (oi.name_snapshot or "")[:45])
            c.drawRightString(360, y, str(int(oi.qty)))
            c.drawRightString(430, y, f"{money(oi.unit_price):.2f}")
            c.drawRightString(560, y, f"{line_total:.2f}")
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)

        compute_order_totals(order)
        db.session.commit()

        y -= 6
        c.line(40, y, 560, y)
        y -= 16
        c.setFont("Helvetica-Bold", 10)
        c.drawRightString(560, y, f"Total: {money(order.total):.2f}")

        c.showPage()
        c.save()
        buffer.seek(0)
        return buffer.read()
    except Exception:
        return None


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


@app.route("/api/combos", methods=["GET"])
@login_required
def api_combos_list():
    rows = Combo.query.order_by(Combo.id.desc()).all()
    out = []

    for c in rows:
        preview_path = c.effective_image_path

        if not preview_path:
            lines = (
                ComboItem.query
                .filter_by(combo_id=c.id)
                .order_by(ComboItem.id.asc())
                .all()
            )
            for li in lines:
                if not li.item_id:
                    continue
                it = MenuItem.query.get(li.item_id)
                if it and it.effective_image_path:
                    preview_path = it.effective_image_path
                    break

        out.append({
            "id": c.id,
            "name": c.name,
            "fixed_price": str(c.fixed_price),
            "is_active": bool(c.is_active),
            "image_path": c.effective_image_path,
            "preview_image_path": preview_path
        })

    return jsonify({"success": True, "combos": out})


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

    if d.get("image_id"):
        try:
            c.image_id = int(d.get("image_id") or 0) or None
        except Exception:
            c.image_id = None
        if c.image_id:
            asset = ImageAsset.query.get(c.image_id)
            c.image_path = asset.file_path if asset else c.image_path

    if d.get("image_path"):
        p = (d.get("image_path") or "").strip() or None
        c.image_path = p
        if p:
            asset = upsert_image_asset_by_path(p, uploaded_by_user_id=current_user.id if current_user.is_authenticated else None)
            c.image_id = asset.id if asset else c.image_id

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

    item_ids = [li.item_id for li in lines if li.item_id]
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
            "image_path": c.effective_image_path,
            "items": [{
                "id": li.id,
                "item_id": li.item_id,
                "qty": int(li.qty or 1),
                "item_name": (items_map.get(li.item_id).name if items_map.get(li.item_id) else f"Item #{li.item_id}"),
                "item_image_path": (items_map.get(li.item_id).effective_image_path if items_map.get(li.item_id) else None),
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

    if "image_id" in d:
        try:
            c.image_id = int(d.get("image_id") or 0) or None
        except Exception:
            c.image_id = None
        if c.image_id:
            asset = ImageAsset.query.get(c.image_id)
            c.image_path = asset.file_path if asset else c.image_path
        else:
            c.image_path = None

    if "image_path" in d:
        p = (d.get("image_path") or "").strip() or None
        c.image_path = p
        if p:
            asset = upsert_image_asset_by_path(p, uploaded_by_user_id=current_user.id if current_user.is_authenticated else None)
            c.image_id = asset.id if asset else c.image_id
        else:
            c.image_id = None

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

    fname = f"{secrets.token_hex(12)}{ext}"
    abs_path = os.path.join(UPLOAD_DIR, fname)
    f.save(abs_path)

    rel_path = f"/static/uploads/{fname}"
    size_bytes = os.path.getsize(abs_path) if os.path.exists(abs_path) else None
    content_type = getattr(f, "mimetype", None)

    asset = upsert_image_asset_by_path(
        rel_path,
        original_name=original,
        content_type=content_type,
        size_bytes=size_bytes,
        uploaded_by_user_id=current_user.id if current_user.is_authenticated else None
    )

    audit("upload", "image", asset.id if asset else None, {"path": rel_path, "original": original})
    return jsonify({"success": True, "path": rel_path, "image_id": asset.id if asset else None})


@app.get("/manage-inventory.html")
@login_required
@require_roles("Admin", "Manager")
def manage_inventory_page():
    return render_template("manage-inventory.html")


@app.get("/manage-invertory.html")
@login_required
@require_roles("Admin", "Manager")
def manage_inventory_page_alias():
    return redirect("/manage-inventory.html", code=302)


@app.get("/api/inventory/summary")
@login_required
@require_roles("Admin", "Manager")
def api_inventory_summary():
    today_start = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)

    active_ingredients = Ingredient.query.filter(Ingredient.is_active.is_(True)).count()

    low_stock = (
        Ingredient.query
        .filter(
            Ingredient.is_active.is_(True),
            Ingredient.low_stock_threshold.isnot(None),
            Ingredient.stock_qty <= Ingredient.low_stock_threshold,
            Ingredient.low_stock_threshold > 0
        )
        .count()
    )

    moves_today = StockLedger.query.filter(StockLedger.created_at >= today_start).count()
    open_pos = PurchaseOrder.query.filter(PurchaseOrder.status == "open").count()

    return jsonify({
        "success": True,
        "summary": {
            "active_ingredients": active_ingredients,
            "low_stock": low_stock,
            "moves_today": moves_today,
            "open_pos": open_pos
        }
    })


@app.get("/api/ingredients")
@login_required
@require_roles("Admin", "Manager")
def api_ingredients_list():
    q = Ingredient.query

    qstr = (request.args.get("q") or "").strip()
    if qstr:
        like = f"%{qstr}%"
        q = q.filter(Ingredient.name.like(like))

    rows = q.order_by(Ingredient.name.asc()).all()
    out = [{
        "id": r.id,
        "name": r.name,
        "unit": r.unit,
        "stock_qty": str(r.stock_qty or 0),
        "low_stock_threshold": str(r.low_stock_threshold or 0),
        "is_active": bool(r.is_active),
    } for r in rows]

    return jsonify({"success": True, "ingredients": out})


@app.post("/api/ingredients")
@login_required
@require_roles("Admin", "Manager")
def api_ingredient_create():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    unit = (d.get("unit") or "pcs").strip() or "pcs"

    if not name:
        return json_error("name is required", 400)

    exists = Ingredient.query.filter(db.func.lower(Ingredient.name) == name.lower()).first()
    if exists:
        return json_error("ingredient name already exists", 400)

    opening_qty = d.get("opening_qty")
    low_thr = d.get("low_stock_threshold")

    row = Ingredient(
        name=name,
        unit=unit,
        stock_qty=dec3(opening_qty if opening_qty is not None else 0),
        low_stock_threshold=dec3(low_thr if low_thr is not None else 0),
        is_active=True
    )
    db.session.add(row)
    db.session.commit()
    audit("create", "ingredient", row.id)

    if opening_qty is not None and Decimal(str(opening_qty)) != Decimal("0"):
        db.session.add(StockLedger(
            ingredient_id=row.id,
            change_qty=dec3(opening_qty),
            reason="opening_balance",
            ref_type="ingredient",
            ref_id=row.id,
            created_at=now_utc()
        ))
        db.session.commit()
        audit("stock_opening", "ingredient", row.id, {"qty": str(dec3(opening_qty))})

    return jsonify({"success": True, "id": row.id})


@app.put("/api/ingredients/<int:ingredient_id>")
@login_required
@require_roles("Admin", "Manager")
def api_ingredient_update(ingredient_id):
    bad = require_json()
    if bad:
        return bad

    row = Ingredient.query.get_or_404(ingredient_id)
    d = request.get_json() or {}

    if "name" in d:
        name = (d.get("name") or "").strip()
        if not name:
            return json_error("name is required", 400)
        other = Ingredient.query.filter(
            db.func.lower(Ingredient.name) == name.lower(),
            Ingredient.id != row.id
        ).first()
        if other:
            return json_error("ingredient name already exists", 400)
        row.name = name

    if "unit" in d:
        row.unit = (d.get("unit") or "pcs").strip() or "pcs"

    if "low_stock_threshold" in d:
        row.low_stock_threshold = dec3(d.get("low_stock_threshold") or 0)

    if "is_active" in d:
        row.is_active = bool(d.get("is_active"))

    db.session.commit()
    audit("update", "ingredient", row.id)
    return jsonify({"success": True})


@app.delete("/api/ingredients/<int:ingredient_id>")
@login_required
@require_roles("Admin", "Manager")
def api_ingredient_deactivate(ingredient_id):
    row = Ingredient.query.get_or_404(ingredient_id)
    row.is_active = False
    db.session.commit()
    audit("deactivate", "ingredient", row.id)
    return jsonify({"success": True})


@app.post("/api/inventory/adjust")
@login_required
@require_roles("Admin", "Manager")
def api_inventory_adjust():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json() or {}
    ingredient_id = int(d.get("ingredient_id") or 0)
    change_qty = d.get("change_qty")
    reason = (d.get("reason") or "count_adjustment").strip()
    ref_note = (d.get("ref_note") or "").strip()

    if ingredient_id <= 0:
        return json_error("ingredient_id is required", 400)

    try:
        qty = Decimal(str(change_qty))
    except Exception:
        return json_error("change_qty is invalid", 400)

    if qty == Decimal("0"):
        return json_error("change_qty cannot be zero", 400)

    ing = Ingredient.query.get_or_404(ingredient_id)
    if not bool(ing.is_active):
        return json_error("ingredient is inactive", 400)

    ing.stock_qty = (Decimal(str(ing.stock_qty or 0)) + qty).quantize(Decimal("0.001"))
    db.session.add(StockLedger(
        ingredient_id=ingredient_id,
        change_qty=dec3(qty),
        reason=reason,
        ref_type="manual",
        ref_id=None,
        created_at=now_utc()
    ))
    db.session.commit()
    audit("stock_adjust", "ingredient", ingredient_id, {"qty": str(dec3(qty)), "reason": reason, "ref_note": ref_note})

    return jsonify({"success": True})


@app.get("/api/stock-ledger")
@login_required
@require_roles("Admin", "Manager")
def api_stock_ledger_list():
    limit = int(request.args.get("limit") or 200)
    limit = max(1, min(limit, 500))

    ingredient_id = request.args.get("ingredient_id")
    q = (
        db.session.query(
            StockLedger.id,
            StockLedger.created_at,
            StockLedger.change_qty,
            StockLedger.reason,
            StockLedger.ref_type,
            StockLedger.ref_id,
            Ingredient.name.label("ingredient_name")
        )
        .join(Ingredient, Ingredient.id == StockLedger.ingredient_id)
    )

    if ingredient_id:
        try:
            iid = int(ingredient_id)
            q = q.filter(StockLedger.ingredient_id == iid)
        except Exception:
            return json_error("ingredient_id is invalid", 400)

    rows = q.order_by(StockLedger.id.desc()).limit(limit).all()

    out = [{
        "id": r.id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "ingredient_name": r.ingredient_name,
        "change_qty": str(r.change_qty or 0),
        "reason": r.reason,
        "ref_type": r.ref_type,
        "ref_id": r.ref_id
    } for r in rows]

    return jsonify({"success": True, "ledger": out})


@app.get("/api/suppliers")
@login_required
@require_roles("Admin", "Manager")
def api_suppliers_list():
    q = Supplier.query
    qstr = (request.args.get("q") or "").strip()
    if qstr:
        like = f"%{qstr}%"
        q = q.filter(Supplier.name.like(like))

    rows = q.order_by(Supplier.name.asc()).all()
    out = [{
        "id": r.id,
        "name": r.name,
        "phone": r.phone,
        "email": r.email,
        "address": r.address,
        "is_active": bool(r.is_active),
        "created_at": r.created_at.isoformat() if r.created_at else None
    } for r in rows]

    return jsonify({"success": True, "suppliers": out})


@app.post("/api/suppliers")
@login_required
@require_roles("Admin", "Manager")
def api_supplier_create():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json() or {}
    name = (d.get("name") or "").strip()
    if not name:
        return json_error("name is required", 400)

    exists = Supplier.query.filter(db.func.lower(Supplier.name) == name.lower()).first()
    if exists:
        return json_error("supplier name already exists", 400)

    row = Supplier(
        name=name,
        phone=(d.get("phone") or "").strip() or None,
        email=(d.get("email") or "").strip() or None,
        address=(d.get("address") or "").strip() or None,
        is_active=bool(d.get("is_active", True)),
        created_at=now_utc()
    )
    db.session.add(row)
    db.session.commit()
    audit("create", "supplier", row.id)
    return jsonify({"success": True, "id": row.id})


@app.put("/api/suppliers/<int:supplier_id>")
@login_required
@require_roles("Admin", "Manager")
def api_supplier_update(supplier_id):
    bad = require_json()
    if bad:
        return bad

    row = Supplier.query.get_or_404(supplier_id)
    d = request.get_json() or {}

    if "name" in d:
        name = (d.get("name") or "").strip()
        if not name:
            return json_error("name is required", 400)
        other = Supplier.query.filter(
            db.func.lower(Supplier.name) == name.lower(),
            Supplier.id != row.id
        ).first()
        if other:
            return json_error("supplier name already exists", 400)
        row.name = name

    if "phone" in d:
        row.phone = (d.get("phone") or "").strip() or None
    if "email" in d:
        row.email = (d.get("email") or "").strip() or None
    if "address" in d:
        row.address = (d.get("address") or "").strip() or None
    if "is_active" in d:
        row.is_active = bool(d.get("is_active"))

    db.session.commit()
    audit("update", "supplier", row.id)
    return jsonify({"success": True})


@app.delete("/api/suppliers/<int:supplier_id>")
@login_required
@require_roles("Admin", "Manager")
def api_supplier_deactivate(supplier_id):
    row = Supplier.query.get_or_404(supplier_id)
    row.is_active = False
    db.session.commit()
    audit("deactivate", "supplier", row.id)
    return jsonify({"success": True})


@app.get("/api/purchase-orders")
@login_required
@require_roles("Admin", "Manager")
def api_purchase_orders_list():
    status = (request.args.get("status") or "open").strip().lower()

    q = (
        db.session.query(
            PurchaseOrder,
            Supplier.name.label("supplier_name")
        )
        .join(Supplier, Supplier.id == PurchaseOrder.supplier_id)
    )

    if status in ("open", "received"):
        q = q.filter(PurchaseOrder.status == status)

    rows = q.order_by(PurchaseOrder.id.desc()).limit(300).all()

    out = []
    for po, supplier_name in rows:
        out.append({
            "id": po.id,
            "supplier_id": po.supplier_id,
            "supplier_name": supplier_name,
            "status": po.status,
            "total_cost": str(po.total_cost or 0),
            "created_at": po.created_at.isoformat() if po.created_at else None,
            "received_at": po.received_at.isoformat() if po.received_at else None
        })

    return jsonify({"success": True, "purchase_orders": out})


@app.get("/api/purchase-orders/<int:po_id>")
@login_required
@require_roles("Admin", "Manager")
def api_purchase_order_get(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)
    supplier = Supplier.query.get(po.supplier_id)

    items = PurchaseOrderItem.query.filter_by(po_id=po.id).order_by(PurchaseOrderItem.id.asc()).all()
    ing_ids = [x.ingredient_id for x in items]
    ing_map = {}
    if ing_ids:
        ings = Ingredient.query.filter(Ingredient.id.in_(ing_ids)).all()
        ing_map = {i.id: i for i in ings}

    out_items = []
    for it in items:
        ing = ing_map.get(it.ingredient_id)
        out_items.append({
            "id": it.id,
            "ingredient_id": it.ingredient_id,
            "ingredient_name": ing.name if ing else f"Ingredient #{it.ingredient_id}",
            "qty": str(it.qty or 0),
            "unit_cost": str(it.unit_cost or 0)
        })

    return jsonify({
        "success": True,
        "purchase_order": {
            "id": po.id,
            "supplier_id": po.supplier_id,
            "supplier_name": supplier.name if supplier else None,
            "status": po.status,
            "total_cost": str(po.total_cost or 0),
            "created_at": po.created_at.isoformat() if po.created_at else None,
            "received_at": po.received_at.isoformat() if po.received_at else None,
            "items": out_items
        }
    })


@app.post("/api/purchase-orders")
@login_required
@require_roles("Admin", "Manager")
def api_purchase_order_create():
    bad = require_json()
    if bad:
        return bad

    d = request.get_json() or {}
    supplier_id = int(d.get("supplier_id") or 0)
    items = d.get("items") or []

    if supplier_id <= 0:
        return json_error("supplier_id is required", 400)

    supplier = Supplier.query.get(supplier_id)
    if not supplier or not bool(supplier.is_active):
        return json_error("supplier is invalid or inactive", 400)

    if not isinstance(items, list) or not items:
        return json_error("items must be a non-empty list", 400)

    po = PurchaseOrder(
        supplier_id=supplier_id,
        status="open",
        total_cost=money(0),
        created_at=now_utc()
    )
    db.session.add(po)
    db.session.flush()

    total = Decimal("0.00")
    created = 0

    for it in items:
        try:
            ing_id = int(it.get("ingredient_id") or 0)
        except Exception:
            ing_id = 0

        if ing_id <= 0:
            continue

        ing = Ingredient.query.get(ing_id)
        if not ing or not bool(ing.is_active):
            continue

        try:
            qty = Decimal(str(it.get("qty") or 0))
        except Exception:
            qty = Decimal("0")

        if qty <= 0:
            continue

        unit_cost = money(it.get("unit_cost") or 0)

        row = PurchaseOrderItem(
            po_id=po.id,
            ingredient_id=ing_id,
            qty=dec3(qty),
            unit_cost=unit_cost
        )
        db.session.add(row)

        line_total = (Decimal(str(dec3(qty))) * Decimal(str(unit_cost))).quantize(Decimal("0.01"))
        total += line_total
        created += 1

    if created == 0:
        db.session.rollback()
        return json_error("no valid items were provided", 400)

    po.total_cost = money(total)
    db.session.commit()
    audit("create", "purchase_order", po.id, {"items": created, "total_cost": str(po.total_cost)})

    return jsonify({"success": True, "id": po.id})


@app.post("/api/purchase-orders/<int:po_id>/receive")
@login_required
@require_roles("Admin", "Manager")
def api_purchase_order_receive(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)
    if po.status != "open":
        return json_error("purchase order is not open", 400)

    items = PurchaseOrderItem.query.filter_by(po_id=po.id).all()
    if not items:
        return json_error("purchase order has no items", 400)

    for it in items:
        ing = Ingredient.query.get(it.ingredient_id)
        if not ing:
            continue
        qty = Decimal(str(it.qty or 0)).quantize(Decimal("0.001"))
        if qty == Decimal("0.000"):
            continue

        ing.stock_qty = (Decimal(str(ing.stock_qty or 0)) + qty).quantize(Decimal("0.001"))
        db.session.add(StockLedger(
            ingredient_id=ing.id,
            change_qty=dec3(qty),
            reason="purchase",
            ref_type="po",
            ref_id=po.id,
            created_at=now_utc()
        ))

    po.status = "received"
    po.received_at = now_utc()
    db.session.commit()

    audit("receive", "purchase_order", po.id)
    return jsonify({"success": True})


@app.delete("/api/purchase-orders/<int:po_id>")
@login_required
@require_roles("Admin", "Manager")
def api_purchase_order_delete(po_id):
    po = PurchaseOrder.query.get_or_404(po_id)
    if po.status != "open":
        return json_error("only open purchase orders can be deleted", 400)

    PurchaseOrderItem.query.filter_by(po_id=po.id).delete()
    db.session.commit()

    db.session.delete(po)
    db.session.commit()

    audit("delete", "purchase_order", po_id)
    return jsonify({"success": True})


@app.get("/api/dashboard/summary")
@login_required
@require_roles("Admin", "Manager", "Cashier")
def api_dashboard_summary():
    now = now_utc()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    month_completed = (
        Order.query
        .filter(
            Order.status == OrderStatus.COMPLETED.value,
            sa_or(
                Order.completed_at >= month_start,
                sa_and(Order.completed_at.is_(None), Order.created_at >= month_start),
            )
        )
        .all()
    )

    sales_today = Decimal("0.00")
    sales_week = Decimal("0.00")
    sales_month = Decimal("0.00")

    for o in month_completed:
        ts = o.completed_at or o.created_at
        if not ts:
            continue
        total = money(o.total or 0)
        sales_month += total
        if ts >= week_start:
            sales_week += total
        if ts >= today_start:
            sales_today += total

    status_rows = (
        db.session.query(Order.status, db.func.count(Order.id))
        .filter(Order.created_at >= month_start)
        .group_by(Order.status)
        .all()
    )
    orders_by_status = {str(st): int(cnt) for st, cnt in status_rows if st is not None}

    top_rows = (
        db.session.query(
            OrderItem.name_snapshot.label("name"),
            db.func.sum(OrderItem.qty).label("qty")
        )
        .join(Order, Order.id == OrderItem.order_id)
        .filter(
            Order.status == OrderStatus.COMPLETED.value,
            OrderItem.is_void.is_(False),
            sa_or(
                Order.completed_at >= month_start,
                sa_and(Order.completed_at.is_(None), Order.created_at >= month_start),
            )
        )
        .group_by(OrderItem.name_snapshot)
        .order_by(db.func.sum(OrderItem.qty).desc())
        .limit(8)
        .all()
    )
    top_selling_items = [{"name": (r.name or ""), "qty": int(r.qty or 0)} for r in top_rows]

    today_date = now.date()
    shift_rows = (
        db.session.query(User.name, User.role)
        .join(ShiftAssignment, ShiftAssignment.user_id == User.id)
        .filter(ShiftAssignment.shift_date == today_date)
        .order_by(User.name.asc())
        .all()
    )

    seen = set()
    staff_on_shift = []
    for name, role in shift_rows:
        key = f"{name}|{role}"
        if key in seen:
            continue
        seen.add(key)
        staff_on_shift.append({"name": name or "", "role": role or ""})

    return jsonify({
        "success": True,
        "sales": {
            "today": str(sales_today.quantize(Decimal("0.01"))),
            "week": str(sales_week.quantize(Decimal("0.01"))),
            "month": str(sales_month.quantize(Decimal("0.01")))
        },
        "orders_by_status": orders_by_status,
        "top_selling_items": top_selling_items,
        "staff_on_shift": staff_on_shift,
        "tables": {"active": 0, "total": 0}
    })


@app.get("/api/orders/<int:order_id>/bill-preview")
@login_required
def api_order_bill_preview(order_id):
    o = Order.query.get_or_404(order_id)
    if not order_accessible_to_current_user(o):
        return json_error("Forbidden", 403)

    totals = compute_order_totals(o)
    db.session.commit()
    paid_total = paid_total_for_order(o.id)

    return jsonify({
        "success": True,
        "totals": totals,
        "paid_total": str(paid_total)
    })


@app.get("/api/orders/<int:order_id>/voucher")
@login_required
def api_order_voucher_alias(order_id):
    return api_voucher_pdf(order_id)



@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"success": True, "time": now_utc().isoformat()})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_image_schema()
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)