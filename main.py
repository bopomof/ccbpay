import datetime
import random
import string

from fastapi import Depends, HTTPException, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import (
    create_engine, Column, Integer, String, Numeric,
    DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from nicegui import ui, app  # app 是内置的 FastAPI

########################################
# 数据库配置
########################################

DATABASE_URL = "postgresql://zhiwei:JH2025_ccb@localhost:5432/ccbpay"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)  # 明文示例
    role          = Column(String(20), nullable=False)   # 五种角色
    parent_id     = Column(Integer, ForeignKey('users.id'), nullable=True)
    bank_key      = Column(String(128), nullable=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    children      = relationship('User', backref='parent', remote_side=[id])


class Order(Base):
    __tablename__ = 'orders'
    id                           = Column(Integer, primary_key=True, index=True)
    timestamp_str                = Column(String(20), nullable=False)
    serial_number                = Column(String(32), unique=True, nullable=False)
    product_order_number         = Column(String(40), unique=True, nullable=False)
    payment_method               = Column(String(2), nullable=False)
    order_type                   = Column(String(2), nullable=False)
    total_order_amount           = Column(Numeric(10,2), nullable=False)
    total_transaction_amount     = Column(Numeric(10,2), nullable=False)
    confirmation_date            = Column(String(8), nullable=True)
    product_description          = Column(String(300), nullable=True)
    bank_payment_transaction_number = Column(String(100), nullable=True)
    bank_payment_order_number    = Column(String(100), nullable=True)
    payment_status               = Column(String(2), nullable=False)
    created_by                   = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at                   = Column(DateTime, default=datetime.datetime.utcnow)


# 创建表
Base.metadata.create_all(bind=engine)

########################################
# 简易明文密码 & 认证工具
########################################

def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_password_hash(p: str) -> str:
    return p  # 明文演示


def verify_password(plain: str, stored: str) -> bool:
    return plain == stored


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/token')
sessions = {}           # token -> user_id
current_user_id = None  # GUI 会话存储


def create_token(user_id: int) -> str:
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    sessions[token] = user_id
    return token


def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    if token not in sessions:
        raise HTTPException(401, 'Token 无效')
    user = db.get(User, sessions[token])
    if not user:
        raise HTTPException(401, '用户不存在')
    return user


# 初始化一个系统管理员：admin/admin
db = SessionLocal()
if not db.query(User).filter(User.role == 'system_admin').first():
    db.add(User(
        username='admin',
        password_hash=get_password_hash('admin'),
        role='system_admin'
    ))
    db.commit()
db.close()

########################################
# 后端 API（挂载到 /api/ 路径）
########################################

@app.post('/api/token')
def api_login(form: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(400, '用户名或密码错误')
    return {'access_token': create_token(user.id), 'token_type': 'bearer'}


@app.post('/api/orders')
def api_create_order(
    payment_method: str       = Form(...),
    order_type: str           = Form(...),
    total_order_amount: float = Form(...),
    total_transaction_amount: float = Form(...),
    product_description: str  = Form(''),
    user: User                = Depends(get_current_user),
    db=Depends(get_db)
):
    now = datetime.datetime.utcnow()
    ts  = now.strftime('%Y%m%d%H%M%S') + f'{int(now.microsecond/1000):03d}'
    sn  = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    pon = ''.join(random.choices(string.ascii_letters + string.digits, k=40))
    order = Order(
        timestamp_str=ts,
        serial_number=sn,
        product_order_number=pon,
        payment_method=payment_method,
        order_type=order_type,
        total_order_amount=total_order_amount,
        total_transaction_amount=total_transaction_amount,
        product_description=product_description,
        payment_status='1',
        created_by=user.id
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return {'order_id': order.id, 'serial_number': sn}

########################################
# GUI 辅助函数
########################################

def current_user_obj():
    if not current_user_id:
        return None
    db = next(get_db())
    return db.get(User, current_user_id)


def logout_and_home():
    global current_user_id
    current_user_id = None
    ui.notify('已登出', color='blue')
    ui.navigate.to('/')


########################################
# NiceGUI 页面
########################################

@ui.page('/')
def login_page():
    ui.label('支付中台 登录').classes('text-h4')
    username = ui.input('用户名')
    password = ui.input('密码').props('type=password')
    def do_login():
        global current_user_id
        db = next(get_db())
        u = db.query(User).filter(User.username == username.value).first()
        if u and verify_password(password.value, u.password_hash):
            current_user_id = u.id
            ui.notify('登录成功', color='green')
            ui.navigate.to('/dashboard')
        else:
            ui.notify('用户名或密码错误', color='red')
    ui.button('登录', on_click=do_login)


@ui.page('/dashboard')
def dashboard_page():
    u = current_user_obj()
    if not u:
        ui.navigate.to('/')
        return
    ui.label(f'欢迎，{u.username} （{u.role}）').classes('text-h5')
    ui.button('登出', on_click=logout_and_home)
    ui.separator()
    if u.role in ['system_admin', 'customer_service', 'group_merchant']:
        ui.button('商户树状列表', on_click=lambda: ui.navigate.to('/tree'))
    if u.role == 'ordinary_merchant':
        ui.button('生成支付订单', on_click=lambda: ui.navigate.to('/create_order'))
        ui.button('查询订单', on_click=lambda: ui.navigate.to('/query_order'))
    if u.role in ['customer_service', 'group_merchant', 'merchant_manager', 'ordinary_merchant']:
        ui.button('修改密码', on_click=lambda: ui.navigate.to('/change_password'))
    if u.role == 'system_admin':
        ui.button('配置银行密钥', on_click=lambda: ui.navigate.to('/config_key'))
        ui.button('管理用户', on_click=lambda: ui.navigate.to('/manage_users'))


@ui.page('/tree')
def merchant_tree_page():
    u = current_user_obj()
    if not u:
        ui.navigate.to('/')
        return
    ui.label('商户树状列表').classes('text-h5')
    db = next(get_db())
    ms = db.query(User).filter(
        User.role.in_(['group_merchant', 'merchant_manager', 'ordinary_merchant'])
    ).all()
    tree = {}
    for m in ms:
        if m.role == 'group_merchant':
            tree[m.id] = {'u': m, 'children': []}
    for m in ms:
        if m.role == 'merchant_manager' and m.parent_id in tree:
            tree[m.parent_id]['children'].append({'u': m, 'children': []})
    for m in ms:
        if m.role == 'ordinary_merchant':
            for grp in tree.values():
                for mgr in grp['children']:
                    if mgr['u'].id == m.parent_id:
                        mgr['children'].append({'u': m, 'children': []})
    def render(nodes, indent=0):
        for node in nodes:
            ui.label(' ' * indent + f"{node['u'].username} ({node['u'].role})")
            if node['children']:
                render(node['children'], indent+4)
    for grp in tree.values():
        ui.label(f"{grp['u'].username} ({grp['u'].role})").style('font-weight:bold')
        render(grp['children'], indent=4)
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


@ui.page('/create_order')
def page_create_order():
    u = current_user_obj()
    if not u or u.role != 'ordinary_merchant':
        ui.navigate.to('/dashboard')
        return
    ui.label('生成支付订单').classes('text-h5')

    pm = ui.select([('07','聚合二维码'), ('09','扫码扣款')], label='支付方式')
    pm.value = '07'

    ot = ui.select([('02','消费券'), ('03','在途订单'), ('04','普通订单')], label='订单类型')
    ot.value = '04'

    amt = ui.input('订单总金额', value='0').props('type=number')
    ta  = ui.input('交易总金额', value='0').props('type=number')
    desc = ui.input('商品描述')
    def submit():
        db = next(get_db())
        now = datetime.datetime.utcnow()
        ts = now.strftime('%Y%m%d%H%M%S') + f'{int(now.microsecond/1000):03d}'
        sn = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        pon= ''.join(random.choices(string.ascii_letters + string.digits, k=40))
        order = Order(
            timestamp_str=ts,
            serial_number=sn,
            product_order_number=pon,
            payment_method=pm.value,
            order_type=ot.value,
            total_order_amount=float(amt.value),
            total_transaction_amount=float(ta.value),
            product_description=desc.value,
            payment_status='1',
            created_by=u.id
        )
        db.add(order)
        db.commit()
        ui.notify('订单已生成', color='green')
    ui.button('提交', on_click=submit)
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


@ui.page('/query_order')
def page_query_order():
    u = current_user_obj()
    if not u or u.role != 'ordinary_merchant':
        ui.navigate.to('/dashboard')
        return
    ui.label('查询订单').classes('text-h5')
    db = next(get_db())
    for o in db.query(Order).filter(Order.created_by == u.id).all():
        ui.label(f"流水号: {o.serial_number} | 状态: {o.payment_status}")
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


@ui.page('/change_password')
def page_change_password():
    u = current_user_obj()
    if not u:
        ui.navigate.to('/')
        return
    ui.label('修改密码').classes('text-h5')
    old = ui.input('旧密码').props('type=password')
    new = ui.input('新密码').props('type=password')
    def submit():
        db  = next(get_db())
        usr = db.get(User, u.id)
        if not verify_password(old.value, usr.password_hash):
            ui.notify('旧密码错误', color='red')
        else:
            usr.password_hash = get_password_hash(new.value)
            db.commit()
            ui.notify('密码已修改', color='green')
    ui.button('提交', on_click=submit)
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


@ui.page('/config_key')
def page_config_key():
    u = current_user_obj()
    if not u or u.role != 'system_admin':
        ui.navigate.to('/dashboard')
        return
    ui.label('配置商户集团银行密钥').classes('text-h5')
    db     = next(get_db())
    groups = db.query(User).filter(User.role == 'group_merchant').all()
    sel    = ui.select([(str(g.id), g.username) for g in groups], label='商户集团')
    key    = ui.input('银行密钥')
    def submit():
        db = next(get_db())
        raw = sel.value[0] if isinstance(sel.value, tuple) else sel.value
        gm = db.get(User, int(raw))
        if gm:
            gm.bank_key = key.value
            db.commit()
            ui.notify('密钥已保存', color='green')
        else:
            ui.notify('请选择有效集团', color='red')
    ui.button('提交', on_click=submit)
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


@ui.page('/manage_users')
def page_manage_users():
    u = current_user_obj()
    if not u or u.role != 'system_admin':
        ui.navigate.to('/dashboard')
        return
    ui.label('管理用户').classes('text-h5')
    db = next(get_db())
    for usr in db.query(User).all():
        ui.label(f"{usr.id}: {usr.username} | {usr.role}")
    ui.separator()
    ui.label('添加用户').classes('text-subtitle1')
    rsel = ui.select([
        ('system_admin','系统管理员'),
        ('customer_service','客服'),
        ('group_merchant','商户集团'),
        ('merchant_manager','商户长'),
        ('ordinary_merchant','普通商户')
    ], label='角色')
    uname = ui.input('用户名')
    pwd   = ui.input('密码').props('type=password')
    pid   = ui.input('上级ID（可留空）')
    def add_user():
        db     = next(get_db())
        parent = int(pid.value) if pid.value.isdigit() else None
        role_value = rsel.value[0] if isinstance(rsel.value, tuple) else rsel.value
        db.add(User(
            username      = uname.value,
            password_hash = get_password_hash(pwd.value),
            role          = role_value,
            parent_id     = parent
        ))
        db.commit()
        ui.notify('用户已添加', color='green')
    ui.button('添加', on_click=add_user)
    ui.button('返回', on_click=lambda: ui.navigate.to('/dashboard'))


########################################
# 启动 NiceGUI
########################################

if __name__ == '__main__':
    ui.run(title='支付中台', host='0.0.0.0', port=8080, reload=False)
