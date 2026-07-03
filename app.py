"""
MoneyEx Analytics — single-file FastAPI backend.
Run: uvicorn app:app --host 0.0.0.0 --port $PORT
"""
from datetime import datetime, timedelta
from typing import Optional, List
import enum
import secrets
import random
import uuid
import io
import csv

from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from pydantic_settings import BaseSettings
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Enum, Float, select, update, func, delete,
)
from sqlalchemy.sql import func as sqlfunc
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase


class Settings(BaseSettings):
    PROJECT_NAME: str = "MoneyEx Analytics"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    DATABASE_URL: str = "sqlite+aiosqlite:///./moneyex.db"

    class Config:
        env_file = ".env"


settings = Settings()

ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(p, h):
    return pwd_context.verify(p, h)


def get_password_hash(p):
    return pwd_context.hash(p)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(120))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.viewer)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())
    last_login = Column(DateTime(timezone=True), nullable=True)


class Channel(str, enum.Enum):
    online = "online"
    branch = "branch"
    agent = "agent"


class TransactionType(str, enum.Enum):
    remittance = "remittance"
    exchange = "exchange"
    transfer = "transfer"


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    txn_ref = Column(String(64), unique=True, index=True)
    customer_id = Column(String(64), index=True)
    customer_segment = Column(String(64), nullable=True)
    channel = Column(Enum(Channel), nullable=False, index=True)
    txn_type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(8), default="OMR")
    destination_country = Column(String(64), nullable=True)
    corridor = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now(), index=True)
    is_flagged = Column(Boolean, default=False)


class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.viewer


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserOut(BaseModel):
    id: int
    full_name: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserOut


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TransactionCreate(BaseModel):
    txn_ref: str
    customer_id: str
    customer_segment: Optional[str] = None
    channel: Channel
    txn_type: TransactionType
    amount: float
    currency: str = "OMR"
    destination_country: Optional[str] = None
    corridor: Optional[str] = None


class TransactionOut(BaseModel):
    id: int
    txn_ref: str
    customer_id: str
    customer_segment: Optional[str]
    channel: Channel
    txn_type: TransactionType
    amount: float
    currency: str
    destination_country: Optional[str]
    corridor: Optional[str]
    created_at: datetime
    is_flagged: bool
    model_config = {"from_attributes": True}


class ChannelSplit(BaseModel):
    channel: str
    count: int
    total_value: float
    pct_count: float
    pct_value: float


class MonthlyTrend(BaseModel):
    month: str
    online: float
    offline: float
    online_count: int
    offline_count: int


class SegmentBreakdown(BaseModel):
    segment: str
    count: int
    total_value: float


class CorridorStat(BaseModel):
    corridor: str
    count: int
    total_value: float


class DashboardSummary(BaseModel):
    total_transactions: int
    total_value: float
    online_count: int
    offline_count: int
    online_value: float
    offline_value: float
    online_pct: float
    avg_ticket_online: float
    avg_ticket_offline: float
    channel_split: List[ChannelSplit]
    monthly_trend: List[MonthlyTrend]
    segment_breakdown: List[SegmentBreakdown]
    top_corridors: List[CorridorStat]


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    result = await db.execute(select(User).where(User.id == int(payload.get("sub", 0))))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


async def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in (UserRole.admin, UserRole.analyst):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst access required")
    return current_user


auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/login", response_model=Token)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.utcnow()))
    await db.commit()
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return Token(access_token=token, token_type="bearer", user=UserOut.model_validate(user))


@auth_router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


@auth_router.post("/register", response_model=UserOut, dependencies=[Depends(require_admin)])
async def register(data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(full_name=data.full_name, email=data.email,
                hashed_password=get_password_hash(data.password), role=data.role)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


analytics_router = APIRouter(prefix="/analytics", tags=["analytics"])


@analytics_router.get("/dashboard", response_model=DashboardSummary)
async def dashboard(from_date: Optional[str] = Query(None), to_date: Optional[str] = Query(None),
                    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Transaction)
    if from_date:
        q = q.where(Transaction.created_at >= datetime.fromisoformat(from_date))
    if to_date:
        q = q.where(Transaction.created_at <= datetime.fromisoformat(to_date))
    result = await db.execute(q)
    txns = result.scalars().all()
    if not txns:
        return DashboardSummary(total_transactions=0, total_value=0, online_count=0, offline_count=0,
                                online_value=0, offline_value=0, online_pct=0, avg_ticket_online=0,
                                avg_ticket_offline=0, channel_split=[], monthly_trend=[], segment_breakdown=[], top_corridors=[])
    online = [t for t in txns if t.channel == Channel.online]
    offline = [t for t in txns if t.channel != Channel.online]
    total_count = len(txns)
    total_value = sum(t.amount for t in txns)
    online_count = len(online)
    offline_count = len(offline)
    online_value = sum(t.amount for t in online)
    offline_value = sum(t.amount for t in offline)
    channel_map = {}
    for t in txns:
        ch = t.channel.value
        channel_map.setdefault(ch, {"count": 0, "value": 0.0})
        channel_map[ch]["count"] += 1
        channel_map[ch]["value"] += t.amount
    channel_split = [ChannelSplit(channel=ch, count=v["count"], total_value=round(v["value"], 2),
                     pct_count=round(v["count"] / total_count * 100, 1),
                     pct_value=round(v["value"] / total_value * 100, 1) if total_value else 0)
                     for ch, v in channel_map.items()]
    monthly_map = {}
    for t in txns:
        key = t.created_at.strftime("%Y-%m")
        monthly_map.setdefault(key, {"online": 0.0, "offline": 0.0, "online_count": 0, "offline_count": 0})
        if t.channel == Channel.online:
            monthly_map[key]["online"] += t.amount
            monthly_map[key]["online_count"] += 1
        else:
            monthly_map[key]["offline"] += t.amount
            monthly_map[key]["offline_count"] += 1
    monthly_trend = [MonthlyTrend(month=k, online=round(v["online"], 2), offline=round(v["offline"], 2),
                     online_count=v["online_count"], offline_count=v["offline_count"])
                     for k, v in sorted(monthly_map.items())]
    seg_map = {}
    for t in txns:
        seg = t.customer_segment or "Unknown"
        seg_map.setdefault(seg, {"count": 0, "value": 0.0})
        seg_map[seg]["count"] += 1
        seg_map[seg]["value"] += t.amount
    segment_breakdown = [SegmentBreakdown(segment=s, count=v["count"], total_value=round(v["value"], 2))
                         for s, v in sorted(seg_map.items(), key=lambda x: -x[1]["value"])]
    corr_map = {}
    for t in txns:
        c = t.corridor or "Local"
        corr_map.setdefault(c, {"count": 0, "value": 0.0})
        corr_map[c]["count"] += 1
        corr_map[c]["value"] += t.amount
    top_corridors = [CorridorStat(corridor=c, count=v["count"], total_value=round(v["value"], 2))
                     for c, v in sorted(corr_map.items(), key=lambda x: -x[1]["value"])[:8]]
    return DashboardSummary(total_transactions=total_count, total_value=round(total_value, 2),
        online_count=online_count, offline_count=offline_count, online_value=round(online_value, 2),
        offline_value=round(offline_value, 2), online_pct=round(online_count / total_count * 100, 1) if total_count else 0,
        avg_ticket_online=round(online_value / online_count, 2) if online_count else 0,
        avg_ticket_offline=round(offline_value / offline_count, 2) if offline_count else 0,
        channel_split=channel_split, monthly_trend=monthly_trend, segment_breakdown=segment_breakdown, top_corridors=top_corridors)


txn_router = APIRouter(prefix="/transactions", tags=["transactions"])


@txn_router.get("/", response_model=dict)
async def list_transactions(page: int = Query(1, ge=1), limit: int = Query(20, le=100),
                            channel: Optional[str] = None, from_date: Optional[str] = None,
                            to_date: Optional[str] = None, db: AsyncSession = Depends(get_db),
                            _: User = Depends(get_current_user)):
    q = select(Transaction).order_by(Transaction.created_at.desc())
    if channel:
        q = q.where(Transaction.channel == channel)
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar()
    q = q.offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)
    items = result.scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [TransactionOut.model_validate(t) for t in items]}


@txn_router.post("/", response_model=TransactionOut, dependencies=[Depends(require_analyst)])
async def create_transaction(data: TransactionCreate, db: AsyncSession = Depends(get_db)):
    txn = Transaction(**data.model_dump())
    db.add(txn)
    await db.commit()
    await db.refresh(txn)
    return TransactionOut.model_validate(txn)


@txn_router.delete("/{txn_id}", dependencies=[Depends(require_analyst)])
async def delete_transaction(txn_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Transaction).where(Transaction.id == txn_id))
    txn = result.scalar_one_or_none()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    await db.delete(txn)
    await db.commit()
    return {"ok": True}


_CHANNEL_ALIASES = {
    "online": "online", "web": "online", "app": "online", "mobile": "online", "digital": "online",
    "branch": "branch", "offline": "branch", "counter": "branch", "store": "branch", "walk-in": "branch",
    "agent": "agent", "partner": "agent", "reseller": "agent",
}
_TYPE_ALIASES = {
    "remittance": "remittance", "remit": "remittance", "send": "remittance",
    "exchange": "exchange", "fx": "exchange", "forex": "exchange", "currency": "exchange",
    "transfer": "transfer", "wire": "transfer",
}


def _norm(s) -> str:
    return str(s if s is not None else "").strip().lower().replace(" ", "_")


def _parse_csv(content: bytes):
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return [{_norm(k): v for k, v in row.items() if k is not None} for row in reader]


def _parse_xlsx(content: bytes):
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        return []
    headers = [_norm(h) for h in rows[0]]
    out = []
    for r in rows[1:]:
        out.append({headers[i]: (r[i] if i < len(r) else None) for i in range(len(headers))})
    return out


def _pick(row: dict, *keys):
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "":
            return v
    return None


def _parse_date(raw):
    if raw is None:
        return datetime.utcnow()
    if isinstance(raw, datetime):
        return raw
    s = str(raw).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y", "%d-%b-%Y", "%d %b %Y"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.utcnow()


@txn_router.post("/import", dependencies=[Depends(require_analyst)])
async def import_transactions(file: UploadFile = File(...), mode: str = Form("replace"),
                              db: AsyncSession = Depends(get_db)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    fname = (file.filename or "").lower()
    try:
        rows = _parse_xlsx(content) if fname.endswith((".xlsx", ".xlsm")) else _parse_csv(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")
    if not rows:
        raise HTTPException(status_code=400, detail="No data rows found in the file")
    if mode == "replace":
        await db.execute(delete(Transaction))
        await db.commit()
    imported = 0
    errors = []
    seen_refs = set()
    batch = []
    for i, row in enumerate(rows, start=2):
        if not any(v is not None and str(v).strip() != "" for v in row.values()):
            continue
        try:
            amt_raw = _pick(row, "amount", "value", "txn_amount", "transaction_amount", "amt")
            if amt_raw is None:
                raise ValueError("missing 'amount'")
            amount = float(str(amt_raw).replace(",", "").replace("OMR", "").strip())
            channel = _CHANNEL_ALIASES.get(_norm(_pick(row, "channel", "source") or "online"), "online")
            txn_type = _TYPE_ALIASES.get(_norm(_pick(row, "txn_type", "type", "transaction_type") or "remittance"), "remittance")
            ref = str(_pick(row, "txn_ref", "reference", "ref") or f"TXN{str(uuid.uuid4())[:8].upper()}")
            base = ref
            n = 1
            while ref in seen_refs:
                ref = f"{base}-{n}"
                n += 1
            seen_refs.add(ref)
            seg = _pick(row, "customer_segment", "segment")
            dest = _pick(row, "destination_country", "country", "destination")
            corr = _pick(row, "corridor", "route")
            batch.append(Transaction(
                txn_ref=ref,
                customer_id=str(_pick(row, "customer_id", "customer", "cust_id") or f"CUST{random.randint(1000, 9999)}"),
                customer_segment=str(seg) if seg is not None else None,
                channel=Channel(channel),
                txn_type=TransactionType(txn_type),
                amount=round(amount, 2),
                currency=str(_pick(row, "currency", "ccy") or "OMR"),
                destination_country=str(dest) if dest is not None else None,
                corridor=str(corr) if corr is not None else None,
                created_at=_parse_date(_pick(row, "date", "created_at", "txn_date", "transaction_date")),
            ))
            imported += 1
        except Exception as e:
            if len(errors) < 25:
                errors.append(f"Row {i}: {e}")
    if batch:
        db.add_all(batch)
        await db.commit()
    total = (await db.execute(select(func.count()).select_from(Transaction))).scalar()
    return {"imported": imported, "skipped": len(rows) - imported, "errors": errors, "mode": mode, "total_in_db": total}


admin_router = APIRouter(prefix="/admin", tags=["admin"])


@admin_router.get("/users", response_model=list[UserOut])
async def list_users(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@admin_router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: int, data: UserUpdate, db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(user, field, value)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@admin_router.delete("/users/{user_id}")
async def delete_user(user_id: int, db: AsyncSession = Depends(get_db), admin: User = Depends(require_admin)):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"ok": True}


@admin_router.get("/stats")
async def admin_stats(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    total_users = (await db.execute(select(func.count()).select_from(User))).scalar()
    active_users = (await db.execute(select(func.count()).select_from(User).where(User.is_active == True))).scalar()
    total_txns = (await db.execute(select(func.count()).select_from(Transaction))).scalar()
    total_value = (await db.execute(select(func.sum(Transaction.amount)).select_from(Transaction))).scalar() or 0
    return {"total_users": total_users, "active_users": active_users,
            "total_transactions": total_txns, "total_value": round(total_value, 2)}


app = FastAPI(title=settings.PROJECT_NAME, version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(analytics_router, prefix=settings.API_V1_STR)
app.include_router(txn_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)


@app.on_event("startup")
async def on_startup():
    await init_db()
    await seed_demo_data()


async def seed_demo_data():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == "admin@moneyex.com"))
        if not result.scalar_one_or_none():
            admin = User(full_name="Admin User", email="admin@moneyex.com",
                         hashed_password=get_password_hash("Admin@1234"), role=UserRole.admin)
            analyst = User(full_name="Adarsh Vasudevan", email="adarsh@ozngroup.com",
                           hashed_password=get_password_hash("Analyst@1234"), role=UserRole.analyst)
            viewer = User(full_name="Demo Viewer", email="viewer@moneyex.com",
                          hashed_password=get_password_hash("Viewer@1234"), role=UserRole.viewer)
            db.add_all([admin, analyst, viewer])
            await db.commit()
        txn_exists = (await db.execute(select(Transaction).limit(1))).scalar_one_or_none()
        if not txn_exists:
            segments = ["Premium", "Standard", "New", "Corporate", "Youth"]
            corridors = ["OMR-INR", "OMR-PKR", "OMR-PHP", "OMR-EGP", "OMR-BDT", "OMR-LKR", "OMR-NPR", "Local"]
            countries = ["India", "Pakistan", "Philippines", "Egypt", "Bangladesh", "Sri Lanka", "Nepal", "Oman"]
            txns = []
            base_date = datetime.utcnow() - timedelta(days=365)
            for i in range(800):
                day_offset = random.randint(0, 365)
                ch = random.choices([Channel.online, Channel.branch, Channel.agent], weights=[38, 45, 17])[0]
                idx = random.randint(0, len(corridors) - 1)
                txns.append(Transaction(
                    txn_ref=f"TXN{str(uuid.uuid4())[:8].upper()}",
                    customer_id=f"CUST{random.randint(1000, 9999)}",
                    customer_segment=random.choice(segments),
                    channel=ch,
                    txn_type=random.choice(list(TransactionType)),
                    amount=round(random.uniform(50, 2000) if ch == Channel.online else random.uniform(30, 1200), 2),
                    currency="OMR",
                    destination_country=countries[idx % len(countries)],
                    corridor=corridors[idx],
                    created_at=base_date + timedelta(days=day_offset, hours=random.randint(0, 23)),
                ))
            db.add_all(txns)
            await db.commit()


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.PROJECT_NAME}
