"""MoneyEx Analytics — advanced single-file FastAPI backend."""
from datetime import datetime, timedelta
from typing import Optional, List
import enum, secrets, random, uuid, io, csv

from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from pydantic_settings import BaseSettings
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Float, select, update, func, delete
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
def verify_password(p, h): return pwd_context.verify(p, h)
def get_password_hash(p): return pwd_context.hash(p)

def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token):
    try: return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError: return None

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
class Base(DeclarativeBase): pass

async def get_db():
    async with AsyncSessionLocal() as s:
        try: yield s
        finally: await s.close()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class UserRole(str, enum.Enum):
    admin = "admin"; analyst = "analyst"; viewer = "viewer"

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
    online = "online"; mobile = "mobile"; web = "web"; api = "api"; branch = "branch"; agent = "agent"
ONLINE_CHANNELS = {Channel.online, Channel.mobile, Channel.web, Channel.api}

class TransactionType(str, enum.Enum):
    remittance = "remittance"; exchange = "exchange"; transfer = "transfer"
class Direction(str, enum.Enum):
    buy = "buy"; sell = "sell"; na = "na"
class CustomerType(str, enum.Enum):
    retail = "retail"; corporate = "corporate"; vip = "vip"
class TxnStatus(str, enum.Enum):
    completed = "completed"; pending = "pending"; failed = "failed"

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    txn_ref = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now(), index=True)
    customer_id = Column(String(64), index=True)
    customer_segment = Column(String(64), nullable=True)
    customer_type = Column(Enum(CustomerType), default=CustomerType.retail, index=True)
    nationality = Column(String(64), nullable=True)
    gender = Column(String(16), nullable=True)
    age_group = Column(String(16), nullable=True)
    channel = Column(Enum(Channel), nullable=False, index=True)
    txn_type = Column(Enum(TransactionType), nullable=False)
    direction = Column(Enum(Direction), default=Direction.na)
    payment_method = Column(String(32), nullable=True)
    amount = Column(Float, nullable=False)                # OMR base value
    currency = Column(String(8), default="OMR")
    foreign_currency = Column(String(8), nullable=True)
    currency_pair = Column(String(16), nullable=True)
    fx_rate = Column(Float, nullable=True)
    commission = Column(Float, default=0.0)
    fx_margin = Column(Float, default=0.0)
    service_fee = Column(Float, default=0.0)
    vat = Column(Float, default=0.0)
    cost = Column(Float, default=0.0)
    branch = Column(String(64), nullable=True, index=True)
    city = Column(String(64), nullable=True)
    country = Column(String(64), nullable=True)
    destination_country = Column(String(64), nullable=True)
    corridor = Column(String(128), nullable=True)
    employee = Column(String(64), nullable=True, index=True)
    status = Column(Enum(TxnStatus), default=TxnStatus.completed, index=True)
    risk_score = Column(Integer, default=0)
    is_flagged = Column(Boolean, default=False, index=True)
    kyc_status = Column(String(16), default="verified", index=True)
    is_pep = Column(Boolean, default=False, index=True)
    is_sanctioned = Column(Boolean, default=False, index=True)
    nps = Column(Integer, nullable=True)
    satisfaction = Column(Integer, nullable=True)
    handling_time = Column(Integer, nullable=True)


class UserCreate(BaseModel):
    full_name: str; email: EmailStr; password: str; role: UserRole = UserRole.viewer
class UserUpdate(BaseModel):
    full_name: Optional[str] = None; role: Optional[UserRole] = None; is_active: Optional[bool] = None
class UserOut(BaseModel):
    id: int; full_name: str; email: str; role: UserRole; is_active: bool
    created_at: datetime; last_login: Optional[datetime]
    model_config = {"from_attributes": True}
class Token(BaseModel):
    access_token: str; token_type: str; user: UserOut
class LoginRequest(BaseModel):
    email: EmailStr; password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    result = await db.execute(select(User).where(User.id == int(payload.get("sub", 0))))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user
async def require_admin(u: User = Depends(get_current_user)) -> User:
    if u.role != UserRole.admin: raise HTTPException(status_code=403, detail="Admin access required")
    return u
async def require_analyst(u: User = Depends(get_current_user)) -> User:
    if u.role not in (UserRole.admin, UserRole.analyst): raise HTTPException(status_code=403, detail="Analyst access required")
    return u


auth_router = APIRouter(prefix="/auth", tags=["auth"])
@auth_router.post("/login", response_model=Token)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active: raise HTTPException(status_code=403, detail="Account deactivated")
    await db.execute(update(User).where(User.id == user.id).values(last_login=datetime.utcnow()))
    await db.commit()
    token = create_access_token({"sub": str(user.id), "role": user.role})
    return Token(access_token=token, token_type="bearer", user=UserOut.model_validate(user))
@auth_router.get("/me", response_model=UserOut)
async def me(u: User = Depends(get_current_user)): return UserOut.model_validate(u)
@auth_router.post("/register", response_model=UserOut, dependencies=[Depends(require_admin)])
async def register(data: UserCreate, db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(User).where(User.email == data.email))).scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(full_name=data.full_name, email=data.email, hashed_password=get_password_hash(data.password), role=data.role)
    db.add(user); await db.commit(); await db.refresh(user)
    return UserOut.model_validate(user)


# ---------------- analytics helpers ----------------
def _rev(t): return (t.commission or 0) + (t.fx_margin or 0) + (t.service_fee or 0)
def _is_online(t): return t.channel in ONLINE_CHANNELS

def _grp(items, keyfn, topn=None):
    m = {}
    for t in items:
        k = keyfn(t)
        if k is None or k == "": k = "Unknown"
        d = m.setdefault(str(k), {"key": str(k), "count": 0, "value": 0.0, "revenue": 0.0})
        d["count"] += 1; d["value"] += t.amount; d["revenue"] += _rev(t)
    out = sorted(m.values(), key=lambda x: -x["value"])
    for d in out: d["value"] = round(d["value"], 2); d["revenue"] = round(d["revenue"], 2)
    return out[:topn] if topn else out



def _monthly(txns, valfn):
    m = {}
    for t in txns:
        k = t.created_at.strftime("%Y-%m")
        m[k] = m.get(k, 0) + valfn(t)
    return [(k, m[k]) for k in sorted(m)]

def _forecast(values, periods=3):
    n = len(values)
    if n < 2:
        last = values[-1] if values else 0
        return [round(max(0, last), 2)] * periods
    xs = list(range(n)); ys = values
    mx = sum(xs) / n; my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs) or 1
    b = sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / denom
    a = my - b * mx
    return [round(max(0, a + b * (n + i)), 2) for i in range(periods)]

def _next_months(last, n):
    try: y, m = map(int, last.split("-"))
    except Exception: y, m = 2026, 1
    out = []
    for _ in range(n):
        m += 1
        if m > 12: m = 1; y += 1
        out.append(f"{y:04d}-{m:02d}")
    return out

def _build_cash(txns):
    branch_cash = {}; cur_pos = {}; cash_in = cash_out = 0.0
    for t in txns:
        amt = t.amount
        bin_ = amt if t.direction != Direction.sell else 0.0
        bout = amt if t.direction == Direction.sell else 0.0
        cash_in += bin_; cash_out += bout
        b = t.branch or "Unknown"
        d = branch_cash.setdefault(b, {"name": b, "cash_in": 0.0, "cash_out": 0.0})
        d["cash_in"] += bin_; d["cash_out"] += bout
        if t.foreign_currency:
            c = cur_pos.setdefault(t.foreign_currency, {"name": t.foreign_currency, "bought": 0.0, "sold": 0.0})
            if t.direction == Direction.buy: c["bought"] += amt
            elif t.direction == Direction.sell: c["sold"] += amt
    bl = []
    for d in branch_cash.values():
        d["net"] = round(d["cash_in"] - d["cash_out"], 2); d["cash_in"] = round(d["cash_in"], 2); d["cash_out"] = round(d["cash_out"], 2); bl.append(d)
    bl.sort(key=lambda x: -x["net"])
    cl = []
    for c in cur_pos.values():
        c["net_position"] = round(c["bought"] - c["sold"], 2); c["bought"] = round(c["bought"], 2); c["sold"] = round(c["sold"], 2); cl.append(c)
    cl.sort(key=lambda x: -abs(x["net_position"]))
    series = _monthly(txns, lambda t: (t.amount if t.direction != Direction.sell else -t.amount))
    months = [k for k, _ in series]
    fc = _forecast([v for _, v in series], 3)
    nm = _next_months(months[-1] if months else "2026-01", 3)
    return {"total_cash_in": round(cash_in, 2), "total_cash_out": round(cash_out, 2),
            "net_position": round(cash_in - cash_out, 2), "branch_cash": bl, "currency_positions": cl,
            "forecast": [{"month": nm[i], "net": fc[i]} for i in range(3)]}

def _build_operations(txns):
    wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    hourmap = {h: 0 for h in range(24)}; wdmap = {w: 0 for w in wd}
    for t in txns: hourmap[t.created_at.hour] += 1; wdmap[wd[t.created_at.weekday()]] += 1
    peak_hour = max(hourmap, key=hourmap.get); peak_day = max(wdmap, key=wdmap.get)
    emp = {}
    for t in txns:
        e = t.employee or "Unassigned"; d = emp.setdefault(e, {"name": e, "count": 0, "handle": [], "value": 0.0})
        d["count"] += 1; d["value"] += t.amount
        if t.handling_time: d["handle"].append(t.handling_time)
    emps = []
    for d in emp.values():
        d["avg_handle_sec"] = round(sum(d["handle"]) / len(d["handle"])) if d["handle"] else None
        d["value"] = round(d["value"], 2); d.pop("handle"); emps.append(d)
    emps.sort(key=lambda x: -x["count"])
    br = {}
    for t in txns:
        b = t.branch or "Unknown"; d = br.setdefault(b, {"name": b, "count": 0, "customers": set(), "emps": set()})
        d["count"] += 1; d["customers"].add(t.customer_id)
        if t.employee: d["emps"].add(t.employee)
    brs = []
    for d in br.values():
        d["footfall"] = len(d["customers"]); d["staff"] = len(d["emps"])
        d["txn_per_staff"] = round(d["count"] / d["staff"], 1) if d["staff"] else d["count"]
        d.pop("customers"); d.pop("emps"); brs.append(d)
    brs.sort(key=lambda x: -x["count"])
    ch = {}
    for t in txns:
        c = t.channel.value; d = ch.setdefault(c, {"name": c, "total": 0, "completed": 0, "failed": 0})
        d["total"] += 1
        if t.status == TxnStatus.completed: d["completed"] += 1
        elif t.status == TxnStatus.failed: d["failed"] += 1
    chs = [{"name": d["name"], "total": d["total"], "success_rate": round(d["completed"] / d["total"] * 100, 1) if d["total"] else 0, "failed": d["failed"]} for d in ch.values()]
    chs.sort(key=lambda x: -x["total"])
    aht = [t.handling_time for t in txns if t.handling_time]
    return {"peak_hour": f"{peak_hour:02d}:00", "peak_day": peak_day,
            "avg_handling_sec": round(sum(aht) / len(aht)) if aht else None,
            "by_hour": [{"hour": f"{h:02d}:00", "count": hourmap[h]} for h in range(24)],
            "by_weekday": [{"day": w, "count": wdmap[w]} for w in wd],
            "employees": emps[:15], "branches": brs, "channel_success": chs}

def _build_compliance(txns):
    THRESH = 3000.0
    cash_txns = [t for t in txns if (t.payment_method or "").lower() == "cash"]
    ctr = [t for t in cash_txns if t.amount >= THRESH]
    flagged = [t for t in txns if t.is_flagged]
    daymap = {}
    for t in txns: daymap.setdefault((t.customer_id, t.created_at.strftime("%Y-%m-%d")), []).append(t)
    structuring = []; velocity = 0
    for (cust, day), lst in daymap.items():
        if len(lst) >= 3: velocity += 1
        subs = [x for x in lst if x.amount < THRESH]
        if len(subs) >= 2 and sum(x.amount for x in subs) >= THRESH:
            structuring.append({"customer": cust, "date": day, "count": len(subs), "total": round(sum(x.amount for x in subs), 2)})
    structuring.sort(key=lambda x: -x["total"])
    kyc = {}
    for t in txns:
        k = t.kyc_status or "verified"; kyc[k] = kyc.get(k, 0) + 1
    pep = len(set(t.customer_id for t in txns if t.is_pep))
    sanc = len(set(t.customer_id for t in txns if t.is_sanctioned))
    def rgrp(keyfn):
        m = {}
        for t in txns:
            k = keyfn(t) or "Unknown"; d = m.setdefault(str(k), {"name": str(k), "count": 0, "flagged": 0, "score": 0})
            d["count"] += 1; d["score"] += (t.risk_score or 0)
            if t.is_flagged: d["flagged"] += 1
        out = [{"name": d["name"], "count": d["count"], "flagged": d["flagged"], "avg_risk": round(d["score"] / d["count"], 1) if d["count"] else 0} for d in m.values()]
        out.sort(key=lambda x: -x["avg_risk"]); return out
    return {"ctr_count": len(ctr), "ctr_value": round(sum(t.amount for t in ctr), 2), "threshold": THRESH,
            "str_candidates": len(flagged), "structuring_count": len(structuring), "structuring": structuring[:15],
            "velocity_alerts": velocity, "pep_customers": pep, "sanction_hits": sanc,
            "kyc_status": [{"name": k, "count": v} for k, v in kyc.items()],
            "pending_kyc": kyc.get("pending", 0), "expired_kyc": kyc.get("expired", 0),
            "risk_by_country": rgrp(lambda t: t.country)[:10], "risk_by_nationality": rgrp(lambda t: t.nationality)[:10]}

def _build_predictive(txns):
    rev_series = _monthly(txns, _rev); vol_series = _monthly(txns, lambda t: 1)
    rev_fc = _forecast([v for _, v in rev_series], 3); vol_fc = _forecast([v for _, v in vol_series], 3)
    months = [k for k, _ in rev_series]; nm = _next_months(months[-1] if months else "2026-01", 3)
    cur_month = {}
    for t in txns:
        if not t.foreign_currency: continue
        cur_month.setdefault(t.foreign_currency, {}).setdefault(t.created_at.strftime("%Y-%m"), 0)
        cur_month[t.foreign_currency][t.created_at.strftime("%Y-%m")] += t.amount
    cur_fc = []
    for cur, mm in cur_month.items():
        series = [mm[k] for k in sorted(mm)]
        cur_fc.append({"name": cur, "forecast_next": _forecast(series, 1)[0]})
    cur_fc.sort(key=lambda x: -x["forecast_next"]); cur_fc = cur_fc[:8]
    dormant = at_risk = 0
    if txns:
        maxd = max(t.created_at for t in txns); last_by = {}
        for t in txns: last_by[t.customer_id] = max(last_by.get(t.customer_id, t.created_at), t.created_at)
        dormant = sum(1 for d in last_by.values() if (maxd - d).days > 60)
        at_risk = sum(1 for d in last_by.values() if 30 < (maxd - d).days <= 60)
    return {"revenue_forecast": [{"month": nm[i], "value": rev_fc[i]} for i in range(3)],
            "volume_forecast": [{"month": nm[i], "count": round(vol_fc[i])} for i in range(3)],
            "revenue_history": [{"month": k, "value": round(v, 2)} for k, v in rev_series],
            "volume_history": [{"month": k, "count": v} for k, v in vol_series],
            "currency_demand": cur_fc, "dormant_customers": dormant, "at_risk_customers": at_risk}

def _build_geo(txns):
    city = _grp(txns, lambda t: t.city, 15)
    corr = {}
    for t in txns:
        if t.destination_country:
            k = t.destination_country; d = corr.setdefault(k, {"name": k, "count": 0, "value": 0.0})
            d["count"] += 1; d["value"] += t.amount
    corridors = sorted(corr.values(), key=lambda x: -x["value"])
    for d in corridors: d["value"] = round(d["value"], 2)
    hot = {}
    for t in txns:
        if t.is_flagged:
            k = t.city or t.branch or "Unknown"; d = hot.setdefault(k, {"name": k, "flagged": 0, "value": 0.0})
            d["flagged"] += 1; d["value"] += t.amount
    hotspots = sorted(hot.values(), key=lambda x: -x["flagged"])
    for d in hotspots: d["value"] = round(d["value"], 2)
    return {"cities": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in city],
            "corridors": corridors[:15], "fraud_hotspots": hotspots[:10]}

def _build_insights(txns):
    if not txns: return {"insights": []}
    ins = []
    br = _grp(txns, lambda t: t.branch)
    if br: ins.append({"type": "Performance", "text": f"{br[0]['key']} is the top branch by volume (OMR {br[0]['value']:,.0f} across {br[0]['count']} transactions).", "drill": {"branch": br[0]['key']}})
    if len(br) > 1: ins.append({"type": "Performance", "text": f"{br[-1]['key']} is the lowest-performing branch this period — consider a targeted review.", "drill": {"branch": br[-1]['key']}})
    pred = _build_predictive(txns)
    if pred["revenue_forecast"]:
        f = pred["revenue_forecast"][0]; ins.append({"type": "Predictive", "text": f"Projected revenue for {f['month']}: OMR {f['value']:,.0f} (trend-based forecast)."})
    if pred["dormant_customers"]: ins.append({"type": "Retention", "text": f"{pred['dormant_customers']} customers are dormant (no activity in 60+ days) — retention outreach recommended."})
    if pred["currency_demand"]:
        c = pred["currency_demand"][0]; ins.append({"type": "Prescriptive", "text": f"{c['name']} shows the highest projected demand — consider increasing {c['name']} inventory across branches.", "drill": {"currency": c['name']}})
    comp = _build_compliance(txns)
    if comp["ctr_count"]: ins.append({"type": "Compliance", "text": f"{comp['ctr_count']} cash transactions breach the CTR threshold (OMR {comp['threshold']:,.0f}) — ensure Currency Transaction Reports are filed.", "drill": {"payment_method": "cash", "min_amount": str(comp['threshold'])}})
    if comp["structuring_count"]:
        cust = comp["structuring"][0]["customer"] if comp["structuring"] else None
        item = {"type": "Risk", "text": f"{comp['structuring_count']} possible structuring pattern(s) detected — review for smurfing / STR filing."}
        if cust: item["drill"] = {"search": cust}
        ins.append(item)
    if comp["expired_kyc"]: ins.append({"type": "Compliance", "text": f"{comp['expired_kyc']} transactions involve customers with expired KYC — refresh due diligence.", "drill": {"kyc_status": "expired"}})
    if comp["sanction_hits"]: ins.append({"type": "Risk", "text": f"{comp['sanction_hits']} customer(s) match sanction/watchlist flags — escalate immediately.", "drill": {"is_sanctioned": "true"}})
    cash = _build_cash(txns)
    neg = [b for b in cash["branch_cash"] if b["net"] < 0]
    if neg: ins.append({"type": "Cash", "text": f"{len(neg)} branch(es) show negative net OMR cash flow — plan replenishment: " + ", ".join(b["name"] for b in neg[:3]) + ".", "drill": {"branch": neg[0]["name"]}})
    return {"insights": ins}


analytics_router = APIRouter(prefix="/analytics", tags=["analytics"])

@analytics_router.get("/dashboard")
async def dashboard(from_date: Optional[str] = Query(None), to_date: Optional[str] = Query(None),
                    db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Transaction)
    if from_date: q = q.where(Transaction.created_at >= datetime.fromisoformat(from_date))
    if to_date: q = q.where(Transaction.created_at <= datetime.fromisoformat(to_date))
    txns = (await db.execute(q)).scalars().all()
    if not txns:
        return {"total_transactions": 0, "total_value": 0, "online_count": 0, "offline_count": 0,
                "online_value": 0, "offline_value": 0, "online_pct": 0, "avg_ticket_online": 0,
                "avg_ticket_offline": 0, "channel_split": [], "monthly_trend": [], "segment_breakdown": [], "top_corridors": []}
    online = [t for t in txns if _is_online(t)]; offline = [t for t in txns if not _is_online(t)]
    tc = len(txns); tv = sum(t.amount for t in txns)
    oc, fc = len(online), len(offline)
    ov, fv = sum(t.amount for t in online), sum(t.amount for t in offline)
    cmap = {}
    for t in txns:
        d = cmap.setdefault(t.channel.value, {"count": 0, "value": 0.0}); d["count"] += 1; d["value"] += t.amount
    channel_split = [{"channel": k, "count": v["count"], "total_value": round(v["value"], 2),
                      "pct_count": round(v["count"]/tc*100, 1), "pct_value": round(v["value"]/tv*100, 1) if tv else 0}
                     for k, v in cmap.items()]
    mmap = {}
    for t in txns:
        key = t.created_at.strftime("%Y-%m")
        d = mmap.setdefault(key, {"online": 0.0, "offline": 0.0, "online_count": 0, "offline_count": 0})
        if _is_online(t): d["online"] += t.amount; d["online_count"] += 1
        else: d["offline"] += t.amount; d["offline_count"] += 1
    monthly = [{"month": k, "online": round(v["online"], 2), "offline": round(v["offline"], 2),
                "online_count": v["online_count"], "offline_count": v["offline_count"]} for k, v in sorted(mmap.items())]
    seg = [{"segment": g["key"], "count": g["count"], "total_value": g["value"]} for g in _grp(txns, lambda t: t.customer_segment)]
    corr = [{"corridor": g["key"], "count": g["count"], "total_value": g["value"]} for g in _grp(txns, lambda t: t.corridor or "Local", 8)]
    return {"total_transactions": tc, "total_value": round(tv, 2), "online_count": oc, "offline_count": fc,
            "online_value": round(ov, 2), "offline_value": round(fv, 2), "online_pct": round(oc/tc*100, 1) if tc else 0,
            "avg_ticket_online": round(ov/oc, 2) if oc else 0, "avg_ticket_offline": round(fv/fc, 2) if fc else 0,
            "channel_split": channel_split, "monthly_trend": monthly, "segment_breakdown": seg, "top_corridors": corr}


@analytics_router.get("/advanced")
async def advanced(from_date: Optional[str] = Query(None), to_date: Optional[str] = Query(None),
                   db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Transaction)
    if from_date: q = q.where(Transaction.created_at >= datetime.fromisoformat(from_date))
    if to_date: q = q.where(Transaction.created_at <= datetime.fromisoformat(to_date))
    txns = (await db.execute(q)).scalars().all()
    empty = {"executive": {}, "transactions": {}, "customers": {}, "fx": {}, "profitability": {},
             "branches": [], "employees": [], "remittance": {}, "risk": {},
             "cash": {}, "operations": {}, "compliance": {}, "predictive": {}, "geo": {}, "insights": {}}
    if not txns: return empty

    tc = len(txns); tv = sum(t.amount for t in txns)
    revenue = sum(_rev(t) for t in txns)
    commission = sum(t.commission or 0 for t in txns)
    fx_margin = sum(t.fx_margin or 0 for t in txns)
    service_fee = sum(t.service_fee or 0 for t in txns)
    vat = sum(t.vat or 0 for t in txns)
    cost = sum(t.cost or 0 for t in txns)
    gross_profit = revenue - cost
    net_profit = gross_profit - revenue * 0.10  # 10% overhead allocation
    completed = [t for t in txns if t.status == TxnStatus.completed]

    executive = {
        "total_transactions": tc, "total_value": round(tv, 2), "revenue": round(revenue, 2),
        "commission": round(commission, 2), "fx_margin": round(fx_margin, 2), "service_fee": round(service_fee, 2),
        "vat": round(vat, 2), "operating_cost": round(cost, 2), "gross_profit": round(gross_profit, 2),
        "net_profit": round(net_profit, 2),
        "gross_margin_pct": round(gross_profit / revenue * 100, 1) if revenue else 0,
        "take_rate_pct": round(revenue / tv * 100, 2) if tv else 0,
        "cost_per_txn": round(cost / tc, 2) if tc else 0,
        "revenue_per_txn": round(revenue / tc, 2) if tc else 0,
        "revenue_by_branch": [{"name": g["key"], "revenue": g["revenue"], "value": g["value"], "count": g["count"]} for g in _grp(txns, lambda t: t.branch, 10)],
        "revenue_by_country": [{"name": g["key"], "revenue": g["revenue"], "value": g["value"], "count": g["count"]} for g in _grp(txns, lambda t: t.country, 10)],
        "revenue_by_currency": [{"name": g["key"], "revenue": g["revenue"], "value": g["value"], "count": g["count"]} for g in _grp(txns, lambda t: t.foreign_currency, 10)],
        "revenue_by_channel": [{"name": g["key"], "revenue": g["revenue"], "value": g["value"], "count": g["count"]} for g in _grp(txns, lambda t: t.channel.value)],
    }

    # transactions module
    wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    by_month = {}
    for t in txns:
        by_month.setdefault(t.created_at.strftime("%Y-%m"), 0)
        by_month[t.created_at.strftime("%Y-%m")] += 1
    weekday = {w: 0 for w in wd}
    for t in txns: weekday[wd[t.created_at.weekday()]] += 1
    hourmap = {h: 0 for h in range(24)}
    for t in txns: hourmap[t.created_at.hour] += 1
    transactions = {
        "by_channel": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.channel.value)],
        "by_type": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.txn_type.value)],
        "by_month": [{"month": k, "count": v} for k, v in sorted(by_month.items())],
        "by_weekday": [{"day": w, "count": weekday[w]} for w in wd],
        "by_hour": [{"hour": f"{h:02d}:00", "count": hourmap[h]} for h in range(24)],
        "by_country": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.country, 10)],
        "by_city": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.city, 10)],
        "by_currency_pair": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.currency_pair, 12)],
        "buy_volume": round(sum(t.amount for t in txns if t.direction == Direction.buy), 2),
        "sell_volume": round(sum(t.amount for t in txns if t.direction == Direction.sell), 2),
    }

    # customers
    custmap = {}
    for t in txns:
        d = custmap.setdefault(t.customer_id, {"id": t.customer_id, "count": 0, "value": 0.0, "revenue": 0.0, "type": (t.customer_type.value if t.customer_type else "retail")})
        d["count"] += 1; d["value"] += t.amount; d["revenue"] += _rev(t)
    top_customers = sorted(custmap.values(), key=lambda x: -x["value"])[:10]
    for d in top_customers: d["value"] = round(d["value"], 2); d["revenue"] = round(d["revenue"], 2)
    customers = {
        "total_customers": len(custmap),
        "avg_ticket": round(tv / tc, 2) if tc else 0,
        "avg_clv": round(tv / len(custmap), 2) if custmap else 0,
        "by_type": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: (t.customer_type.value if t.customer_type else "retail"))],
        "by_nationality": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.nationality, 10)],
        "by_age": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.age_group)],
        "by_gender": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(txns, lambda t: t.gender)],
        "top_customers": top_customers,
    }

    # fx
    buys = [t for t in txns if t.direction == Direction.buy]
    sells = [t for t in txns if t.direction == Direction.sell]
    fx = {
        "most_bought": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(buys, lambda t: t.foreign_currency, 8)],
        "most_sold": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(sells, lambda t: t.foreign_currency, 8)],
        "by_pair": [{"name": g["key"], "count": g["count"], "value": g["value"], "revenue": g["revenue"]} for g in _grp([t for t in txns if t.currency_pair], lambda t: t.currency_pair, 12)],
        "currency_profit": [{"name": g["key"], "revenue": g["revenue"], "value": g["value"]} for g in sorted(_grp(txns, lambda t: t.foreign_currency), key=lambda x: -x["revenue"])[:10]],
    }

    # profitability
    def prof_group(keyfn, topn=None):
        m = {}
        for t in txns:
            k = keyfn(t)
            if not k: k = "Unknown"
            d = m.setdefault(str(k), {"name": str(k), "revenue": 0.0, "cost": 0.0, "value": 0.0, "count": 0})
            d["revenue"] += _rev(t); d["cost"] += (t.cost or 0); d["value"] += t.amount; d["count"] += 1
        out = []
        for d in m.values():
            d["profit"] = round(d["revenue"] - d["cost"], 2)
            d["margin_pct"] = round((d["revenue"] - d["cost"]) / d["revenue"] * 100, 1) if d["revenue"] else 0
            d["revenue"] = round(d["revenue"], 2); d["cost"] = round(d["cost"], 2); d["value"] = round(d["value"], 2)
            out.append(d)
        out = sorted(out, key=lambda x: -x["profit"])
        return out[:topn] if topn else out
    profitability = {
        "by_branch": prof_group(lambda t: t.branch, 10),
        "by_currency": prof_group(lambda t: t.foreign_currency, 10),
        "by_country": prof_group(lambda t: t.country, 10),
        "by_customer_type": prof_group(lambda t: (t.customer_type.value if t.customer_type else "retail")),
    }

    branches = prof_group(lambda t: t.branch)
    for b in branches:
        b["avg_ticket"] = round(b["value"] / b["count"], 2) if b["count"] else 0

    empmap = {}
    for t in txns:
        e = t.employee or "Unassigned"
        d = empmap.setdefault(e, {"name": e, "count": 0, "value": 0.0, "revenue": 0.0})
        d["count"] += 1; d["value"] += t.amount; d["revenue"] += _rev(t)
    employees = sorted(empmap.values(), key=lambda x: -x["revenue"])
    for d in employees: d["value"] = round(d["value"], 2); d["revenue"] = round(d["revenue"], 2)

    # remittance
    rem = [t for t in txns if t.txn_type == TransactionType.remittance]
    rem_completed = [t for t in rem if t.status == TxnStatus.completed]
    remittance = {
        "total": len(rem),
        "avg_transfer": round(sum(t.amount for t in rem) / len(rem), 2) if rem else 0,
        "success_rate": round(len(rem_completed) / len(rem) * 100, 1) if rem else 0,
        "failed": len([t for t in rem if t.status == TxnStatus.failed]),
        "pending": len([t for t in rem if t.status == TxnStatus.pending]),
        "corridors": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(rem, lambda t: t.corridor, 12)],
        "by_destination": [{"name": g["key"], "count": g["count"], "value": g["value"]} for g in _grp(rem, lambda t: t.destination_country, 12)],
    }

    # risk
    THRESHOLD = 3000.0
    high_value = [t for t in txns if t.amount >= THRESHOLD]
    round_fig = [t for t in txns if t.amount >= 1000 and t.amount % 1000 == 0]
    # duplicates & velocity by customer+day
    daymap = {}
    for t in txns:
        daymap.setdefault((t.customer_id, t.created_at.strftime("%Y-%m-%d")), []).append(t)
    duplicates = sum(1 for k, v in daymap.items() if len(v) >= 2 and len(set(round(x.amount, 2) for x in v)) < len(v))
    rapid_repeat = sum(1 for k, v in daymap.items() if len(v) >= 3)
    flagged = [t for t in txns if t.is_flagged]
    def band(s):
        return "High" if s >= 70 else ("Medium" if s >= 40 else "Low")
    bandmap = {"Low": 0, "Medium": 0, "High": 0}
    for t in txns: bandmap[band(t.risk_score or 0)] += 1
    risk = {
        "flagged_count": len(flagged),
        "flagged_value": round(sum(t.amount for t in flagged), 2),
        "high_value_count": len(high_value),
        "round_figure_count": len(round_fig),
        "duplicate_groups": duplicates,
        "rapid_repeat_customers": rapid_repeat,
        "threshold": THRESHOLD,
        "risk_bands": [{"name": k, "count": bandmap[k]} for k in ("Low", "Medium", "High")],
        "top_flagged": [{"ref": t.txn_ref, "customer": t.customer_id, "amount": round(t.amount, 2),
                         "channel": t.channel.value, "score": t.risk_score, "branch": t.branch}
                        for t in sorted(flagged, key=lambda x: -x.risk_score)[:15]],
    }

    return {"executive": executive, "transactions": transactions, "customers": customers, "fx": fx,
            "profitability": profitability, "branches": branches, "employees": employees,
            "remittance": remittance, "risk": risk,
            "cash": _build_cash(txns), "operations": _build_operations(txns),
            "compliance": _build_compliance(txns), "predictive": _build_predictive(txns),
            "geo": _build_geo(txns), "insights": _build_insights(txns)}

print("part1 ok")


# ---------------- transactions ----------------
txn_router = APIRouter(prefix="/transactions", tags=["transactions"])

def _apply_filters(q, channel, txn_type, branch, country, currency, customer_type, status_f, flagged, direction, min_amount, max_amount, from_date, to_date, search, employee=None, city=None, corridor=None, nationality=None, segment=None, currency_pair=None, age_group=None, gender=None, destination_country=None, payment_method=None, kyc_status=None, is_pep=None, is_sanctioned=None):
    if channel: q = q.where(Transaction.channel == channel)
    if txn_type: q = q.where(Transaction.txn_type == txn_type)
    if branch: q = q.where(Transaction.branch == branch)
    if country: q = q.where(Transaction.country == country)
    if currency: q = q.where(Transaction.foreign_currency == currency)
    if customer_type: q = q.where(Transaction.customer_type == customer_type)
    if status_f: q = q.where(Transaction.status == status_f)
    if direction: q = q.where(Transaction.direction == direction)
    if flagged is not None: q = q.where(Transaction.is_flagged == flagged)
    if min_amount is not None: q = q.where(Transaction.amount >= min_amount)
    if max_amount is not None: q = q.where(Transaction.amount <= max_amount)
    if from_date: q = q.where(Transaction.created_at >= datetime.fromisoformat(from_date))
    if to_date: q = q.where(Transaction.created_at <= datetime.fromisoformat(to_date))
    if employee: q = q.where(Transaction.employee == employee)
    if city: q = q.where(Transaction.city == city)
    if corridor: q = q.where(Transaction.corridor == corridor)
    if nationality: q = q.where(Transaction.nationality == nationality)
    if segment: q = q.where(Transaction.customer_segment == segment)
    if currency_pair: q = q.where(Transaction.currency_pair == currency_pair)
    if age_group: q = q.where(Transaction.age_group == age_group)
    if gender: q = q.where(Transaction.gender == gender)
    if destination_country: q = q.where(Transaction.destination_country == destination_country)
    if payment_method: q = q.where(func.lower(Transaction.payment_method) == payment_method.lower())
    if kyc_status: q = q.where(Transaction.kyc_status == kyc_status)
    if is_pep is not None: q = q.where(Transaction.is_pep == is_pep)
    if is_sanctioned is not None: q = q.where(Transaction.is_sanctioned == is_sanctioned)
    if search: q = q.where((Transaction.customer_id.ilike(f"%{search}%")) | (Transaction.txn_ref.ilike(f"%{search}%")))
    return q

def _txn_dict(t: Transaction):
    return {"id": t.id, "txn_ref": t.txn_ref, "created_at": t.created_at.isoformat() if t.created_at else None,
            "customer_id": t.customer_id, "customer_segment": t.customer_segment,
            "customer_type": t.customer_type.value if t.customer_type else None,
            "nationality": t.nationality, "gender": t.gender, "age_group": t.age_group,
            "channel": t.channel.value, "txn_type": t.txn_type.value,
            "direction": t.direction.value if t.direction else None, "payment_method": t.payment_method,
            "amount": round(t.amount, 2), "currency": t.currency, "foreign_currency": t.foreign_currency,
            "currency_pair": t.currency_pair, "fx_rate": t.fx_rate,
            "commission": t.commission, "fx_margin": t.fx_margin, "service_fee": t.service_fee,
            "vat": t.vat, "cost": t.cost, "branch": t.branch, "city": t.city, "country": t.country,
            "destination_country": t.destination_country, "corridor": t.corridor, "employee": t.employee,
            "status": t.status.value if t.status else None, "risk_score": t.risk_score, "is_flagged": t.is_flagged,
            "kyc_status": t.kyc_status, "is_pep": t.is_pep, "is_sanctioned": t.is_sanctioned,
            "nps": t.nps, "satisfaction": t.satisfaction, "handling_time": t.handling_time}

@txn_router.get("/")
async def list_transactions(page: int = Query(1, ge=1), limit: int = Query(20, le=200),
        channel: Optional[str] = None, txn_type: Optional[str] = None, branch: Optional[str] = None,
        country: Optional[str] = None, currency: Optional[str] = None, customer_type: Optional[str] = None,
        status: Optional[str] = None, flagged: Optional[bool] = None, direction: Optional[str] = None,
        min_amount: Optional[float] = None, max_amount: Optional[float] = None,
        from_date: Optional[str] = None, to_date: Optional[str] = None, search: Optional[str] = None,
        employee: Optional[str] = None, city: Optional[str] = None, corridor: Optional[str] = None,
        nationality: Optional[str] = None, segment: Optional[str] = None, currency_pair: Optional[str] = None,
        age_group: Optional[str] = None, gender: Optional[str] = None, destination_country: Optional[str] = None,
        payment_method: Optional[str] = None, kyc_status: Optional[str] = None,
        is_pep: Optional[bool] = None, is_sanctioned: Optional[bool] = None,
        db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Transaction).order_by(Transaction.created_at.desc())
    q = _apply_filters(q, channel, txn_type, branch, country, currency, customer_type, status, flagged, direction, min_amount, max_amount, from_date, to_date, search, employee, city, corridor, nationality, segment, currency_pair, age_group, gender, destination_country, payment_method, kyc_status, is_pep, is_sanctioned)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    q = q.offset((page - 1) * limit).limit(limit)
    items = (await db.execute(q)).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_txn_dict(t) for t in items]}

@txn_router.get("/export")
async def export_transactions(channel: Optional[str] = None, txn_type: Optional[str] = None, branch: Optional[str] = None,
        country: Optional[str] = None, currency: Optional[str] = None, customer_type: Optional[str] = None,
        status: Optional[str] = None, flagged: Optional[bool] = None, direction: Optional[str] = None,
        min_amount: Optional[float] = None, max_amount: Optional[float] = None,
        from_date: Optional[str] = None, to_date: Optional[str] = None, search: Optional[str] = None,
        employee: Optional[str] = None, city: Optional[str] = None, corridor: Optional[str] = None,
        nationality: Optional[str] = None, segment: Optional[str] = None, currency_pair: Optional[str] = None,
        age_group: Optional[str] = None, gender: Optional[str] = None, destination_country: Optional[str] = None,
        payment_method: Optional[str] = None, kyc_status: Optional[str] = None,
        is_pep: Optional[bool] = None, is_sanctioned: Optional[bool] = None,
        db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Transaction).order_by(Transaction.created_at.desc())
    q = _apply_filters(q, channel, txn_type, branch, country, currency, customer_type, status, flagged, direction, min_amount, max_amount, from_date, to_date, search, employee, city, corridor, nationality, segment, currency_pair, age_group, gender, destination_country, payment_method, kyc_status, is_pep, is_sanctioned)
    rows = (await db.execute(q)).scalars().all()
    cols = ["txn_ref", "created_at", "customer_id", "customer_type", "nationality", "gender", "age_group",
            "channel", "txn_type", "direction", "payment_method", "amount", "currency", "foreign_currency",
            "currency_pair", "fx_rate", "commission", "fx_margin", "service_fee", "vat", "cost",
            "branch", "city", "country", "destination_country", "corridor", "employee", "status",
            "risk_score", "is_flagged", "kyc_status", "is_pep", "is_sanctioned", "nps", "satisfaction", "handling_time"]
    def gen():
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(cols); yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for t in rows:
            d = _txn_dict(t); w.writerow([d.get(c) for c in cols]); yield buf.getvalue(); buf.seek(0); buf.truncate(0)
    return StreamingResponse(gen(), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=moneyex_transactions.csv"})

@txn_router.delete("/{txn_id}", dependencies=[Depends(require_analyst)])
async def delete_transaction(txn_id: int, db: AsyncSession = Depends(get_db)):
    t = (await db.execute(select(Transaction).where(Transaction.id == txn_id))).scalar_one_or_none()
    if not t: raise HTTPException(status_code=404, detail="Transaction not found")
    await db.delete(t); await db.commit()
    return {"ok": True}

# ---- import ----
_CH = {"online": "online", "web": "web", "website": "web", "portal": "web", "app": "mobile", "mobile": "mobile",
       "api": "api", "branch": "branch", "offline": "branch", "counter": "branch", "store": "branch",
       "agent": "agent", "partner": "agent"}
_TY = {"remittance": "remittance", "remit": "remittance", "send": "remittance", "transfer": "transfer", "wire": "transfer",
       "exchange": "exchange", "fx": "exchange", "forex": "exchange", "currency": "exchange"}
_DIR = {"buy": "buy", "purchase": "buy", "bought": "buy", "sell": "sell", "sold": "sell", "sale": "sell"}
_CT = {"retail": "retail", "individual": "retail", "personal": "retail", "corporate": "corporate", "business": "corporate",
       "company": "corporate", "vip": "vip", "premium": "vip"}
_ST = {"completed": "completed", "success": "completed", "successful": "completed", "done": "completed", "settled": "completed",
       "pending": "pending", "processing": "pending", "failed": "failed", "declined": "failed", "rejected": "failed"}

def _norm(s): return str(s if s is not None else "").strip().lower().replace(" ", "_")
def _pick(row, *keys):
    for k in keys:
        v = row.get(k)
        if v is not None and str(v).strip() != "": return v
    return None
def _num(v, default=0.0):
    if v is None or str(v).strip() == "": return default
    try: return float(str(v).replace(",", "").replace("OMR", "").strip())
    except Exception: return default
def _parse_date(raw):
    if raw is None: return datetime.utcnow()
    if isinstance(raw, datetime): return raw
    s = str(raw).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y", "%d-%b-%Y", "%d %b %Y"):
        try: return datetime.strptime(s[:19], fmt)
        except ValueError: pass
    try: return datetime.fromisoformat(s)
    except ValueError: return datetime.utcnow()

def _parse_csv(content):
    text = content.decode("utf-8-sig", errors="replace")
    return [{_norm(k): v for k, v in row.items() if k is not None} for row in csv.DictReader(io.StringIO(text))]
def _parse_xlsx(content):
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    ws = wb.active; rows = list(ws.iter_rows(values_only=True))
    if not rows: return []
    headers = [_norm(h) for h in rows[0]]
    return [{headers[i]: (r[i] if i < len(r) else None) for i in range(len(headers))} for r in rows[1:]]

def _risk(amount, channel, direction, ct):
    score = min(60, int(amount / 80))
    reasons = 0
    if amount >= 3000: score += 25; reasons += 1
    if amount >= 1000 and amount % 1000 == 0: score += 10; reasons += 1
    if channel in ("agent",): score += 5
    score = min(100, score)
    return score, score >= 65

def _row_to_txn(row, seen):
    amt = _num(_pick(row, "amount", "value", "txn_amount", "transaction_amount", "amt", "omr_amount"))
    if amt <= 0 and str(_pick(row, "amount", "value") or "").strip() == "": raise ValueError("missing 'amount'")
    ch = _CH.get(_norm(_pick(row, "channel", "source") or "branch"), "branch")
    ty = _TY.get(_norm(_pick(row, "txn_type", "type", "transaction_type") or "exchange"), "exchange")
    dr = _DIR.get(_norm(_pick(row, "direction", "buy_sell", "trade") or ""), None)
    if dr is None: dr = "buy" if ty == "exchange" else "na"
    ct = _CT.get(_norm(_pick(row, "customer_type", "cust_type") or "retail"), "retail")
    st = _ST.get(_norm(_pick(row, "status", "txn_status") or "completed"), "completed")
    comm = _num(_pick(row, "commission"))
    fxm = _num(_pick(row, "fx_margin", "margin", "spread"))
    svc = _num(_pick(row, "service_fee", "fee", "transfer_fee"))
    vat = _num(_pick(row, "vat", "tax"))
    cost = _num(_pick(row, "cost", "operating_cost"))
    if comm == 0 and fxm == 0 and svc == 0:  # estimate revenue when absent
        fxm = round(amt * 0.015, 2); comm = round(amt * 0.005, 2)
    if cost == 0: cost = round(amt * 0.004, 2)
    if vat == 0: vat = round((comm + fxm + svc) * 0.05, 2)
    fcur = _pick(row, "foreign_currency", "currency_code", "fx_currency", "target_currency")
    pair = _pick(row, "currency_pair", "pair")
    if not pair and fcur: pair = f"OMR/{str(fcur).upper()}"
    ref = str(_pick(row, "txn_ref", "reference", "ref") or f"TXN{str(uuid.uuid4())[:8].upper()}")
    base = ref; n = 1
    while ref in seen: ref = f"{base}-{n}"; n += 1
    seen.add(ref)
    score, flagged = _risk(amt, ch, dr, ct)
    def sv(v): return str(v) if v is not None and str(v).strip() != "" else None
    return Transaction(
        txn_ref=ref, created_at=_parse_date(_pick(row, "date", "created_at", "txn_date", "transaction_date")),
        customer_id=str(_pick(row, "customer_id", "customer", "cust_id") or f"CUST{random.randint(1000,9999)}"),
        customer_segment=sv(_pick(row, "customer_segment", "segment")),
        customer_type=CustomerType(ct), nationality=sv(_pick(row, "nationality", "country_of_origin")),
        gender=sv(_pick(row, "gender", "sex")), age_group=sv(_pick(row, "age_group", "age_band", "age")),
        channel=Channel(ch), txn_type=TransactionType(ty), direction=Direction(dr),
        payment_method=sv(_pick(row, "payment_method", "method", "pay_mode")),
        amount=round(amt, 2), currency=str(_pick(row, "currency", "base_currency") or "OMR"),
        foreign_currency=(str(fcur).upper() if fcur else None), currency_pair=(str(pair).upper() if pair else None),
        fx_rate=_num(_pick(row, "fx_rate", "rate", "exchange_rate"), None) if _pick(row, "fx_rate", "rate", "exchange_rate") else None,
        commission=comm, fx_margin=fxm, service_fee=svc, vat=vat, cost=cost,
        branch=sv(_pick(row, "branch", "branch_name", "location")), city=sv(_pick(row, "city", "governorate")),
        country=sv(_pick(row, "country") or "Oman"),
        destination_country=sv(_pick(row, "destination_country", "beneficiary_country", "destination")),
        corridor=sv(_pick(row, "corridor", "route")), employee=sv(_pick(row, "employee", "cashier", "staff", "teller")),
        status=TxnStatus(st), risk_score=score, is_flagged=flagged,
        kyc_status=(str(_pick(row, "kyc_status", "kyc") or "verified").strip().lower() if _pick(row, "kyc_status", "kyc") else "verified"),
        is_pep=str(_pick(row, "is_pep", "pep") or "").strip().lower() in ("1", "true", "yes", "y"),
        is_sanctioned=str(_pick(row, "is_sanctioned", "sanctioned", "sanction") or "").strip().lower() in ("1", "true", "yes", "y"),
        nps=int(_num(_pick(row, "nps"))) if _pick(row, "nps") else None,
        satisfaction=int(_num(_pick(row, "satisfaction", "csat"))) if _pick(row, "satisfaction", "csat") else None,
        handling_time=int(_num(_pick(row, "handling_time", "service_time"))) if _pick(row, "handling_time", "service_time") else None)

@txn_router.post("/import", dependencies=[Depends(require_analyst)])
async def import_transactions(file: UploadFile = File(...), mode: str = Form("replace"), db: AsyncSession = Depends(get_db)):
    content = await file.read()
    if not content: raise HTTPException(status_code=400, detail="Uploaded file is empty")
    fname = (file.filename or "").lower()
    try:
        rows = _parse_xlsx(content) if fname.endswith((".xlsx", ".xlsm")) else _parse_csv(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")
    if not rows: raise HTTPException(status_code=400, detail="No data rows found in the file")
    if mode == "replace":
        await db.execute(delete(Transaction)); await db.commit()
    imported = 0; errors = []; seen = set(); batch = []
    for i, row in enumerate(rows, start=2):
        if not any(v is not None and str(v).strip() != "" for v in row.values()): continue
        try:
            batch.append(_row_to_txn(row, seen)); imported += 1
        except Exception as e:
            if len(errors) < 25: errors.append(f"Row {i}: {e}")
    if batch: db.add_all(batch); await db.commit()
    total = (await db.execute(select(func.count()).select_from(Transaction))).scalar()
    return {"imported": imported, "skipped": len(rows) - imported, "errors": errors, "mode": mode, "total_in_db": total}


# ---------------- admin ----------------
admin_router = APIRouter(prefix="/admin", tags=["admin"])
@admin_router.get("/users", response_model=list[UserOut])
async def list_users(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    return [UserOut.model_validate(u) for u in (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()]
@admin_router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: int, data: UserUpdate, db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u: raise HTTPException(status_code=404, detail="User not found")
    for f, v in data.model_dump(exclude_none=True).items(): setattr(u, f, v)
    await db.commit(); await db.refresh(u)
    return UserOut.model_validate(u)
@admin_router.delete("/users/{user_id}")
async def delete_user(user_id: int, db: AsyncSession = Depends(get_db), admin: User = Depends(require_admin)):
    if user_id == admin.id: raise HTTPException(status_code=400, detail="Cannot delete yourself")
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u: raise HTTPException(status_code=404, detail="User not found")
    await db.delete(u); await db.commit()
    return {"ok": True}
@admin_router.get("/stats")
async def admin_stats(db: AsyncSession = Depends(get_db), _: User = Depends(require_admin)):
    tu = (await db.execute(select(func.count()).select_from(User))).scalar()
    au = (await db.execute(select(func.count()).select_from(User).where(User.is_active == True))).scalar()
    tt = (await db.execute(select(func.count()).select_from(Transaction))).scalar()
    tv = (await db.execute(select(func.sum(Transaction.amount)).select_from(Transaction))).scalar() or 0
    return {"total_users": tu, "active_users": au, "total_transactions": tt, "total_value": round(tv, 2)}


app = FastAPI(title=settings.PROJECT_NAME, version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(analytics_router, prefix=settings.API_V1_STR)
app.include_router(txn_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def on_startup():
    await init_db(); await seed_demo_data()

async def seed_demo_data():
    async with AsyncSessionLocal() as db:
        if not (await db.execute(select(User).where(User.email == "admin@moneyex.com"))).scalar_one_or_none():
            db.add_all([
                User(full_name="Admin User", email="admin@moneyex.com", hashed_password=get_password_hash("Admin@1234"), role=UserRole.admin),
                User(full_name="Adarsh Vasudevan", email="adarsh@ozngroup.com", hashed_password=get_password_hash("Analyst@1234"), role=UserRole.analyst),
                User(full_name="Demo Viewer", email="viewer@moneyex.com", hashed_password=get_password_hash("Viewer@1234"), role=UserRole.viewer)])
            await db.commit()
        if (await db.execute(select(Transaction).limit(1))).scalar_one_or_none(): return
        branches = [("Ruwi", "Muscat"), ("Salalah", "Dhofar"), ("Sohar", "Batinah"), ("Nizwa", "Dakhiliyah"), ("Seeb", "Muscat")]
        currencies = [("INR", "India"), ("PKR", "Pakistan"), ("PHP", "Philippines"), ("EGP", "Egypt"),
                      ("BDT", "Bangladesh"), ("LKR", "Sri Lanka"), ("NPR", "Nepal"), ("USD", "United States"), ("GBP", "United Kingdom")]
        segs = ["Premium", "Standard", "New", "Corporate", "Youth"]
        nats = ["Indian", "Pakistani", "Filipino", "Egyptian", "Bangladeshi", "Omani", "British"]
        emps = ["E. Rashid", "F. Kumar", "S. Ali", "M. Santos", "A. Nair", "H. Said", "R. Perera"]
        methods = ["cash", "card", "bank", "wallet"]
        ages = ["18-25", "26-35", "36-45", "46-60", "60+"]
        genders = ["Male", "Female"]
        ctypes = [CustomerType.retail, CustomerType.retail, CustomerType.retail, CustomerType.corporate, CustomerType.vip]
        chans = [Channel.online, Channel.mobile, Channel.web, Channel.api, Channel.branch, Channel.agent]
        chan_w = [16, 14, 8, 4, 42, 16]
        base = datetime.utcnow() - timedelta(days=365)
        rows = []
        for i in range(600):
            br, city = random.choice(branches)
            cur, dest = random.choice(currencies)
            ty = random.choices([TransactionType.remittance, TransactionType.exchange, TransactionType.transfer], weights=[45, 40, 15])[0]
            dr = random.choice([Direction.buy, Direction.sell]) if ty == TransactionType.exchange else Direction.na
            ch = random.choices(chans, weights=chan_w)[0]
            amt = round(random.uniform(30, 500) if random.random() < 0.7 else random.uniform(500, 6000), 2)
            comm = round(amt * random.uniform(0.002, 0.008), 2)
            fxm = round(amt * random.uniform(0.008, 0.02), 2)
            svc = round(random.choice([0, 0, 1, 2, 3]), 2)
            rev = comm + fxm + svc
            cost = round(amt * random.uniform(0.002, 0.006), 2)
            vat = round(rev * 0.05, 2)
            st = random.choices([TxnStatus.completed, TxnStatus.pending, TxnStatus.failed], weights=[92, 5, 3])[0]
            score = min(100, int(amt / 80) + (25 if amt >= 3000 else 0) + (10 if amt >= 1000 and amt % 1000 == 0 else 0) + (5 if ch == Channel.agent else 0))
            created = base + timedelta(days=random.randint(0, 365), hours=random.randint(6, 21), minutes=random.randint(0, 59))
            rows.append(Transaction(
                txn_ref=f"TXN{str(uuid.uuid4())[:8].upper()}", created_at=created,
                customer_id=f"CUST{random.randint(1000, 1200)}", customer_segment=random.choice(segs),
                customer_type=random.choice(ctypes), nationality=random.choice(nats),
                gender=random.choice(genders), age_group=random.choice(ages),
                channel=ch, txn_type=ty, direction=dr, payment_method=random.choice(methods),
                amount=amt, currency="OMR", foreign_currency=cur, currency_pair=f"OMR/{cur}",
                fx_rate=round(random.uniform(0.4, 500), 3), commission=comm, fx_margin=fxm, service_fee=svc, vat=vat, cost=cost,
                branch=br, city=city, country="Oman", destination_country=dest,
                corridor=f"OMR/{cur}", employee=random.choice(emps), status=st,
                risk_score=score, is_flagged=score >= 65,
                kyc_status=random.choices(["verified", "pending", "expired"], weights=[88, 8, 4])[0],
                is_pep=random.random() < 0.02, is_sanctioned=random.random() < 0.008,
                nps=random.randint(0, 10), satisfaction=random.randint(1, 5),
                handling_time=random.randint(60, 900)))
        db.add_all(rows); await db.commit()

@app.get("/health")
def health():
    return {"status": "ok", "service": settings.PROJECT_NAME, "version": "2.0.0"}
