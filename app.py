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


# ============================ CRM + HELPDESK ============================
class ContactStatus(str, enum.Enum):
    lead = "lead"; prospect = "prospect"; customer = "customer"; vip = "vip"; churned = "churned"
class ContactType(str, enum.Enum):
    individual = "individual"; corporate = "corporate"
class DealStage(str, enum.Enum):
    new = "new"; contacted = "contacted"; qualified = "qualified"; proposal = "proposal"; won = "won"; lost = "lost"
class TicketPriority(str, enum.Enum):
    low = "low"; medium = "medium"; high = "high"; urgent = "urgent"
class TicketStatus(str, enum.Enum):
    open = "open"; pending = "pending"; on_hold = "on_hold"; resolved = "resolved"; closed = "closed"

class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), index=True)
    email = Column(String(200), index=True)
    phone = Column(String(40), nullable=True)
    company = Column(String(120), nullable=True)
    contact_type = Column(Enum(ContactType), default=ContactType.individual, index=True)
    status = Column(Enum(ContactStatus), default=ContactStatus.lead, index=True)
    source = Column(String(40), nullable=True, index=True)
    owner = Column(String(80), nullable=True, index=True)
    nationality = Column(String(64), nullable=True)
    tags = Column(String(200), nullable=True)
    lifetime_value = Column(Float, default=0.0)
    last_contact = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now(), index=True)

class Deal(Base):
    __tablename__ = "deals"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(160))
    contact_name = Column(String(120), index=True)
    stage = Column(Enum(DealStage), default=DealStage.new, index=True)
    value = Column(Float, default=0.0)
    probability = Column(Integer, default=10)
    owner = Column(String(80), nullable=True, index=True)
    source = Column(String(40), nullable=True)
    expected_close = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now(), index=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    ref = Column(String(20), unique=True, index=True)
    subject = Column(String(200))
    description = Column(String(2000), nullable=True)
    requester = Column(String(120), index=True)
    requester_email = Column(String(200), nullable=True)
    assignee = Column(String(80), nullable=True, index=True)
    priority = Column(Enum(TicketPriority), default=TicketPriority.medium, index=True)
    status = Column(Enum(TicketStatus), default=TicketStatus.open, index=True)
    category = Column(String(40), index=True)
    channel = Column(String(30), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now(), index=True)
    first_response_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    sla_due = Column(DateTime(timezone=True), nullable=True)
    first_response_mins = Column(Integer, nullable=True)
    resolution_mins = Column(Integer, nullable=True)
    sla_breached = Column(Boolean, default=False, index=True)
    csat = Column(Integer, nullable=True)


class ContactIn(BaseModel):
    name: str; email: Optional[str] = None; phone: Optional[str] = None; company: Optional[str] = None
    contact_type: ContactType = ContactType.individual; status: ContactStatus = ContactStatus.lead
    source: Optional[str] = None; owner: Optional[str] = None; nationality: Optional[str] = None
    tags: Optional[str] = None; lifetime_value: float = 0.0
class ContactPatch(BaseModel):
    name: Optional[str] = None; email: Optional[str] = None; phone: Optional[str] = None; company: Optional[str] = None
    contact_type: Optional[ContactType] = None; status: Optional[ContactStatus] = None
    source: Optional[str] = None; owner: Optional[str] = None; nationality: Optional[str] = None
    tags: Optional[str] = None; lifetime_value: Optional[float] = None
class DealIn(BaseModel):
    title: str; contact_name: Optional[str] = None; stage: DealStage = DealStage.new
    value: float = 0.0; probability: int = 10; owner: Optional[str] = None; source: Optional[str] = None
    expected_close: Optional[str] = None
class DealPatch(BaseModel):
    title: Optional[str] = None; contact_name: Optional[str] = None; stage: Optional[DealStage] = None
    value: Optional[float] = None; probability: Optional[int] = None; owner: Optional[str] = None
    source: Optional[str] = None; expected_close: Optional[str] = None
class TicketIn(BaseModel):
    subject: str; description: Optional[str] = None; requester: Optional[str] = None; requester_email: Optional[str] = None
    assignee: Optional[str] = None; priority: TicketPriority = TicketPriority.medium
    status: TicketStatus = TicketStatus.open; category: Optional[str] = "general"; channel: Optional[str] = "web"; csat: Optional[int] = None
class TicketPatch(BaseModel):
    subject: Optional[str] = None; description: Optional[str] = None; requester: Optional[str] = None
    assignee: Optional[str] = None; priority: Optional[TicketPriority] = None; status: Optional[TicketStatus] = None
    category: Optional[str] = None; channel: Optional[str] = None; csat: Optional[int] = None


def _pdate(v):
    if not v: return None
    try: return datetime.fromisoformat(str(v)[:19])
    except Exception:
        try: return datetime.strptime(str(v)[:10], "%Y-%m-%d")
        except Exception: return None

def _contact_dict(c):
    return {"id": c.id, "name": c.name, "email": c.email, "phone": c.phone, "company": c.company,
            "contact_type": c.contact_type.value if c.contact_type else None, "status": c.status.value if c.status else None,
            "source": c.source, "owner": c.owner, "nationality": c.nationality, "tags": c.tags,
            "lifetime_value": round(c.lifetime_value or 0, 2),
            "last_contact": c.last_contact.isoformat() if c.last_contact else None,
            "created_at": c.created_at.isoformat() if c.created_at else None}

def _deal_dict(d):
    return {"id": d.id, "title": d.title, "contact_name": d.contact_name, "stage": d.stage.value if d.stage else None,
            "value": round(d.value or 0, 2), "probability": d.probability, "owner": d.owner, "source": d.source,
            "expected_close": d.expected_close.isoformat() if d.expected_close else None,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "closed_at": d.closed_at.isoformat() if d.closed_at else None}

def _ticket_dict(t):
    return {"id": t.id, "ref": t.ref, "subject": t.subject, "description": t.description, "requester": t.requester,
            "requester_email": t.requester_email, "assignee": t.assignee,
            "priority": t.priority.value if t.priority else None, "status": t.status.value if t.status else None,
            "category": t.category, "channel": t.channel,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "first_response_at": t.first_response_at.isoformat() if t.first_response_at else None,
            "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
            "sla_due": t.sla_due.isoformat() if t.sla_due else None,
            "first_response_mins": t.first_response_mins, "resolution_mins": t.resolution_mins,
            "sla_breached": t.sla_breached, "csat": t.csat}

_SLA_HOURS = {"urgent": 4, "high": 8, "medium": 24, "low": 48}


# ---------------- CRM ----------------
crm_router = APIRouter(prefix="/crm", tags=["crm"])

@crm_router.get("/contacts")
async def list_contacts(page: int = Query(1, ge=1), limit: int = Query(20, le=200),
        status: Optional[str] = None, contact_type: Optional[str] = None, source: Optional[str] = None,
        owner: Optional[str] = None, search: Optional[str] = None,
        db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Contact).order_by(Contact.created_at.desc())
    if status: q = q.where(Contact.status == status)
    if contact_type: q = q.where(Contact.contact_type == contact_type)
    if source: q = q.where(Contact.source == source)
    if owner: q = q.where(Contact.owner == owner)
    if search: q = q.where((Contact.name.ilike(f"%{search}%")) | (Contact.email.ilike(f"%{search}%")) | (Contact.company.ilike(f"%{search}%")))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.offset((page - 1) * limit).limit(limit))).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_contact_dict(c) for c in rows]}

@crm_router.post("/contacts", dependencies=[Depends(require_analyst)])
async def create_contact(data: ContactIn, db: AsyncSession = Depends(get_db)):
    c = Contact(**data.model_dump()); db.add(c); await db.commit(); await db.refresh(c)
    return _contact_dict(c)

@crm_router.patch("/contacts/{cid}", dependencies=[Depends(require_analyst)])
async def update_contact(cid: int, data: ContactPatch, db: AsyncSession = Depends(get_db)):
    c = (await db.execute(select(Contact).where(Contact.id == cid))).scalar_one_or_none()
    if not c: raise HTTPException(status_code=404, detail="Contact not found")
    for k, v in data.model_dump(exclude_none=True).items(): setattr(c, k, v)
    await db.commit(); await db.refresh(c)
    return _contact_dict(c)

@crm_router.delete("/contacts/{cid}", dependencies=[Depends(require_analyst)])
async def delete_contact(cid: int, db: AsyncSession = Depends(get_db)):
    c = (await db.execute(select(Contact).where(Contact.id == cid))).scalar_one_or_none()
    if not c: raise HTTPException(status_code=404, detail="Contact not found")
    await db.delete(c); await db.commit(); return {"ok": True}

@crm_router.get("/deals")
async def list_deals(page: int = Query(1, ge=1), limit: int = Query(50, le=200),
        stage: Optional[str] = None, owner: Optional[str] = None, source: Optional[str] = None, search: Optional[str] = None,
        db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Deal).order_by(Deal.created_at.desc())
    if stage: q = q.where(Deal.stage == stage)
    if owner: q = q.where(Deal.owner == owner)
    if source: q = q.where(Deal.source == source)
    if search: q = q.where((Deal.title.ilike(f"%{search}%")) | (Deal.contact_name.ilike(f"%{search}%")))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.offset((page - 1) * limit).limit(limit))).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_deal_dict(d) for d in rows]}

@crm_router.post("/deals", dependencies=[Depends(require_analyst)])
async def create_deal(data: DealIn, db: AsyncSession = Depends(get_db)):
    payload = data.model_dump(); ec = _pdate(payload.pop("expected_close", None))
    d = Deal(**payload, expected_close=ec)
    if d.stage in (DealStage.won, DealStage.lost): d.closed_at = datetime.utcnow()
    db.add(d); await db.commit(); await db.refresh(d)
    return _deal_dict(d)

@crm_router.patch("/deals/{did}", dependencies=[Depends(require_analyst)])
async def update_deal(did: int, data: DealPatch, db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(Deal).where(Deal.id == did))).scalar_one_or_none()
    if not d: raise HTTPException(status_code=404, detail="Deal not found")
    payload = data.model_dump(exclude_none=True)
    if "expected_close" in payload: d.expected_close = _pdate(payload.pop("expected_close"))
    for k, v in payload.items(): setattr(d, k, v)
    if d.stage in (DealStage.won, DealStage.lost) and not d.closed_at: d.closed_at = datetime.utcnow()
    await db.commit(); await db.refresh(d)
    return _deal_dict(d)

@crm_router.delete("/deals/{did}", dependencies=[Depends(require_analyst)])
async def delete_deal(did: int, db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(Deal).where(Deal.id == did))).scalar_one_or_none()
    if not d: raise HTTPException(status_code=404, detail="Deal not found")
    await db.delete(d); await db.commit(); return {"ok": True}

@crm_router.get("/analytics")
async def crm_analytics(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    contacts = (await db.execute(select(Contact))).scalars().all()
    deals = (await db.execute(select(Deal))).scalars().all()
    def cg(keyfn):
        m = {}
        for c in contacts:
            k = keyfn(c) or "Unknown"; d = m.setdefault(str(k), {"name": str(k), "count": 0, "value": 0.0})
            d["count"] += 1; d["value"] += (c.lifetime_value or 0)
        out = sorted(m.values(), key=lambda x: -x["count"])
        for d in out: d["value"] = round(d["value"], 2)
        return out
    open_stages = [DealStage.new, DealStage.contacted, DealStage.qualified, DealStage.proposal]
    stage_map = {}
    for s in DealStage:
        ds = [d for d in deals if d.stage == s]
        stage_map[s.value] = {"stage": s.value, "count": len(ds), "value": round(sum(d.value or 0 for d in ds), 2)}
    won = [d for d in deals if d.stage == DealStage.won]; lost = [d for d in deals if d.stage == DealStage.lost]
    open_deals = [d for d in deals if d.stage in open_stages]
    weighted = round(sum((d.value or 0) * (d.probability or 0) / 100 for d in open_deals), 2)
    total_customers = len([c for c in contacts if c.status in (ContactStatus.customer, ContactStatus.vip)])
    top_deals = sorted(deals, key=lambda d: -(d.value or 0))[:10]
    top_contacts = sorted(contacts, key=lambda c: -(c.lifetime_value or 0))[:10]
    dmonth = {}
    for d in deals:
        k = d.created_at.strftime("%Y-%m") if d.created_at else "?"; dmonth[k] = dmonth.get(k, 0) + 1
    return {
        "total_contacts": len(contacts),
        "customers": total_customers,
        "by_status": cg(lambda c: c.status.value if c.status else None),
        "by_source": cg(lambda c: c.source),
        "by_type": cg(lambda c: c.contact_type.value if c.contact_type else None),
        "by_owner": cg(lambda c: c.owner),
        "top_contacts": [{"name": c.name, "company": c.company, "status": c.status.value if c.status else None, "value": round(c.lifetime_value or 0, 2)} for c in top_contacts],
        "pipeline_by_stage": [stage_map[s.value] for s in DealStage],
        "total_pipeline_value": round(sum(d.value or 0 for d in open_deals), 2),
        "weighted_pipeline": weighted,
        "open_deals": len(open_deals), "won_count": len(won), "lost_count": len(lost),
        "win_rate": round(len(won) / (len(won) + len(lost)) * 100, 1) if (won or lost) else 0,
        "conversion_rate": round(total_customers / len(contacts) * 100, 1) if contacts else 0,
        "revenue_won": round(sum(d.value or 0 for d in won), 2),
        "avg_deal_size": round(sum(d.value or 0 for d in deals) / len(deals), 2) if deals else 0,
        "deals_trend": [{"month": k, "count": dmonth[k]} for k in sorted(dmonth)],
        "top_deals": [{"title": d.title, "contact": d.contact_name, "stage": d.stage.value if d.stage else None, "value": round(d.value or 0, 2), "owner": d.owner} for d in top_deals],
    }


# ---------------- Helpdesk ----------------
help_router = APIRouter(prefix="/helpdesk", tags=["helpdesk"])

@help_router.get("/tickets")
async def list_tickets(page: int = Query(1, ge=1), limit: int = Query(20, le=200),
        status: Optional[str] = None, priority: Optional[str] = None, category: Optional[str] = None,
        channel: Optional[str] = None, assignee: Optional[str] = None, sla_breached: Optional[bool] = None,
        search: Optional[str] = None, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Ticket).order_by(Ticket.created_at.desc())
    if status: q = q.where(Ticket.status == status)
    if priority: q = q.where(Ticket.priority == priority)
    if category: q = q.where(Ticket.category == category)
    if channel: q = q.where(Ticket.channel == channel)
    if assignee: q = q.where(Ticket.assignee == assignee)
    if sla_breached is not None: q = q.where(Ticket.sla_breached == sla_breached)
    if search: q = q.where((Ticket.subject.ilike(f"%{search}%")) | (Ticket.ref.ilike(f"%{search}%")) | (Ticket.requester.ilike(f"%{search}%")))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.offset((page - 1) * limit).limit(limit))).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_ticket_dict(t) for t in rows]}

@help_router.post("/tickets", dependencies=[Depends(require_analyst)])
async def create_ticket(data: TicketIn, db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    t = Ticket(ref=f"TKT{str(uuid.uuid4())[:6].upper()}", **data.model_dump())
    t.created_at = now
    t.sla_due = now + timedelta(hours=_SLA_HOURS.get(t.priority.value if t.priority else "medium", 24))
    db.add(t); await db.commit(); await db.refresh(t)
    return _ticket_dict(t)

@help_router.patch("/tickets/{tid}", dependencies=[Depends(require_analyst)])
async def update_ticket(tid: int, data: TicketPatch, db: AsyncSession = Depends(get_db)):
    t = (await db.execute(select(Ticket).where(Ticket.id == tid))).scalar_one_or_none()
    if not t: raise HTTPException(status_code=404, detail="Ticket not found")
    for k, v in data.model_dump(exclude_none=True).items(): setattr(t, k, v)
    now = datetime.utcnow()
    if t.first_response_at is None and t.status != TicketStatus.open:
        t.first_response_at = now
        if t.created_at: t.first_response_mins = int((now - t.created_at.replace(tzinfo=None)).total_seconds() / 60)
    if t.status in (TicketStatus.resolved, TicketStatus.closed) and t.resolved_at is None:
        t.resolved_at = now
        if t.created_at:
            t.resolution_mins = int((now - t.created_at.replace(tzinfo=None)).total_seconds() / 60)
            t.sla_breached = bool(t.sla_due and now > t.sla_due.replace(tzinfo=None))
    await db.commit(); await db.refresh(t)
    return _ticket_dict(t)

@help_router.delete("/tickets/{tid}", dependencies=[Depends(require_analyst)])
async def delete_ticket(tid: int, db: AsyncSession = Depends(get_db)):
    t = (await db.execute(select(Ticket).where(Ticket.id == tid))).scalar_one_or_none()
    if not t: raise HTTPException(status_code=404, detail="Ticket not found")
    await db.delete(t); await db.commit(); return {"ok": True}

@help_router.get("/analytics")
async def help_analytics(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    tks = (await db.execute(select(Ticket))).scalars().all()
    def tg(keyfn, valfn=None):
        m = {}
        for t in tks:
            k = keyfn(t) or "Unknown"; d = m.setdefault(str(k), {"name": str(k), "count": 0})
            d["count"] += 1
        return sorted(m.values(), key=lambda x: -x["count"])
    resolved = [t for t in tks if t.status in (TicketStatus.resolved, TicketStatus.closed)]
    open_like = [t for t in tks if t.status in (TicketStatus.open, TicketStatus.pending, TicketStatus.on_hold)]
    frs = [t.first_response_mins for t in tks if t.first_response_mins is not None]
    res = [t.resolution_mins for t in resolved if t.resolution_mins is not None]
    csats = [t.csat for t in tks if t.csat is not None]
    breached = [t for t in resolved if t.sla_breached]
    agent_map = {}
    for t in tks:
        a = t.assignee or "Unassigned"; d = agent_map.setdefault(a, {"name": a, "count": 0, "resolved": 0, "res_mins": []})
        d["count"] += 1
        if t.status in (TicketStatus.resolved, TicketStatus.closed):
            d["resolved"] += 1
            if t.resolution_mins is not None: d["res_mins"].append(t.resolution_mins)
    agents = []
    for d in agent_map.values():
        d["avg_resolution_hrs"] = round(sum(d["res_mins"]) / len(d["res_mins"]) / 60, 1) if d["res_mins"] else None
        d.pop("res_mins"); agents.append(d)
    agents.sort(key=lambda x: -x["count"])
    tmonth = {}
    for t in tks:
        k = t.created_at.strftime("%Y-%m") if t.created_at else "?"; tmonth[k] = tmonth.get(k, 0) + 1
    return {
        "total": len(tks), "open": len([t for t in tks if t.status == TicketStatus.open]),
        "pending": len([t for t in tks if t.status == TicketStatus.pending]),
        "on_hold": len([t for t in tks if t.status == TicketStatus.on_hold]),
        "resolved": len([t for t in tks if t.status == TicketStatus.resolved]),
        "closed": len([t for t in tks if t.status == TicketStatus.closed]),
        "backlog": len(open_like),
        "avg_first_response_hrs": round(sum(frs) / len(frs) / 60, 1) if frs else None,
        "avg_resolution_hrs": round(sum(res) / len(res) / 60, 1) if res else None,
        "sla_compliance": round((1 - len(breached) / len(resolved)) * 100, 1) if resolved else 100,
        "sla_breached": len(breached),
        "csat_avg": round(sum(csats) / len(csats), 2) if csats else None,
        "csat_responses": len(csats),
        "by_status": tg(lambda t: t.status.value if t.status else None),
        "by_priority": tg(lambda t: t.priority.value if t.priority else None),
        "by_category": tg(lambda t: t.category),
        "by_channel": tg(lambda t: t.channel),
        "agents": agents,
        "volume_trend": [{"month": k, "count": tmonth[k]} for k in sorted(tmonth)],
        "recent_open": [{"ref": t.ref, "subject": t.subject, "requester": t.requester, "priority": t.priority.value if t.priority else None, "status": t.status.value if t.status else None, "assignee": t.assignee} for t in sorted(open_like, key=lambda x: (x.priority != TicketPriority.urgent, x.priority != TicketPriority.high))[:15]],
    }


async def seed_crm_helpdesk():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Contact).limit(1))).scalar_one_or_none(): return
        owners = ["E. Rashid", "F. Kumar", "S. Ali", "M. Santos", "A. Nair"]
        agents = ["Layla H.", "Omar K.", "Priya S.", "Yusuf A.", "Sara M."]
        sources = ["referral", "online", "campaign", "walk-in", "agent"]
        nats = ["Indian", "Pakistani", "Filipino", "Egyptian", "Bangladeshi", "Omani", "British"]
        companies = ["Al Noor Trading", "Gulf Logistics", "Dhofar Retail", "Muscat Tech", "Batinah Foods", None, None, None]
        base = datetime.utcnow() - timedelta(days=180)
        contacts = []
        for i in range(160):
            st = random.choices(list(ContactStatus), weights=[30, 22, 30, 6, 12])[0]
            ct = random.choices([ContactType.individual, ContactType.corporate], weights=[72, 28])[0]
            ltv = round(random.uniform(50, 800) if st in (ContactStatus.lead, ContactStatus.prospect) else random.uniform(500, 12000), 2)
            created = base + timedelta(days=random.randint(0, 180))
            contacts.append(Contact(name=f"Customer {1000+i}", email=f"cust{1000+i}@example.com",
                phone=f"+968 9{random.randint(1000000,9999999)}", company=random.choice(companies),
                contact_type=ct, status=st, source=random.choice(sources), owner=random.choice(owners),
                nationality=random.choice(nats), tags=random.choice(["remittance", "fx", "corporate", "vip", "payroll"]),
                lifetime_value=ltv, last_contact=created + timedelta(days=random.randint(0, 30)), created_at=created))
        db.add_all(contacts); await db.commit()

        titles = ["Corporate FX Agreement", "Payroll Remittance Deal", "Bulk Currency Order", "Monthly Transfer Plan",
                  "Trade Settlement Account", "Premium FX Package", "Business Exchange Contract", "Retail Loyalty Signup"]
        deals = []
        for i in range(90):
            stage = random.choices(list(DealStage), weights=[18, 16, 16, 14, 22, 14])[0]
            prob = {"new": 10, "contacted": 25, "qualified": 45, "proposal": 65, "won": 100, "lost": 0}[stage.value]
            val = round(random.uniform(500, 25000), 2)
            created = base + timedelta(days=random.randint(0, 180))
            closed = created + timedelta(days=random.randint(5, 40)) if stage in (DealStage.won, DealStage.lost) else None
            deals.append(Deal(title=random.choice(titles), contact_name=f"Customer {1000+random.randint(0,159)}",
                stage=stage, value=val, probability=prob, owner=random.choice(owners), source=random.choice(sources),
                expected_close=created + timedelta(days=random.randint(10, 60)), created_at=created, closed_at=closed))
        db.add_all(deals); await db.commit()

        subjects = ["Delayed remittance to India", "OTP not received", "Incorrect exchange rate applied",
                    "KYC document re-upload", "Refund request for failed transfer", "App login issue",
                    "Beneficiary details update", "Cash pickup not available", "Double charge on transaction",
                    "Account statement request", "Suspicious transaction query", "Branch queue complaint"]
        cats = ["remittance", "account", "technical", "complaint", "kyc", "fraud", "general"]
        chans = ["email", "phone", "chat", "web", "branch"]
        tickets = []
        for i in range(240):
            pri = random.choices(list(TicketPriority), weights=[30, 40, 22, 8])[0]
            st = random.choices(list(TicketStatus), weights=[22, 14, 8, 26, 30])[0]
            created = base + timedelta(days=random.randint(0, 180), hours=random.randint(0, 23))
            sla_hours = _SLA_HOURS[pri.value]
            sla_due = created + timedelta(hours=sla_hours)
            fr_mins = res_mins = fr_at = res_at = None
            breached = False
            if st != TicketStatus.open:
                fr_mins = random.randint(10, sla_hours * 60)
                fr_at = created + timedelta(minutes=fr_mins)
            if st in (TicketStatus.resolved, TicketStatus.closed):
                if random.random() < 0.72:
                    res_mins = random.randint(fr_mins or 30, sla_hours * 60)
                else:
                    res_mins = random.randint(sla_hours * 60 + 30, sla_hours * 60 * 3)
                res_at = created + timedelta(minutes=res_mins)
                breached = res_at > sla_due
            csat = random.randint(3, 5) if st in (TicketStatus.resolved, TicketStatus.closed) and random.random() < 0.6 else None
            tickets.append(Ticket(ref=f"TKT{str(uuid.uuid4())[:6].upper()}", subject=random.choice(subjects),
                description="Customer reported an issue that requires follow-up.",
                requester=f"Customer {1000+random.randint(0,159)}", requester_email=f"cust{1000+random.randint(0,159)}@example.com",
                assignee=random.choice(agents), priority=pri, status=st, category=random.choice(cats),
                channel=random.choice(chans), created_at=created, first_response_at=fr_at, resolved_at=res_at,
                sla_due=sla_due, first_response_mins=fr_mins, resolution_mins=res_mins, sla_breached=breached, csat=csat))
        db.add_all(tickets); await db.commit()
# ============================ END CRM + HELPDESK ============================




# ============================ DOCUMENT MANAGEMENT SYSTEM ============================
class DocDomain(str, enum.Enum):
    customer = "customer"; compliance = "compliance"; operational = "operational"; financial = "financial"; regulatory = "regulatory"

class DocStatus(str, enum.Enum):
    draft = "draft"; pending_review = "pending_review"; approved = "approved"; rejected = "rejected"; archived = "archived"

class Confidentiality(str, enum.Enum):
    public = "public"; internal = "internal"; confidential = "confidential"; restricted = "restricted"

class SigStatus(str, enum.Enum):
    not_required = "not_required"; unsigned = "unsigned"; pending = "pending"; signed = "signed"

class OcrStatus(str, enum.Enum):
    not_applicable = "not_applicable"; pending = "pending"; processed = "processed"

class Disposition(str, enum.Enum):
    active = "active"; review_due = "review_due"; dispose_due = "dispose_due"

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True, index=True)
    doc_ref = Column(String, unique=True, index=True)
    title = Column(String, index=True)
    description = Column(String, default="")
    domain = Column(Enum(DocDomain), default=DocDomain.operational, index=True)
    category = Column(String, index=True)
    status = Column(Enum(DocStatus), default=DocStatus.draft, index=True)
    confidentiality = Column(Enum(Confidentiality), default=Confidentiality.internal, index=True)
    owner = Column(String, index=True)
    department = Column(String, index=True)
    file_type = Column(String, default="pdf")
    size_kb = Column(Integer, default=0)
    version = Column(Integer, default=1)
    supersedes = Column(String, default="")            # doc_ref of prior version
    signature_status = Column(Enum(SigStatus), default=SigStatus.not_required, index=True)
    signed_by = Column(String, default="")
    signed_at = Column(DateTime, nullable=True)
    ocr_status = Column(Enum(OcrStatus), default=OcrStatus.not_applicable, index=True)
    searchable = Column(Boolean, default=False)
    reviewer = Column(String, default="")
    approved_by = Column(String, default="")
    approved_at = Column(DateTime, nullable=True)
    regulatory_body = Column(String, default="")       # CBO / FATF / Tax Authority / Internal
    compliance_flag = Column(String, default="compliant", index=True)  # compliant / expiring / expired / missing
    retention_years = Column(Integer, default=5)
    retention_until = Column(DateTime, nullable=True)
    legal_hold = Column(Boolean, default=False, index=True)
    disposition = Column(Enum(Disposition), default=Disposition.active, index=True)
    related_entity = Column(String, default="")
    tags = Column(String, default="")
    expiry_date = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_accessed_at = Column(DateTime, nullable=True)

class DocAudit(Base):
    __tablename__ = "doc_audit"
    id = Column(Integer, primary_key=True, index=True)
    doc_ref = Column(String, index=True)
    action = Column(String)          # created / viewed / edited / submitted / approved / rejected / signed / archived / downloaded
    actor = Column(String)
    note = Column(String, default="")
    at = Column(DateTime, default=datetime.utcnow, index=True)

class DocumentIn(BaseModel):
    title: str; description: Optional[str] = ""
    domain: DocDomain = DocDomain.operational; category: str = "general"
    status: DocStatus = DocStatus.draft; confidentiality: Confidentiality = Confidentiality.internal
    owner: Optional[str] = ""; department: Optional[str] = ""
    file_type: Optional[str] = "pdf"; size_kb: Optional[int] = 0
    version: Optional[int] = 1; supersedes: Optional[str] = ""
    signature_status: SigStatus = SigStatus.not_required
    ocr_status: OcrStatus = OcrStatus.not_applicable; searchable: Optional[bool] = False
    reviewer: Optional[str] = ""; regulatory_body: Optional[str] = ""
    compliance_flag: Optional[str] = "compliant"; retention_years: Optional[int] = 5
    legal_hold: Optional[bool] = False; related_entity: Optional[str] = ""
    tags: Optional[str] = ""; expiry_date: Optional[str] = None

class DocumentPatch(BaseModel):
    title: Optional[str] = None; description: Optional[str] = None
    domain: Optional[DocDomain] = None; category: Optional[str] = None
    status: Optional[DocStatus] = None; confidentiality: Optional[Confidentiality] = None
    owner: Optional[str] = None; department: Optional[str] = None
    file_type: Optional[str] = None; size_kb: Optional[int] = None
    version: Optional[int] = None; supersedes: Optional[str] = None
    signature_status: Optional[SigStatus] = None; signed_by: Optional[str] = None
    ocr_status: Optional[OcrStatus] = None; searchable: Optional[bool] = None
    reviewer: Optional[str] = None; approved_by: Optional[str] = None
    regulatory_body: Optional[str] = None; compliance_flag: Optional[str] = None
    retention_years: Optional[int] = None; legal_hold: Optional[bool] = None
    disposition: Optional[Disposition] = None; related_entity: Optional[str] = None
    tags: Optional[str] = None; expiry_date: Optional[str] = None

def _ddate(s):
    if not s: return None
    try: return datetime.strptime(s[:10], "%Y-%m-%d")
    except Exception: return None

def _iso(d):
    return d.isoformat() if d else None

def _doc_dict(d):
    return {"id": d.id, "doc_ref": d.doc_ref, "title": d.title, "description": d.description,
            "domain": d.domain.value if d.domain else None, "category": d.category,
            "status": d.status.value if d.status else None,
            "confidentiality": d.confidentiality.value if d.confidentiality else None,
            "owner": d.owner, "department": d.department, "file_type": d.file_type, "size_kb": d.size_kb,
            "version": d.version, "supersedes": d.supersedes,
            "signature_status": d.signature_status.value if d.signature_status else None,
            "signed_by": d.signed_by, "signed_at": _iso(d.signed_at),
            "ocr_status": d.ocr_status.value if d.ocr_status else None, "searchable": d.searchable,
            "reviewer": d.reviewer, "approved_by": d.approved_by, "approved_at": _iso(d.approved_at),
            "regulatory_body": d.regulatory_body, "compliance_flag": d.compliance_flag,
            "retention_years": d.retention_years, "retention_until": _iso(d.retention_until),
            "legal_hold": d.legal_hold, "disposition": d.disposition.value if d.disposition else None,
            "related_entity": d.related_entity, "tags": d.tags, "expiry_date": _iso(d.expiry_date),
            "access_count": d.access_count, "created_at": _iso(d.created_at), "updated_at": _iso(d.updated_at)}

def _audit_dict(a):
    return {"id": a.id, "doc_ref": a.doc_ref, "action": a.action, "actor": a.actor, "note": a.note, "at": _iso(a.at)}

doc_router = APIRouter(prefix="/documents", tags=["documents"])

@doc_router.get("")
async def list_documents(page: int = Query(1, ge=1), limit: int = Query(50, le=300),
        domain: Optional[str] = None, category: Optional[str] = None, status: Optional[str] = None,
        confidentiality: Optional[str] = None, department: Optional[str] = None,
        signature_status: Optional[str] = None, compliance_flag: Optional[str] = None,
        legal_hold: Optional[str] = None, disposition: Optional[str] = None, search: Optional[str] = None,
        db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    q = select(Document).order_by(Document.created_at.desc())
    if domain: q = q.where(Document.domain == domain)
    if category: q = q.where(Document.category == category)
    if status: q = q.where(Document.status == status)
    if confidentiality: q = q.where(Document.confidentiality == confidentiality)
    if department: q = q.where(Document.department == department)
    if signature_status: q = q.where(Document.signature_status == signature_status)
    if compliance_flag: q = q.where(Document.compliance_flag == compliance_flag)
    if legal_hold in ("true", "false"): q = q.where(Document.legal_hold == (legal_hold == "true"))
    if disposition: q = q.where(Document.disposition == disposition)
    if search: q = q.where((Document.title.ilike(f"%{search}%")) | (Document.doc_ref.ilike(f"%{search}%")) | (Document.tags.ilike(f"%{search}%")) | (Document.related_entity.ilike(f"%{search}%")))
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows = (await db.execute(q.offset((page - 1) * limit).limit(limit))).scalars().all()
    return {"total": total, "page": page, "limit": limit, "items": [_doc_dict(d) for d in rows]}

DEPTS = ["Compliance", "Operations", "Finance", "Legal", "Branch Ops", "Risk", "IT"]

async def _add_audit(db, doc_ref, action, actor, note=""):
    db.add(DocAudit(doc_ref=doc_ref, action=action, actor=actor, note=note, at=datetime.utcnow()))

@doc_router.post("", dependencies=[Depends(require_analyst)])
async def create_document(data: DocumentIn, db: AsyncSession = Depends(get_db), u: User = Depends(get_current_user)):
    n = (await db.execute(select(func.count()).select_from(Document))).scalar() or 0
    ref = f"DOC-{datetime.utcnow().year}-{100001 + n}"
    payload = data.model_dump(); exp = _ddate(payload.pop("expiry_date", None))
    ry = payload.get("retention_years") or 5
    d = Document(**payload, doc_ref=ref, expiry_date=exp,
                 retention_until=datetime.utcnow() + timedelta(days=365 * ry),
                 created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    if not d.owner: d.owner = u.full_name
    db.add(d); await _add_audit(db, ref, "created", u.full_name, f"Created in {d.domain.value}")
    await db.commit(); await db.refresh(d)
    return _doc_dict(d)

@doc_router.patch("/{did}", dependencies=[Depends(require_analyst)])
async def update_document(did: int, data: DocumentPatch, db: AsyncSession = Depends(get_db), u: User = Depends(get_current_user)):
    d = (await db.execute(select(Document).where(Document.id == did))).scalar_one_or_none()
    if not d: raise HTTPException(status_code=404, detail="Document not found")
    changes = data.model_dump(exclude_none=True)
    if "expiry_date" in changes: d.expiry_date = _ddate(changes.pop("expiry_date"))
    prev_status, prev_sig = d.status, d.signature_status
    for k, v in changes.items(): setattr(d, k, v)
    d.updated_at = datetime.utcnow()
    if data.status and data.status != prev_status:
        if data.status == DocStatus.approved:
            d.approved_by = d.approved_by or u.full_name; d.approved_at = datetime.utcnow()
            await _add_audit(db, d.doc_ref, "approved", u.full_name)
        elif data.status == DocStatus.rejected:
            await _add_audit(db, d.doc_ref, "rejected", u.full_name)
        elif data.status == DocStatus.pending_review:
            await _add_audit(db, d.doc_ref, "submitted", u.full_name)
        elif data.status == DocStatus.archived:
            await _add_audit(db, d.doc_ref, "archived", u.full_name)
        else:
            await _add_audit(db, d.doc_ref, "edited", u.full_name)
    if data.signature_status == SigStatus.signed and prev_sig != SigStatus.signed:
        d.signed_by = d.signed_by or u.full_name; d.signed_at = datetime.utcnow()
        await _add_audit(db, d.doc_ref, "signed", d.signed_by)
    if not (data.status or data.signature_status):
        await _add_audit(db, d.doc_ref, "edited", u.full_name)
    await db.commit(); await db.refresh(d)
    return _doc_dict(d)

@doc_router.delete("/{did}", dependencies=[Depends(require_analyst)])
async def delete_document(did: int, db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(Document).where(Document.id == did))).scalar_one_or_none()
    if not d: raise HTTPException(status_code=404, detail="Document not found")
    await db.delete(d); await db.commit(); return {"ok": True}

@doc_router.get("/{did}/audit")
async def document_audit(did: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    d = (await db.execute(select(Document).where(Document.id == did))).scalar_one_or_none()
    if not d: raise HTTPException(status_code=404, detail="Document not found")
    rows = (await db.execute(select(DocAudit).where(DocAudit.doc_ref == d.doc_ref).order_by(DocAudit.at.desc()))).scalars().all()
    return {"doc_ref": d.doc_ref, "items": [_audit_dict(a) for a in rows]}

@doc_router.get("/analytics")
async def documents_analytics(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    docs = (await db.execute(select(Document))).scalars().all()
    now = datetime.utcnow()
    def grp(key):
        c = {}
        for d in docs:
            v = key(d)
            if v is None: continue
            c[v] = c.get(v, 0) + 1
        return [{"name": k, "count": v} for k, v in sorted(c.items(), key=lambda x: -x[1])]
    def days_to(dt): return (dt - now).days if dt else None
    expiring = [d for d in docs if d.expiry_date and 0 <= days_to(d.expiry_date) <= 90]
    expired = [d for d in docs if d.expiry_date and days_to(d.expiry_date) < 0]
    monthly = {}
    for d in docs:
        if d.created_at:
            m = d.created_at.strftime("%Y-%m"); monthly[m] = monthly.get(m, 0) + 1
    trend = [{"month": k, "count": v} for k, v in sorted(monthly.items())][-12:]
    audits = (await db.execute(select(DocAudit).order_by(DocAudit.at.desc()).limit(15))).scalars().all()
    signed = len([d for d in docs if d.signature_status == SigStatus.signed])
    sig_pending = len([d for d in docs if d.signature_status == SigStatus.pending])
    owners = {}
    for d in docs: owners[d.owner or "—"] = owners.get(d.owner or "—", 0) + 1
    top_owners = [{"owner": k, "count": v} for k, v in sorted(owners.items(), key=lambda x: -x[1])[:8]]
    approved_docs = [d for d in docs if d.approved_at and d.created_at]
    avg_appr = round(sum((d.approved_at - d.created_at).days for d in approved_docs) / len(approved_docs), 1) if approved_docs else 0
    return {
        "total": len(docs),
        "pending_review": len([d for d in docs if d.status == DocStatus.pending_review]),
        "approved": len([d for d in docs if d.status == DocStatus.approved]),
        "draft": len([d for d in docs if d.status == DocStatus.draft]),
        "archived": len([d for d in docs if d.status == DocStatus.archived]),
        "expiring_soon": len(expiring), "expired": len(expired),
        "legal_holds": len([d for d in docs if d.legal_hold]),
        "retention_due": len([d for d in docs if d.disposition in (Disposition.review_due, Disposition.dispose_due)]),
        "signed": signed, "signature_pending": sig_pending,
        "sign_rate": round(signed / max(1, len([d for d in docs if d.signature_status != SigStatus.not_required])) * 100, 1),
        "ocr_processed": len([d for d in docs if d.ocr_status == OcrStatus.processed]),
        "storage_mb": round(sum(d.size_kb or 0 for d in docs) / 1024, 1),
        "avg_approval_days": avg_appr,
        "by_domain": grp(lambda d: d.domain.value if d.domain else None),
        "by_category": grp(lambda d: d.category)[:10],
        "by_status": grp(lambda d: d.status.value if d.status else None),
        "by_confidentiality": grp(lambda d: d.confidentiality.value if d.confidentiality else None),
        "by_department": grp(lambda d: d.department),
        "by_file_type": grp(lambda d: d.file_type),
        "by_signature": grp(lambda d: d.signature_status.value if d.signature_status else None),
        "by_compliance": grp(lambda d: d.compliance_flag),
        "docs_trend": trend,
        "expiring_list": sorted([{"doc_ref": d.doc_ref, "title": d.title, "category": d.category,
                                  "owner": d.owner, "days": days_to(d.expiry_date),
                                  "expiry_date": _iso(d.expiry_date)} for d in expiring], key=lambda x: x["days"])[:20],
        "recent_activity": [_audit_dict(a) for a in audits],
        "top_owners": top_owners,
    }

async def seed_documents():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Document).limit(1))).scalar_one_or_none(): return
        cats = {
            DocDomain.customer: ["KYC Form", "ID Proof", "Address Proof", "Customer Agreement", "Beneficiary Form"],
            DocDomain.compliance: ["AML Policy", "STR Report", "CTR Report", "Sanctions Screening", "Compliance Manual", "Risk Assessment"],
            DocDomain.operational: ["SOP", "Branch Report", "Reconciliation", "Incident Report", "Training Record"],
            DocDomain.financial: ["Invoice", "Bank Statement", "Settlement Report", "Audit Report", "Tax Filing", "Ledger Export"],
            DocDomain.regulatory: ["CBO License", "Regulatory Return", "Inspection Report", "Circular Ack", "Renewal Application"],
        }
        regbody = {DocDomain.compliance: "FATF", DocDomain.regulatory: "CBO", DocDomain.financial: "Tax Authority",
                   DocDomain.customer: "Internal", DocDomain.operational: "Internal"}
        owners = ["A. Nair", "F. Kumar", "S. Ali", "H. Said", "R. Perera", "M. Santos", "E. Rashid"]
        ftypes = ["pdf", "pdf", "pdf", "docx", "xlsx", "png", "tiff"]
        docs = []; base = datetime.utcnow() - timedelta(days=720)
        for i in range(210):
            dom = random.choices(list(cats.keys()), weights=[30, 26, 18, 16, 10])[0]
            cat = random.choice(cats[dom])
            created = base + timedelta(days=random.randint(0, 700), hours=random.randint(7, 19))
            st = random.choices(list(DocStatus), weights=[14, 16, 55, 5, 10])[0]
            conf = random.choices(list(Confidentiality), weights=[8, 30, 42, 20])[0]
            needs_sig = dom in (DocDomain.customer, DocDomain.regulatory, DocDomain.compliance) and random.random() < 0.7
            sig = SigStatus.not_required
            if needs_sig:
                sig = random.choices([SigStatus.signed, SigStatus.pending, SigStatus.unsigned], weights=[62, 20, 18])[0]
            ft = random.choice(ftypes)
            ocr = OcrStatus.not_applicable
            if ft in ("png", "tiff", "pdf"):
                ocr = random.choices([OcrStatus.processed, OcrStatus.pending, OcrStatus.not_applicable], weights=[64, 16, 20])[0]
            ver = random.choices([1, 1, 1, 2, 3, 4], weights=[45, 20, 10, 12, 8, 5])[0]
            has_exp = dom in (DocDomain.regulatory, DocDomain.customer, DocDomain.compliance) and random.random() < 0.55
            exp = None; cflag = "compliant"
            if has_exp:
                exp = now_off = datetime.utcnow() + timedelta(days=random.randint(-120, 420))
                dd = (exp - datetime.utcnow()).days
                cflag = "expired" if dd < 0 else ("expiring" if dd <= 90 else "compliant")
            ry = random.choice([3, 5, 5, 7, 10])
            legal = random.random() < 0.06
            disp = Disposition.active
            r = random.random()
            if r < 0.08: disp = Disposition.review_due
            elif r < 0.12: disp = Disposition.dispose_due
            appr_by = ""; appr_at = None; reviewer = random.choice(owners)
            if st == DocStatus.approved:
                appr_by = random.choice(owners); appr_at = created + timedelta(days=random.randint(1, 20))
            d = Document(
                doc_ref=f"DOC-{created.year}-{100001 + i}", title=f"{cat} #{1000 + i}",
                description=f"{cat} document for {dom.value} records.", domain=dom, category=cat,
                status=st, confidentiality=conf, owner=random.choice(owners), department=random.choice(DEPTS),
                file_type=ft, size_kb=random.randint(40, 8200), version=ver,
                supersedes=(f"DOC-{created.year}-{100000 + i}" if ver > 1 else ""),
                signature_status=sig, signed_by=(random.choice(owners) if sig == SigStatus.signed else ""),
                signed_at=(created + timedelta(days=random.randint(1, 10)) if sig == SigStatus.signed else None),
                ocr_status=ocr, searchable=(ocr == OcrStatus.processed),
                reviewer=reviewer, approved_by=appr_by, approved_at=appr_at,
                regulatory_body=regbody[dom], compliance_flag=cflag,
                retention_years=ry, retention_until=created + timedelta(days=365 * ry),
                legal_hold=legal, disposition=disp,
                related_entity=(f"Customer {1000 + random.randint(0, 400)}" if dom == DocDomain.customer else random.choice(["Ruwi Branch", "Salalah Branch", "Head Office", "Sohar Branch"])),
                tags=",".join(random.sample(["kyc", "aml", "renewal", "audit", "urgent", "signed", "scan", "archive"], k=random.randint(1, 3))),
                expiry_date=exp, access_count=random.randint(0, 240),
                created_at=created, updated_at=created + timedelta(days=random.randint(0, 30)),
                last_accessed_at=created + timedelta(days=random.randint(0, 60)))
            docs.append(d)
        db.add_all(docs); await db.commit()
        # seed audit trail
        audits = []
        for d in docs:
            audits.append(DocAudit(doc_ref=d.doc_ref, action="created", actor=d.owner, at=d.created_at, note=f"Created in {d.domain.value}"))
            if random.random() < 0.7:
                audits.append(DocAudit(doc_ref=d.doc_ref, action="viewed", actor=random.choice(owners), at=d.created_at + timedelta(days=random.randint(1, 30))))
            if d.status.value in ("pending_review", "approved", "rejected"):
                audits.append(DocAudit(doc_ref=d.doc_ref, action="submitted", actor=d.reviewer, at=d.created_at + timedelta(days=1)))
            if d.approved_at:
                audits.append(DocAudit(doc_ref=d.doc_ref, action="approved", actor=d.approved_by, at=d.approved_at))
            if d.signed_at:
                audits.append(DocAudit(doc_ref=d.doc_ref, action="signed", actor=d.signed_by, at=d.signed_at))
        db.add_all(audits); await db.commit()
# ============================ END DOCUMENT MANAGEMENT SYSTEM ============================




# ======================================================================
# SHARED HELPER
# ======================================================================
def _cb(items, fn):
    c = {}
    for it in items:
        v = fn(it)
        if v is None: continue
        c[v] = c.get(v, 0) + 1
    return [{"name": k, "count": v} for k, v in sorted(c.items(), key=lambda x: -x[1])]

def _monthly_count(items, datefn):
    m = {}
    for it in items:
        d = datefn(it)
        if d: m[d.strftime("%Y-%m")] = m.get(d.strftime("%Y-%m"), 0) + 1
    return [{"month": k, "count": v} for k, v in sorted(m.items())][-12:]

# ======================================================================
# LOYALTY & REWARDS
# ======================================================================
class Tier(str, enum.Enum):
    bronze="bronze"; silver="silver"; gold="gold"; platinum="platinum"

class Member(Base):
    __tablename__="loyalty_members"
    id=Column(Integer, primary_key=True, index=True)
    member_ref=Column(String, unique=True, index=True)
    name=Column(String, index=True); email=Column(String, default=""); phone=Column(String, default="")
    tier=Column(Enum(Tier), default=Tier.bronze, index=True)
    points_balance=Column(Integer, default=0); points_earned=Column(Integer, default=0); points_redeemed=Column(Integer, default=0)
    lifetime_value=Column(Float, default=0.0)
    status=Column(String, default="active", index=True)
    home_branch=Column(String, default=""); nationality=Column(String, default="")
    enrolled_at=Column(DateTime, default=datetime.utcnow, index=True)
    last_activity=Column(DateTime, nullable=True)

class Redemption(Base):
    __tablename__="loyalty_redemptions"
    id=Column(Integer, primary_key=True, index=True)
    member_ref=Column(String, index=True); reward=Column(String); points=Column(Integer, default=0)
    value_omr=Column(Float, default=0.0); status=Column(String, default="redeemed")
    at=Column(DateTime, default=datetime.utcnow, index=True)

class MemberIn(BaseModel):
    name: str; email: Optional[str]=""; phone: Optional[str]=""
    tier: Tier=Tier.bronze; points_balance: Optional[int]=0; lifetime_value: Optional[float]=0.0
    status: Optional[str]="active"; home_branch: Optional[str]=""; nationality: Optional[str]=""
class MemberPatch(BaseModel):
    name: Optional[str]=None; email: Optional[str]=None; phone: Optional[str]=None
    tier: Optional[Tier]=None; points_balance: Optional[int]=None; lifetime_value: Optional[float]=None
    status: Optional[str]=None; home_branch: Optional[str]=None

def _member_dict(m):
    return {"id":m.id,"member_ref":m.member_ref,"name":m.name,"email":m.email,"phone":m.phone,
            "tier":m.tier.value if m.tier else None,"points_balance":m.points_balance,"points_earned":m.points_earned,
            "points_redeemed":m.points_redeemed,"lifetime_value":round(m.lifetime_value or 0,2),"status":m.status,
            "home_branch":m.home_branch,"nationality":m.nationality,"enrolled_at":_iso(m.enrolled_at),"last_activity":_iso(m.last_activity)}

loyalty_router=APIRouter(prefix="/loyalty", tags=["loyalty"])
@loyalty_router.get("/members")
async def list_members(page:int=Query(1,ge=1), limit:int=Query(60,le=300), tier:Optional[str]=None,
        status:Optional[str]=None, search:Optional[str]=None, db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(Member).order_by(Member.points_balance.desc())
    if tier: q=q.where(Member.tier==tier)
    if status: q=q.where(Member.status==status)
    if search: q=q.where((Member.name.ilike(f"%{search}%"))|(Member.member_ref.ilike(f"%{search}%"))|(Member.email.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_member_dict(m) for m in rows]}
@loyalty_router.post("/members", dependencies=[Depends(require_analyst)])
async def create_member(data:MemberIn, db:AsyncSession=Depends(get_db)):
    n=(await db.execute(select(func.count()).select_from(Member))).scalar() or 0
    m=Member(**data.model_dump(), member_ref=f"LYL{100001+n}", points_earned=data.points_balance or 0, enrolled_at=datetime.utcnow())
    db.add(m); await db.commit(); await db.refresh(m); return _member_dict(m)
@loyalty_router.patch("/members/{mid}", dependencies=[Depends(require_analyst)])
async def update_member(mid:int, data:MemberPatch, db:AsyncSession=Depends(get_db)):
    m=(await db.execute(select(Member).where(Member.id==mid))).scalar_one_or_none()
    if not m: raise HTTPException(status_code=404, detail="Member not found")
    for k,v in data.model_dump(exclude_none=True).items(): setattr(m,k,v)
    await db.commit(); await db.refresh(m); return _member_dict(m)
@loyalty_router.delete("/members/{mid}", dependencies=[Depends(require_analyst)])
async def delete_member(mid:int, db:AsyncSession=Depends(get_db)):
    m=(await db.execute(select(Member).where(Member.id==mid))).scalar_one_or_none()
    if not m: raise HTTPException(status_code=404, detail="Member not found")
    await db.delete(m); await db.commit(); return {"ok":True}
@loyalty_router.get("/analytics")
async def loyalty_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    ms=(await db.execute(select(Member))).scalars().all()
    rs=(await db.execute(select(Redemption))).scalars().all()
    issued=sum(m.points_earned or 0 for m in ms); redeemed=sum(m.points_redeemed or 0 for m in ms)
    bal=sum(m.points_balance or 0 for m in ms)
    branch={}
    for m in ms: branch[m.home_branch or "—"]=branch.get(m.home_branch or "—",0)+1
    top=sorted(ms, key=lambda m:-(m.points_balance or 0))[:10]
    recent=sorted(rs, key=lambda r:r.at or datetime.min, reverse=True)[:12]
    return {"total_members":len(ms),"active":len([m for m in ms if m.status=="active"]),
        "points_issued":issued,"points_redeemed":redeemed,"points_balance":bal,
        "points_liability_omr":round(bal*0.01,2),"redemption_rate":round(redeemed/max(1,issued)*100,1),
        "avg_balance":round(bal/max(1,len(ms)),0),"total_redemptions":len(rs),
        "redemption_value_omr":round(sum(r.value_omr or 0 for r in rs),2),
        "by_tier":_cb(ms, lambda m:m.tier.value if m.tier else None),
        "by_status":_cb(ms, lambda m:m.status),
        "by_branch":[{"name":k,"count":v} for k,v in sorted(branch.items(), key=lambda x:-x[1])],
        "enroll_trend":_monthly_count(ms, lambda m:m.enrolled_at),
        "top_members":[{"name":m.name,"tier":m.tier.value,"points":m.points_balance,"ltv":round(m.lifetime_value or 0,2)} for m in top],
        "recent_redemptions":[{"member_ref":r.member_ref,"reward":r.reward,"points":r.points,"value_omr":round(r.value_omr or 0,2),"at":_iso(r.at)} for r in recent]}
async def seed_loyalty():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Member).limit(1))).scalar_one_or_none(): return
        branches=["Ruwi","Salalah","Sohar","Nizwa","Seeb"]; nats=["Indian","Pakistani","Filipino","Egyptian","Omani","Bangladeshi"]
        rewards=["Fee Waiver","Cashback OMR 5","Cashback OMR 10","Better FX Rate","Gift Voucher","Priority Service"]
        base=datetime.utcnow()-timedelta(days=900); ms=[]
        for i in range(220):
            earned=random.randint(200,60000); redeemed=random.randint(0,int(earned*0.6)); bal=earned-redeemed
            tier=Tier.platinum if earned>40000 else Tier.gold if earned>18000 else Tier.silver if earned>6000 else Tier.bronze
            en=base+timedelta(days=random.randint(0,880))
            ms.append(Member(member_ref=f"LYL{100001+i}", name=f"Member {1000+i}", email=f"m{1000+i}@example.com",
                phone=f"+9689{random.randint(1000000,9999999)}", tier=tier, points_balance=bal, points_earned=earned,
                points_redeemed=redeemed, lifetime_value=round(earned*random.uniform(0.03,0.08),2),
                status=random.choices(["active","inactive","churned"],weights=[78,15,7])[0],
                home_branch=random.choice(branches), nationality=random.choice(nats), enrolled_at=en,
                last_activity=en+timedelta(days=random.randint(0,300))))
        db.add_all(ms); await db.commit()
        rds=[]
        for i in range(260):
            m=random.choice(ms); pts=random.choice([500,1000,2000,3000,5000])
            rds.append(Redemption(member_ref=m.member_ref, reward=random.choice(rewards), points=pts,
                value_omr=round(pts*0.01,2), status=random.choice(["redeemed","redeemed","pending"]),
                at=base+timedelta(days=random.randint(30,880))))
        db.add_all(rds); await db.commit()

# ======================================================================
# MARKETING MANAGEMENT
# ======================================================================
class MktChannel(str, enum.Enum):
    email="email"; sms="sms"; social="social"; push="push"; whatsapp="whatsapp"; branch="branch"
class Campaign(Base):
    __tablename__="mkt_campaigns"
    id=Column(Integer, primary_key=True, index=True)
    campaign_ref=Column(String, unique=True, index=True); name=Column(String, index=True)
    channel=Column(Enum(MktChannel), default=MktChannel.email, index=True)
    status=Column(String, default="active", index=True); objective=Column(String, default="acquisition")
    budget=Column(Float, default=0.0); spent=Column(Float, default=0.0); audience=Column(Integer, default=0)
    sent=Column(Integer, default=0); opened=Column(Integer, default=0); clicked=Column(Integer, default=0)
    converted=Column(Integer, default=0); revenue=Column(Float, default=0.0); owner=Column(String, default="")
    start_date=Column(DateTime, nullable=True); end_date=Column(DateTime, nullable=True)
    created_at=Column(DateTime, default=datetime.utcnow, index=True)
class CampaignIn(BaseModel):
    name:str; channel:MktChannel=MktChannel.email; status:Optional[str]="active"; objective:Optional[str]="acquisition"
    budget:Optional[float]=0.0; spent:Optional[float]=0.0; audience:Optional[int]=0; sent:Optional[int]=0
    opened:Optional[int]=0; clicked:Optional[int]=0; converted:Optional[int]=0; revenue:Optional[float]=0.0; owner:Optional[str]=""
class CampaignPatch(BaseModel):
    name:Optional[str]=None; channel:Optional[MktChannel]=None; status:Optional[str]=None; objective:Optional[str]=None
    budget:Optional[float]=None; spent:Optional[float]=None; audience:Optional[int]=None; sent:Optional[int]=None
    opened:Optional[int]=None; clicked:Optional[int]=None; converted:Optional[int]=None; revenue:Optional[float]=None; owner:Optional[str]=None
def _camp_dict(c):
    return {"id":c.id,"campaign_ref":c.campaign_ref,"name":c.name,"channel":c.channel.value if c.channel else None,
        "status":c.status,"objective":c.objective,"budget":round(c.budget or 0,2),"spent":round(c.spent or 0,2),
        "audience":c.audience,"sent":c.sent,"opened":c.opened,"clicked":c.clicked,"converted":c.converted,
        "revenue":round(c.revenue or 0,2),"roi":round(((c.revenue or 0)-(c.spent or 0))/max(1,(c.spent or 1))*100,1),
        "open_rate":round((c.opened or 0)/max(1,c.sent or 1)*100,1),"ctr":round((c.clicked or 0)/max(1,c.opened or 1)*100,1),
        "conv_rate":round((c.converted or 0)/max(1,c.clicked or 1)*100,1),"owner":c.owner,
        "start_date":_iso(c.start_date),"end_date":_iso(c.end_date)}
mkt_router=APIRouter(prefix="/marketing", tags=["marketing"])
@mkt_router.get("/campaigns")
async def list_campaigns(page:int=Query(1,ge=1), limit:int=Query(60,le=200), channel:Optional[str]=None,
        status:Optional[str]=None, search:Optional[str]=None, db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(Campaign).order_by(Campaign.created_at.desc())
    if channel: q=q.where(Campaign.channel==channel)
    if status: q=q.where(Campaign.status==status)
    if search: q=q.where((Campaign.name.ilike(f"%{search}%"))|(Campaign.campaign_ref.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_camp_dict(c) for c in rows]}
@mkt_router.post("/campaigns", dependencies=[Depends(require_analyst)])
async def create_campaign(data:CampaignIn, db:AsyncSession=Depends(get_db)):
    n=(await db.execute(select(func.count()).select_from(Campaign))).scalar() or 0
    c=Campaign(**data.model_dump(), campaign_ref=f"CMP{1001+n}", start_date=datetime.utcnow(), created_at=datetime.utcnow())
    db.add(c); await db.commit(); await db.refresh(c); return _camp_dict(c)
@mkt_router.patch("/campaigns/{cid}", dependencies=[Depends(require_analyst)])
async def update_campaign(cid:int, data:CampaignPatch, db:AsyncSession=Depends(get_db)):
    c=(await db.execute(select(Campaign).where(Campaign.id==cid))).scalar_one_or_none()
    if not c: raise HTTPException(status_code=404, detail="Campaign not found")
    for k,v in data.model_dump(exclude_none=True).items(): setattr(c,k,v)
    await db.commit(); await db.refresh(c); return _camp_dict(c)
@mkt_router.delete("/campaigns/{cid}", dependencies=[Depends(require_analyst)])
async def delete_campaign(cid:int, db:AsyncSession=Depends(get_db)):
    c=(await db.execute(select(Campaign).where(Campaign.id==cid))).scalar_one_or_none()
    if not c: raise HTTPException(status_code=404, detail="Campaign not found")
    await db.delete(c); await db.commit(); return {"ok":True}
@mkt_router.get("/analytics")
async def marketing_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    cs=(await db.execute(select(Campaign))).scalars().all()
    spend=sum(c.spent or 0 for c in cs); rev=sum(c.revenue or 0 for c in cs)
    chan={}
    for c in cs:
        k=c.channel.value if c.channel else "—"; d=chan.setdefault(k,{"name":k,"spend":0,"revenue":0,"count":0})
        d["spend"]+=c.spent or 0; d["revenue"]+=c.revenue or 0; d["count"]+=1
    for v in chan.values(): v["spend"]=round(v["spend"],2); v["revenue"]=round(v["revenue"],2)
    funnel=[{"name":"Sent","count":sum(c.sent or 0 for c in cs)},{"name":"Opened","count":sum(c.opened or 0 for c in cs)},
            {"name":"Clicked","count":sum(c.clicked or 0 for c in cs)},{"name":"Converted","count":sum(c.converted or 0 for c in cs)}]
    top=sorted(cs, key=lambda c:-(c.revenue or 0))[:8]
    return {"total_campaigns":len(cs),"active":len([c for c in cs if c.status=="active"]),
        "total_spend":round(spend,2),"total_revenue":round(rev,2),"roi":round((rev-spend)/max(1,spend)*100,1),
        "total_conversions":sum(c.converted or 0 for c in cs),
        "avg_open_rate":round(sum(c.opened or 0 for c in cs)/max(1,sum(c.sent or 0 for c in cs))*100,1),
        "avg_ctr":round(sum(c.clicked or 0 for c in cs)/max(1,sum(c.opened or 0 for c in cs))*100,1),
        "avg_conv_rate":round(sum(c.converted or 0 for c in cs)/max(1,sum(c.clicked or 0 for c in cs))*100,1),
        "by_channel":list(chan.values()),"funnel":funnel,
        "by_status":_cb(cs, lambda c:c.status),
        "spend_trend":_monthly_count(cs, lambda c:c.created_at),
        "top_campaigns":[{"name":c.name,"channel":c.channel.value,"spent":round(c.spent or 0,2),"revenue":round(c.revenue or 0,2),"roi":round(((c.revenue or 0)-(c.spent or 0))/max(1,(c.spent or 1))*100,1)} for c in top]}
async def seed_marketing():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Campaign).limit(1))).scalar_one_or_none(): return
        names=["Ramadan Remittance","Diwali Cashback","Summer FX","New Customer Bonus","Referral Drive","Corporate Outreach",
               "Salalah Festival","Back to School","Year End Rewards","Digital Onboarding","Gold Tier Upgrade","Weekend Rates"]
        owners=["Marketing Team","Growth","Digital","Branch Mktg"]; objs=["acquisition","retention","reactivation","awareness"]
        base=datetime.utcnow()-timedelta(days=540); cs=[]
        for i in range(64):
            ch=random.choice(list(MktChannel)); aud=random.randint(2000,80000)
            sent=int(aud*random.uniform(0.6,1.0)); opened=int(sent*random.uniform(0.15,0.55))
            clicked=int(opened*random.uniform(0.08,0.35)); conv=int(clicked*random.uniform(0.05,0.28))
            budget=round(random.uniform(500,15000),2); spent=round(budget*random.uniform(0.5,1.05),2)
            rev=round(conv*random.uniform(20,120),2); st=random.choices(["active","completed","paused","draft"],weights=[30,45,15,10])[0]
            sd=base+timedelta(days=random.randint(0,500))
            cs.append(Campaign(campaign_ref=f"CMP{1001+i}", name=f"{random.choice(names)} {2025+random.randint(0,1)}",
                channel=ch, status=st, objective=random.choice(objs), budget=budget, spent=spent, audience=aud,
                sent=sent, opened=opened, clicked=clicked, converted=conv, revenue=rev, owner=random.choice(owners),
                start_date=sd, end_date=sd+timedelta(days=random.randint(7,45)), created_at=sd))
        db.add_all(cs); await db.commit()

# ======================================================================
# AI VIDEO ANALYTICS
# ======================================================================
class VEvent(str, enum.Enum):
    footfall="footfall"; queue_length="queue_length"; wait_time="wait_time"; loitering="loitering"
    intrusion="intrusion"; tailgating="tailgating"; face_match="face_match"; ppe_violation="ppe_violation"
    anomaly="anomaly"; camera_offline="camera_offline"
class VideoEvent(Base):
    __tablename__="video_events"
    id=Column(Integer, primary_key=True, index=True)
    event_ref=Column(String, unique=True, index=True); branch=Column(String, index=True); camera=Column(String)
    event_type=Column(Enum(VEvent), default=VEvent.footfall, index=True)
    severity=Column(String, default="info", index=True); confidence=Column(Float, default=0.9)
    value=Column(Float, default=0.0); status=Column(String, default="new", index=True)
    note=Column(String, default=""); detected_at=Column(DateTime, default=datetime.utcnow, index=True)
class VideoPatch(BaseModel):
    status: Optional[str]=None; note: Optional[str]=None
def _ve_dict(v):
    return {"id":v.id,"event_ref":v.event_ref,"branch":v.branch,"camera":v.camera,
        "event_type":v.event_type.value if v.event_type else None,"severity":v.severity,
        "confidence":round(v.confidence or 0,2),"value":round(v.value or 0,1),"status":v.status,
        "note":v.note,"detected_at":_iso(v.detected_at)}
video_router=APIRouter(prefix="/video", tags=["video-analytics"])
@video_router.get("/events")
async def list_events(page:int=Query(1,ge=1), limit:int=Query(80,le=400), branch:Optional[str]=None,
        event_type:Optional[str]=None, severity:Optional[str]=None, status:Optional[str]=None,
        db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(VideoEvent).order_by(VideoEvent.detected_at.desc())
    if branch: q=q.where(VideoEvent.branch==branch)
    if event_type: q=q.where(VideoEvent.event_type==event_type)
    if severity: q=q.where(VideoEvent.severity==severity)
    if status: q=q.where(VideoEvent.status==status)
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_ve_dict(v) for v in rows]}
@video_router.patch("/events/{eid}", dependencies=[Depends(require_analyst)])
async def update_event(eid:int, data:VideoPatch, db:AsyncSession=Depends(get_db)):
    v=(await db.execute(select(VideoEvent).where(VideoEvent.id==eid))).scalar_one_or_none()
    if not v: raise HTTPException(status_code=404, detail="Event not found")
    for k,val in data.model_dump(exclude_none=True).items(): setattr(v,k,val)
    await db.commit(); await db.refresh(v); return _ve_dict(v)
@video_router.get("/analytics")
async def video_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    es=(await db.execute(select(VideoEvent))).scalars().all()
    foot=[e for e in es if e.event_type==VEvent.footfall]; q=[e for e in es if e.event_type==VEvent.queue_length]
    wt=[e for e in es if e.event_type==VEvent.wait_time]
    alerts=[e for e in es if e.severity in ("warning","critical")]
    hours={}
    for e in es:
        if e.detected_at: h=e.detected_at.hour; hours[h]=hours.get(h,0)+1
    peak=[{"name":f"{k:02d}:00","count":v} for k,v in sorted(hours.items())]
    recent_alerts=sorted(alerts, key=lambda e:e.detected_at or datetime.min, reverse=True)[:15]
    cams=set((e.branch,e.camera) for e in es)
    offline=len([e for e in es if e.event_type==VEvent.camera_offline and e.status!="resolved"])
    return {"total_events":len(es),"critical":len([e for e in es if e.severity=="critical"]),
        "unresolved":len([e for e in es if e.status!="resolved"]),"alerts":len(alerts),
        "cameras":len(cams),"cameras_offline":offline,
        "avg_footfall":round(sum(e.value for e in foot)/max(1,len(foot)),0),
        "avg_queue":round(sum(e.value for e in q)/max(1,len(q)),1),
        "avg_wait_sec":round(sum(e.value for e in wt)/max(1,len(wt)),0),
        "by_type":_cb(es, lambda e:e.event_type.value if e.event_type else None),
        "by_branch":_cb(es, lambda e:e.branch),
        "by_severity":_cb(es, lambda e:e.severity),
        "events_trend":_monthly_count(es, lambda e:e.detected_at),
        "peak_hours":peak,
        "recent_alerts":[_ve_dict(e) for e in recent_alerts]}
async def seed_video():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(VideoEvent).limit(1))).scalar_one_or_none(): return
        branches=["Ruwi","Salalah","Sohar","Nizwa","Seeb"]; es=[]; base=datetime.utcnow()-timedelta(days=120)
        for i in range(420):
            br=random.choice(branches); et=random.choices(list(VEvent),
                weights=[26,18,14,6,3,4,8,6,9,6])[0]
            sev="info"; val=0.0
            if et==VEvent.footfall: val=random.randint(20,400)
            elif et==VEvent.queue_length: val=random.randint(1,18); sev="warning" if val>10 else "info"
            elif et==VEvent.wait_time: val=random.randint(30,900); sev="warning" if val>420 else "info"
            elif et in (VEvent.intrusion,VEvent.tailgating): sev=random.choice(["warning","critical"]); val=1
            elif et==VEvent.ppe_violation: sev="warning"; val=1
            elif et==VEvent.anomaly: sev=random.choice(["warning","critical"]); val=1
            elif et==VEvent.loitering: sev="warning"; val=random.randint(60,600)
            elif et==VEvent.camera_offline: sev="critical"; val=1
            elif et==VEvent.face_match: sev="info"; val=1
            st="resolved" if random.random()<0.6 else random.choice(["new","ack"])
            es.append(VideoEvent(event_ref=f"VID{100001+i}", branch=br, camera=f"CAM-{br[:3].upper()}-{random.randint(1,6)}",
                event_type=et, severity=sev, confidence=round(random.uniform(0.72,0.99),2), value=val, status=st,
                note=("Auto-detected by edge AI" if sev!="info" else ""),
                detected_at=base+timedelta(days=random.randint(0,118), hours=random.randint(7,21), minutes=random.randint(0,59))))
        db.add_all(es); await db.commit()

# ======================================================================
# FACILITY MANAGEMENT
# ======================================================================
class AssetStatus(str, enum.Enum):
    operational="operational"; maintenance="maintenance"; down="down"; retired="retired"
class Asset(Base):
    __tablename__="fac_assets"
    id=Column(Integer, primary_key=True, index=True)
    asset_ref=Column(String, unique=True, index=True); name=Column(String, index=True)
    type=Column(String, index=True); branch=Column(String, index=True)
    status=Column(Enum(AssetStatus), default=AssetStatus.operational, index=True)
    criticality=Column(String, default="medium"); health_score=Column(Integer, default=90)
    install_date=Column(DateTime, nullable=True); last_service=Column(DateTime, nullable=True); next_service=Column(DateTime, nullable=True)
class WorkOrder(Base):
    __tablename__="fac_workorders"
    id=Column(Integer, primary_key=True, index=True)
    wo_ref=Column(String, unique=True, index=True); title=Column(String, index=True); asset_ref=Column(String, index=True)
    type=Column(String, default="corrective"); priority=Column(String, default="medium", index=True)
    status=Column(String, default="open", index=True); assignee=Column(String, default="")
    cost=Column(Float, default=0.0); downtime_hrs=Column(Float, default=0.0)
    created_at=Column(DateTime, default=datetime.utcnow, index=True); due_date=Column(DateTime, nullable=True); completed_at=Column(DateTime, nullable=True)
class WorkOrderIn(BaseModel):
    title:str; asset_ref:Optional[str]=""; type:Optional[str]="corrective"; priority:Optional[str]="medium"
    status:Optional[str]="open"; assignee:Optional[str]=""; cost:Optional[float]=0.0; downtime_hrs:Optional[float]=0.0; due_date:Optional[str]=None
class WorkOrderPatch(BaseModel):
    title:Optional[str]=None; asset_ref:Optional[str]=None; type:Optional[str]=None; priority:Optional[str]=None
    status:Optional[str]=None; assignee:Optional[str]=None; cost:Optional[float]=None; downtime_hrs:Optional[float]=None; due_date:Optional[str]=None
def _asset_dict(a):
    return {"id":a.id,"asset_ref":a.asset_ref,"name":a.name,"type":a.type,"branch":a.branch,
        "status":a.status.value if a.status else None,"criticality":a.criticality,"health_score":a.health_score,
        "install_date":_iso(a.install_date),"last_service":_iso(a.last_service),"next_service":_iso(a.next_service)}
def _wo_dict(w):
    return {"id":w.id,"wo_ref":w.wo_ref,"title":w.title,"asset_ref":w.asset_ref,"type":w.type,"priority":w.priority,
        "status":w.status,"assignee":w.assignee,"cost":round(w.cost or 0,2),"downtime_hrs":round(w.downtime_hrs or 0,1),
        "created_at":_iso(w.created_at),"due_date":_iso(w.due_date),"completed_at":_iso(w.completed_at)}
facility_router=APIRouter(prefix="/facility", tags=["facility"])
@facility_router.get("/assets")
async def list_assets(page:int=Query(1,ge=1), limit:int=Query(100,le=300), status:Optional[str]=None,
        type:Optional[str]=None, branch:Optional[str]=None, search:Optional[str]=None,
        db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(Asset).order_by(Asset.health_score.asc())
    if status: q=q.where(Asset.status==status)
    if type: q=q.where(Asset.type==type)
    if branch: q=q.where(Asset.branch==branch)
    if search: q=q.where((Asset.name.ilike(f"%{search}%"))|(Asset.asset_ref.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_asset_dict(a) for a in rows]}
@facility_router.get("/workorders")
async def list_wos(page:int=Query(1,ge=1), limit:int=Query(100,le=300), status:Optional[str]=None,
        type:Optional[str]=None, priority:Optional[str]=None, search:Optional[str]=None,
        db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(WorkOrder).order_by(WorkOrder.created_at.desc())
    if status: q=q.where(WorkOrder.status==status)
    if type: q=q.where(WorkOrder.type==type)
    if priority: q=q.where(WorkOrder.priority==priority)
    if search: q=q.where((WorkOrder.title.ilike(f"%{search}%"))|(WorkOrder.wo_ref.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_wo_dict(w) for w in rows]}
@facility_router.post("/workorders", dependencies=[Depends(require_analyst)])
async def create_wo(data:WorkOrderIn, db:AsyncSession=Depends(get_db)):
    n=(await db.execute(select(func.count()).select_from(WorkOrder))).scalar() or 0
    p=data.model_dump(); due=_ddate(p.pop("due_date",None))
    w=WorkOrder(**p, wo_ref=f"WO{10001+n}", due_date=due, created_at=datetime.utcnow())
    db.add(w); await db.commit(); await db.refresh(w); return _wo_dict(w)
@facility_router.patch("/workorders/{wid}", dependencies=[Depends(require_analyst)])
async def update_wo(wid:int, data:WorkOrderPatch, db:AsyncSession=Depends(get_db)):
    w=(await db.execute(select(WorkOrder).where(WorkOrder.id==wid))).scalar_one_or_none()
    if not w: raise HTTPException(status_code=404, detail="Work order not found")
    ch=data.model_dump(exclude_none=True)
    if "due_date" in ch: w.due_date=_ddate(ch.pop("due_date"))
    if ch.get("status")=="done" and not w.completed_at: w.completed_at=datetime.utcnow()
    for k,v in ch.items(): setattr(w,k,v)
    await db.commit(); await db.refresh(w); return _wo_dict(w)
@facility_router.delete("/workorders/{wid}", dependencies=[Depends(require_analyst)])
async def delete_wo(wid:int, db:AsyncSession=Depends(get_db)):
    w=(await db.execute(select(WorkOrder).where(WorkOrder.id==wid))).scalar_one_or_none()
    if not w: raise HTTPException(status_code=404, detail="Work order not found")
    await db.delete(w); await db.commit(); return {"ok":True}
@facility_router.get("/analytics")
async def facility_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    ax=(await db.execute(select(Asset))).scalars().all()
    ws=(await db.execute(select(WorkOrder))).scalars().all()
    now=datetime.utcnow()
    done=[w for w in ws if w.status=="done"]
    upcoming=[a for a in ax if a.next_service and 0<=(a.next_service-now).days<=30]
    return {"total_assets":len(ax),"operational":len([a for a in ax if a.status==AssetStatus.operational]),
        "in_maintenance":len([a for a in ax if a.status==AssetStatus.maintenance]),
        "down":len([a for a in ax if a.status==AssetStatus.down]),
        "avg_health":round(sum(a.health_score or 0 for a in ax)/max(1,len(ax)),0),
        "wo_open":len([w for w in ws if w.status=="open"]),"wo_in_progress":len([w for w in ws if w.status=="in_progress"]),
        "wo_done":len(done),"total_maint_cost":round(sum(w.cost or 0 for w in ws),2),
        "avg_mttr_hrs":round(sum(w.downtime_hrs or 0 for w in done)/max(1,len(done)),1),
        "upcoming_maintenance":len(upcoming),
        "assets_by_status":_cb(ax, lambda a:a.status.value if a.status else None),
        "assets_by_type":_cb(ax, lambda a:a.type),
        "assets_by_branch":_cb(ax, lambda a:a.branch),
        "wo_by_status":_cb(ws, lambda w:w.status),
        "wo_by_type":_cb(ws, lambda w:w.type),
        "wo_by_priority":_cb(ws, lambda w:w.priority),
        "wo_trend":_monthly_count(ws, lambda w:w.created_at),
        "upcoming_list":sorted([{"asset_ref":a.asset_ref,"name":a.name,"branch":a.branch,"next_service":_iso(a.next_service),"health_score":a.health_score} for a in upcoming], key=lambda x:x["next_service"] or "")[:20],
        "critical_assets":[_asset_dict(a) for a in sorted(ax, key=lambda a:a.health_score or 0)[:10]]}
async def seed_facility():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Asset).limit(1))).scalar_one_or_none(): return
        branches=["Ruwi","Salalah","Sohar","Nizwa","Seeb","Head Office"]
        types=["HVAC","Generator","CCTV","UPS","Counter System","Network","Vehicle","Access Control"]
        techs=["FM Team A","FM Team B","Vendor - Cool Tech","Vendor - PowerGen","IT Support"]
        base=datetime.utcnow()-timedelta(days=1000); ax=[]
        for i in range(90):
            st=random.choices(list(AssetStatus), weights=[74,12,8,6])[0]
            health=random.randint(30,99) if st==AssetStatus.operational else random.randint(10,60)
            inst=base+timedelta(days=random.randint(0,900)); ls=datetime.utcnow()-timedelta(days=random.randint(5,200))
            ax.append(Asset(asset_ref=f"AST{1001+i}", name=f"{random.choice(types)} Unit {i+1}", type=random.choice(types),
                branch=random.choice(branches), status=st, criticality=random.choice(["low","medium","high","high"]),
                health_score=health, install_date=inst, last_service=ls,
                next_service=datetime.utcnow()+timedelta(days=random.randint(-20,120))))
        db.add_all(ax); await db.commit()
        ws=[]
        for i in range(160):
            a=random.choice(ax); ty=random.choice(["preventive","corrective","inspection"])
            st=random.choices(["open","in_progress","on_hold","done"], weights=[22,20,8,50])[0]
            cd=base+timedelta(days=random.randint(200,990)); comp=None; dt=0.0; cost=round(random.uniform(20,1800),2)
            if st=="done": comp=cd+timedelta(hours=random.randint(1,72)); dt=round(random.uniform(0.5,36),1)
            ws.append(WorkOrder(wo_ref=f"WO{10001+i}", title=f"{ty.title()} - {a.name}", asset_ref=a.asset_ref, type=ty,
                priority=random.choices(["low","medium","high","urgent"], weights=[25,40,25,10])[0], status=st,
                assignee=random.choice(techs), cost=cost, downtime_hrs=dt, created_at=cd,
                due_date=cd+timedelta(days=random.randint(1,14)), completed_at=comp))
        db.add_all(ws); await db.commit()

# ======================================================================
# OCR & INTELLIGENT DOCUMENT PROCESSING
# ======================================================================
class OcrJobStatus(str, enum.Enum):
    queued="queued"; processing="processing"; completed="completed"; failed="failed"; needs_review="needs_review"
class OcrJob(Base):
    __tablename__="ocr_jobs"
    id=Column(Integer, primary_key=True, index=True)
    job_ref=Column(String, unique=True, index=True); doc_ref=Column(String, default="", index=True)
    doc_class=Column(String, index=True); file_type=Column(String, default="pdf"); pages=Column(Integer, default=1)
    status=Column(Enum(OcrJobStatus), default=OcrJobStatus.queued, index=True)
    confidence=Column(Float, default=0.0); fields_extracted=Column(Integer, default=0); fields_total=Column(Integer, default=0)
    language=Column(String, default="en"); processing_ms=Column(Integer, default=0)
    straight_through=Column(Boolean, default=False); reviewer=Column(String, default="")
    created_at=Column(DateTime, default=datetime.utcnow, index=True); completed_at=Column(DateTime, nullable=True)
def _ocr_dict(j):
    return {"id":j.id,"job_ref":j.job_ref,"doc_ref":j.doc_ref,"doc_class":j.doc_class,"file_type":j.file_type,
        "pages":j.pages,"status":j.status.value if j.status else None,"confidence":round(j.confidence or 0,3),
        "fields_extracted":j.fields_extracted,"fields_total":j.fields_total,
        "accuracy":round((j.fields_extracted or 0)/max(1,j.fields_total or 1)*100,1),
        "language":j.language,"processing_ms":j.processing_ms,"straight_through":j.straight_through,
        "reviewer":j.reviewer,"created_at":_iso(j.created_at),"completed_at":_iso(j.completed_at)}
ocr_router=APIRouter(prefix="/ocr", tags=["ocr-idp"])
@ocr_router.get("/jobs")
async def list_ocr(page:int=Query(1,ge=1), limit:int=Query(80,le=400), status:Optional[str]=None,
        doc_class:Optional[str]=None, search:Optional[str]=None, db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(OcrJob).order_by(OcrJob.created_at.desc())
    if status: q=q.where(OcrJob.status==status)
    if doc_class: q=q.where(OcrJob.doc_class==doc_class)
    if search: q=q.where((OcrJob.job_ref.ilike(f"%{search}%"))|(OcrJob.doc_ref.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_ocr_dict(j) for j in rows]}
@ocr_router.get("/analytics")
async def ocr_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    js=(await db.execute(select(OcrJob))).scalars().all()
    done=[j for j in js if j.status==OcrJobStatus.completed]
    stp=[j for j in done if j.straight_through]
    return {"total_jobs":len(js),"completed":len(done),"needs_review":len([j for j in js if j.status==OcrJobStatus.needs_review]),
        "failed":len([j for j in js if j.status==OcrJobStatus.failed]),"queued":len([j for j in js if j.status==OcrJobStatus.queued]),
        "processing":len([j for j in js if j.status==OcrJobStatus.processing]),
        "avg_confidence":round(sum(j.confidence or 0 for j in done)/max(1,len(done))*100,1),
        "straight_through_rate":round(len(stp)/max(1,len(done))*100,1),
        "avg_processing_ms":round(sum(j.processing_ms or 0 for j in done)/max(1,len(done)),0),
        "extraction_accuracy":round(sum((j.fields_extracted or 0)/max(1,j.fields_total or 1) for j in done)/max(1,len(done))*100,1),
        "total_pages":sum(j.pages or 0 for j in js),
        "by_doc_class":_cb(js, lambda j:j.doc_class),
        "by_status":_cb(js, lambda j:j.status.value if j.status else None),
        "by_language":_cb(js, lambda j:j.language),
        "throughput_trend":_monthly_count(js, lambda j:j.created_at),
        "recent":[_ocr_dict(j) for j in sorted(js, key=lambda j:j.created_at or datetime.min, reverse=True)[:15]]}
async def seed_ocr():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(OcrJob).limit(1))).scalar_one_or_none(): return
        classes={"ID Card":6,"Passport":8,"Invoice":10,"Bank Statement":14,"KYC Form":9,"Contract":16,"Cheque":5,"Utility Bill":6}
        langs=["en","en","en","ar","hi","ur"]; revs=["A. Nair","F. Kumar","S. Ali","H. Said"]
        base=datetime.utcnow()-timedelta(days=180); js=[]
        for i in range(300):
            dc=random.choice(list(classes.keys())); ftot=classes[dc]
            st=random.choices(list(OcrJobStatus), weights=[6,4,70,5,15])[0]
            conf=round(random.uniform(0.78,0.995),3) if st in (OcrJobStatus.completed,OcrJobStatus.needs_review) else 0.0
            fext=ftot if (st==OcrJobStatus.completed and conf>0.9) else int(ftot*random.uniform(0.5,0.95)) if st in (OcrJobStatus.completed,OcrJobStatus.needs_review) else 0
            stp=st==OcrJobStatus.completed and conf>=0.93 and fext==ftot
            cd=base+timedelta(days=random.randint(0,178), minutes=random.randint(0,1400))
            comp=cd+timedelta(seconds=random.randint(2,40)) if st in (OcrJobStatus.completed,OcrJobStatus.needs_review,OcrJobStatus.failed) else None
            js.append(OcrJob(job_ref=f"OCR{100001+i}", doc_ref=f"DOC-2025-{100001+random.randint(0,209)}", doc_class=dc,
                file_type=random.choice(["pdf","png","tiff","jpg"]), pages=random.randint(1,12), status=st, confidence=conf,
                fields_extracted=fext, fields_total=ftot, language=random.choice(langs),
                processing_ms=random.randint(800,32000) if comp else 0, straight_through=stp,
                reviewer=(random.choice(revs) if st==OcrJobStatus.needs_review else ""), created_at=cd, completed_at=comp))
        db.add_all(js); await db.commit()

# ======================================================================
# ENTERPRISE SEARCH (federated + analytics)
# ======================================================================
class SearchQuery(Base):
    __tablename__="search_queries"
    id=Column(Integer, primary_key=True, index=True)
    query=Column(String, index=True); user=Column(String, default=""); module=Column(String, default="all", index=True)
    results=Column(Integer, default=0); clicked_rank=Column(Integer, default=-1); latency_ms=Column(Integer, default=0)
    zero_results=Column(Boolean, default=False, index=True); at=Column(DateTime, default=datetime.utcnow, index=True)
search_router=APIRouter(prefix="/search", tags=["enterprise-search"])
@search_router.get("/query")
async def federated_search(q: str = Query(..., min_length=1), db:AsyncSession=Depends(get_db), u:User=Depends(get_current_user)):
    import time as _t; t0=_t.time(); term=f"%{q}%"; out={}
    docs=(await db.execute(select(Document).where((Document.title.ilike(term))|(Document.doc_ref.ilike(term))|(Document.tags.ilike(term))).limit(8))).scalars().all()
    out["documents"]=[{"ref":d.doc_ref,"title":d.title,"meta":f"{d.domain.value} · {d.category}","status":d.status.value} for d in docs]
    conts=(await db.execute(select(Contact).where((Contact.name.ilike(term))|(Contact.email.ilike(term))|(Contact.company.ilike(term))).limit(8))).scalars().all()
    out["customers"]=[{"ref":str(c.id),"title":c.name,"meta":c.company or c.email or "","status":c.status.value if c.status else ""} for c in conts]
    txns=(await db.execute(select(Transaction).where((Transaction.txn_ref.ilike(term))|(Transaction.customer_id.ilike(term))|(Transaction.corridor.ilike(term))).limit(8))).scalars().all()
    out["transactions"]=[{"ref":t.txn_ref,"title":t.customer_id,"meta":f"{t.foreign_currency or t.currency} {round(t.amount,2)} · {t.branch or ''}","status":t.status.value if t.status else ""} for t in txns]
    tks=(await db.execute(select(Ticket).where((Ticket.subject.ilike(term))|(Ticket.ref.ilike(term))).limit(8))).scalars().all()
    out["tickets"]=[{"ref":t.ref,"title":t.subject,"meta":f"{t.category} · {t.priority.value if t.priority else ''}","status":t.status.value if t.status else ""} for t in tks]
    total=sum(len(v) for v in out.values()); lat=int((_t.time()-t0)*1000)
    db.add(SearchQuery(query=q, user=u.full_name, module="all", results=total, latency_ms=max(1,lat), zero_results=(total==0), at=datetime.utcnow()))
    await db.commit()
    return {"query":q,"total":total,"latency_ms":max(1,lat),"groups":out}
@search_router.get("/analytics")
async def search_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    qs=(await db.execute(select(SearchQuery))).scalars().all()
    freq={}
    for s in qs: freq[s.query.lower()]=freq.get(s.query.lower(),0)+1
    top=[{"query":k,"count":v} for k,v in sorted(freq.items(), key=lambda x:-x[1])[:12]]
    zero=[{"query":k} for k in {s.query.lower() for s in qs if s.zero_results}][:12]
    clicks=[s for s in qs if s.clicked_rank>=0]
    nd=(await db.execute(select(func.count()).select_from(Document))).scalar() or 0
    nc=(await db.execute(select(func.count()).select_from(Contact))).scalar() or 0
    nt=(await db.execute(select(func.count()).select_from(Transaction))).scalar() or 0
    nk=(await db.execute(select(func.count()).select_from(Ticket))).scalar() or 0
    return {"total_searches":len(qs),"avg_latency_ms":round(sum(s.latency_ms or 0 for s in qs)/max(1,len(qs)),0),
        "zero_result_rate":round(len([s for s in qs if s.zero_results])/max(1,len(qs))*100,1),
        "click_through_rate":round(len(clicks)/max(1,len(qs))*100,1),
        "top_queries":top,"zero_result_queries":zero,
        "by_module":_cb(qs, lambda s:s.module),
        "searches_trend":_monthly_count(qs, lambda s:s.at),
        "indexed":[{"name":"Documents","count":nd},{"name":"Customers","count":nc},{"name":"Transactions","count":nt},{"name":"Tickets","count":nk}],
        "total_indexed":nd+nc+nt+nk}
async def seed_search():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(SearchQuery).limit(1))).scalar_one_or_none(): return
        terms=["KYC","license renewal","AML report","invoice","John","remittance","expired","gold tier","STR","audit",
               "passport","refund","Ruwi","corporate","settlement","xyz123notfound","policy","cheque","INR rate","complaint"]
        users=["Admin User","Adarsh Vasudevan","A. Nair","S. Ali"]; base=datetime.utcnow()-timedelta(days=90); qs=[]
        for i in range(520):
            term=random.choice(terms); zero=term=="xyz123notfound" or random.random()<0.08
            res=0 if zero else random.randint(1,40)
            qs.append(SearchQuery(query=term, user=random.choice(users), module=random.choice(["all","all","documents","customers","transactions"]),
                results=res, clicked_rank=(random.randint(0,5) if (not zero and random.random()<0.6) else -1),
                latency_ms=random.randint(8,180), zero_results=zero,
                at=base+timedelta(days=random.randint(0,88), minutes=random.randint(0,1400))))
        db.add_all(qs); await db.commit()

# ======================================================================
# AI RECOMMENDATION ENGINE
# ======================================================================
class RecoType(str, enum.Enum):
    next_best_action="next_best_action"; product_offer="product_offer"; corridor="corridor"
    retention_offer="retention_offer"; cross_sell="cross_sell"; reactivation="reactivation"
class Recommendation(Base):
    __tablename__="recommendations"
    id=Column(Integer, primary_key=True, index=True)
    rec_ref=Column(String, unique=True, index=True); customer=Column(String, index=True); segment=Column(String, index=True)
    rec_type=Column(Enum(RecoType), default=RecoType.next_best_action, index=True); item=Column(String)
    score=Column(Float, default=0.0); expected_uplift_omr=Column(Float, default=0.0)
    status=Column(String, default="served", index=True); reason=Column(String, default=""); model_version=Column(String, default="v2.3")
    created_at=Column(DateTime, default=datetime.utcnow, index=True); actioned_at=Column(DateTime, nullable=True)
class RecoPatch(BaseModel):
    status: Optional[str]=None
def _rec_dict(r):
    return {"id":r.id,"rec_ref":r.rec_ref,"customer":r.customer,"segment":r.segment,
        "rec_type":r.rec_type.value if r.rec_type else None,"item":r.item,"score":round(r.score or 0,3),
        "expected_uplift_omr":round(r.expected_uplift_omr or 0,2),"status":r.status,"reason":r.reason,
        "model_version":r.model_version,"created_at":_iso(r.created_at),"actioned_at":_iso(r.actioned_at)}
reco_router=APIRouter(prefix="/recommendations", tags=["recommendations"])
@reco_router.get("/list")
async def list_recos(page:int=Query(1,ge=1), limit:int=Query(80,le=300), rec_type:Optional[str]=None,
        status:Optional[str]=None, segment:Optional[str]=None, search:Optional[str]=None,
        db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    q=select(Recommendation).order_by(Recommendation.score.desc())
    if rec_type: q=q.where(Recommendation.rec_type==rec_type)
    if status: q=q.where(Recommendation.status==status)
    if segment: q=q.where(Recommendation.segment==segment)
    if search: q=q.where((Recommendation.customer.ilike(f"%{search}%"))|(Recommendation.item.ilike(f"%{search}%")))
    total=(await db.execute(select(func.count()).select_from(q.subquery()))).scalar()
    rows=(await db.execute(q.offset((page-1)*limit).limit(limit))).scalars().all()
    return {"total":total,"page":page,"limit":limit,"items":[_rec_dict(r) for r in rows]}
@reco_router.patch("/{rid}", dependencies=[Depends(require_analyst)])
async def action_reco(rid:int, data:RecoPatch, db:AsyncSession=Depends(get_db)):
    r=(await db.execute(select(Recommendation).where(Recommendation.id==rid))).scalar_one_or_none()
    if not r: raise HTTPException(status_code=404, detail="Recommendation not found")
    if data.status: r.status=data.status; r.actioned_at=datetime.utcnow()
    await db.commit(); await db.refresh(r); return _rec_dict(r)
@reco_router.get("/analytics")
async def reco_analytics(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    rs=(await db.execute(select(Recommendation))).scalars().all()
    served=[r for r in rs if r.status!="expired"]; acc=[r for r in rs if r.status=="accepted"]; dis=[r for r in rs if r.status=="dismissed"]
    return {"total":len(rs),"served":len(served),"accepted":len(acc),"dismissed":len(dis),
        "pending":len([r for r in rs if r.status=="served"]),
        "acceptance_rate":round(len(acc)/max(1,len(acc)+len(dis))*100,1),
        "projected_uplift_omr":round(sum(r.expected_uplift_omr or 0 for r in served),2),
        "realized_uplift_omr":round(sum(r.expected_uplift_omr or 0 for r in acc),2),
        "avg_score":round(sum(r.score or 0 for r in rs)/max(1,len(rs)),3),"model_version":"v2.3",
        "by_type":_cb(rs, lambda r:r.rec_type.value if r.rec_type else None),
        "by_segment":_cb(rs, lambda r:r.segment),
        "by_status":_cb(rs, lambda r:r.status),
        "trend":_monthly_count(rs, lambda r:r.created_at),
        "top":[_rec_dict(r) for r in sorted(rs, key=lambda r:-(r.score or 0))[:12]]}
async def seed_reco():
    async with AsyncSessionLocal() as db:
        if (await db.execute(select(Recommendation).limit(1))).scalar_one_or_none(): return
        segs=["Premium","Standard","New","Corporate","Youth","At-Risk"]
        items={RecoType.next_best_action:["Call for renewal","Offer mobile app","Schedule review","Send KYC reminder"],
               RecoType.product_offer:["Multi-currency card","Business account","Travel FX pack","Savings plan"],
               RecoType.corridor:["India corridor promo","Philippines fast transfer","Egypt low-fee","Pakistan bonus rate"],
               RecoType.retention_offer:["Fee waiver 3 months","Loyalty points boost","Better FX margin","Priority desk"],
               RecoType.cross_sell:["Add bill payment","Enable auto-remit","Insurance add-on","Gold upgrade"],
               RecoType.reactivation:["Win-back OMR 10","Re-engage SMS","Anniversary offer","Dormant bonus"]}
        base=datetime.utcnow()-timedelta(days=120); rs=[]
        for i in range(250):
            rt=random.choice(list(RecoType)); st=random.choices(["served","accepted","dismissed","expired"], weights=[40,30,20,10])[0]
            cd=base+timedelta(days=random.randint(0,118))
            rs.append(Recommendation(rec_ref=f"REC{100001+i}", customer=f"Customer {1000+random.randint(0,400)}",
                segment=random.choice(segs), rec_type=rt, item=random.choice(items[rt]),
                score=round(random.uniform(0.55,0.98),3), expected_uplift_omr=round(random.uniform(5,320),2), status=st,
                reason=random.choice(["High propensity","Similar customers converted","Behavioural signal","Churn risk detected","Lifecycle stage"]),
                model_version=random.choice(["v2.3","v2.3","v2.2"]), created_at=cd,
                actioned_at=(cd+timedelta(days=random.randint(1,20)) if st in ("accepted","dismissed") else None)))
        db.add_all(rs); await db.commit()

# ======================================================================
# BUSINESS INTELLIGENCE (cross-domain executive dashboard)
# ======================================================================
bi_router=APIRouter(prefix="/bi", tags=["business-intelligence"])
@bi_router.get("/overview")
async def bi_overview(db:AsyncSession=Depends(get_db), _:User=Depends(get_current_user)):
    txns=(await db.execute(select(Transaction))).scalars().all()
    deals=(await db.execute(select(Deal))).scalars().all()
    tickets=(await db.execute(select(Ticket))).scalars().all()
    docs=(await db.execute(select(Document))).scalars().all()
    members=(await db.execute(select(Member))).scalars().all()
    camps=(await db.execute(select(Campaign))).scalars().all()
    revenue=round(sum(_rev(t) for t in txns),2); txn_value=round(sum(t.amount or 0 for t in txns),2)
    completed=[t for t in txns if getattr(t.status,'value','')=="completed"]
    open_deals=[d for d in deals if getattr(d.stage,'value','') not in ("won","lost")]
    weighted=round(sum((d.value or 0)*(d.probability or 0)/100 for d in open_deals),2)
    won=[d for d in deals if getattr(d.stage,'value','')=="won"]
    open_tickets=[t for t in tickets if getattr(t.status,'value','') in ("open","pending","on_hold")]
    breached=[t for t in tickets if getattr(t,'sla_breached',False)]
    csat=[t.csat for t in tickets if getattr(t,'csat',None)]
    mkt_spend=round(sum(c.spent or 0 for c in camps),2); mkt_rev=round(sum(c.revenue or 0 for c in camps),2)
    pts_liab=round(sum(m.points_balance or 0 for m in members)*0.01,2)
    # revenue trend monthly
    mrev={}
    for t in txns:
        if t.created_at:
            k=t.created_at.strftime("%Y-%m"); mrev[k]=mrev.get(k,0)+_rev(t)
    rev_trend=[{"month":k,"revenue":round(v,2)} for k,v in sorted(mrev.items())][-12:]
    chan={}
    for t in txns:
        k=t.channel.value if t.channel else "—"; chan[k]=chan.get(k,0)+1
    scorecard=[
        {"module":"Transactions","metric":"Revenue (OMR)","value":revenue,"status":"good"},
        {"module":"CRM","metric":"Weighted Pipeline (OMR)","value":weighted,"status":"good"},
        {"module":"Helpdesk","metric":"Open Tickets","value":len(open_tickets),"status":"warn" if len(open_tickets)>60 else "good"},
        {"module":"Helpdesk","metric":"SLA Breaches","value":len(breached),"status":"warn" if breached else "good"},
        {"module":"Documents","metric":"Expiring/Expired","value":len([d for d in docs if d.compliance_flag in ("expiring","expired")]),"status":"warn"},
        {"module":"Loyalty","metric":"Points Liability (OMR)","value":pts_liab,"status":"good"},
        {"module":"Marketing","metric":"ROI %","value":round((mkt_rev-mkt_spend)/max(1,mkt_spend)*100,1),"status":"good"},
    ]
    return {
        "kpis":{"revenue_omr":revenue,"txn_value_omr":txn_value,"transactions":len(txns),"completed_txns":len(completed),
            "active_customers":len([m for m in members if m.status=="active"]),"loyalty_members":len(members),
            "pipeline_weighted_omr":weighted,"deals_won":len(won),"open_tickets":len(open_tickets),
            "sla_breaches":len(breached),"csat":round(sum(csat)/max(1,len(csat)),2),
            "documents":len(docs),"docs_expiring":len([d for d in docs if d.compliance_flag in ("expiring","expired")]),
            "points_liability_omr":pts_liab,"marketing_spend_omr":mkt_spend,"marketing_revenue_omr":mkt_rev,
            "marketing_roi":round((mkt_rev-mkt_spend)/max(1,mkt_spend)*100,1)},
        "revenue_trend":rev_trend,
        "channel_mix":[{"name":k,"count":v} for k,v in sorted(chan.items(), key=lambda x:-x[1])],
        "txn_by_status":_cb(txns, lambda t:t.status.value if t.status else None),
        "docs_by_domain":_cb(docs, lambda d:d.domain.value if d.domain else None),
        "members_by_tier":_cb(members, lambda m:m.tier.value if m.tier else None),
        "marketing_by_channel":[{"name":(c.channel.value if c.channel else "—")} for c in camps] and _cb(camps, lambda c:c.channel.value if c.channel else None),
        "scorecard":scorecard,
    }


app = FastAPI(title=settings.PROJECT_NAME, version="3.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(analytics_router, prefix=settings.API_V1_STR)
app.include_router(txn_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)
app.include_router(crm_router, prefix=settings.API_V1_STR)
app.include_router(help_router, prefix=settings.API_V1_STR)
app.include_router(doc_router, prefix=settings.API_V1_STR)
app.include_router(loyalty_router, prefix=settings.API_V1_STR)
app.include_router(mkt_router, prefix=settings.API_V1_STR)
app.include_router(video_router, prefix=settings.API_V1_STR)
app.include_router(facility_router, prefix=settings.API_V1_STR)
app.include_router(ocr_router, prefix=settings.API_V1_STR)
app.include_router(search_router, prefix=settings.API_V1_STR)
app.include_router(reco_router, prefix=settings.API_V1_STR)
app.include_router(bi_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def on_startup():
    await init_db(); await seed_demo_data(); await seed_crm_helpdesk(); await seed_documents(); await seed_loyalty(); await seed_marketing(); await seed_video(); await seed_facility(); await seed_ocr(); await seed_search(); await seed_reco()

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
    return {"status": "ok", "service": settings.PROJECT_NAME, "version": "3.2.0"}
