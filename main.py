import os
import re
import logging
import redis
import smtplib
import bcrypt
import time
from datetime import datetime
from fastapi import FastAPI, Request, Form, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr, BaseModel, ValidationError
from typing import Optional
from starlette.middleware.sessions import SessionMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "supersecretkey"),
    session_cookie="admin_session"
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Configuration from environment variables
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "securepassword")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "user@example.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "smtppassword")

# Redis connection pool with password
redis_pool = redis.ConnectionPool.from_url(
    REDIS_URL,
    password=REDIS_PASSWORD,
    decode_responses=True,
    ssl=True
)
redis_conn = redis.Redis(connection_pool=redis_pool)

class UserRegistration(BaseModel):
    name: str
    email: EmailStr

def get_redis_with_retry(max_retries=3, delay=1):
    retries = 0
    while retries < max_retries:
        try:
            if redis_conn.ping():
                return redis_conn
        except (redis.ConnectionError, redis.AuthenticationError) as e:
            retries += 1
            logger.warning(f"Redis connection attempt {retries} failed: {str(e)}")
            if retries < max_retries:
                time.sleep(delay)
    raise redis.ConnectionError("Max retries reached. Could not connect to Redis.")

def get_redis():
    try:
        yield get_redis_with_retry()
    except redis.AuthenticationError:
        logger.error("Redis authentication failed. Please check password.")
        raise HTTPException(
            status_code=500,
            detail="Database authentication failed. Please check Redis credentials."
        )
    except redis.ConnectionError as e:
        logger.error(f"Redis connection error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Database connection failed. Please check Redis credentials."
        )
    except redis.RedisError as e:
        logger.error(f"Redis error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database operation failed")

def validate_email(email: str) -> bool:
    try:
        EmailStr.validate(email)
        return True
    except ValidationError:
        return False

async def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to
    msg.set_content(body)
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email sent to {to}")
    except smtplib.SMTPException as e:
        logger.error(f"Email sending failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Email sending failed: {str(e)}")

def initialize_admin_account(db: redis.Redis):
    if not db.exists("admin:account"):
        hashed_pw = bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
        db.hset("admin:account", mapping={
            "username": ADMIN_USERNAME,
            "password": hashed_pw
        })
        logger.info("Admin account initialized")

def verify_admin(username: str, password: str, db: redis.Redis) -> bool:
    admin_data = db.hgetall("admin:account")
    if not admin_data:
        return False
        
    stored_user = admin_data.get("username", "")
    stored_pw = admin_data.get("password", "")
    
    if username != stored_user:
        return False
    
    return bcrypt.checkpw(password.encode('utf-8'), stored_pw.encode('utf-8'))

@app.on_event("startup")
async def startup_event():
    try:
        # Test Redis connection
        if not redis_conn.ping():
            raise redis.ConnectionError("Redis connection failed")
        initialize_admin_account(redis_conn)
        logger.info("Redis connection established successfully")
    except redis.AuthenticationError:
        logger.error("Redis authentication failed. Please check password.")
        raise RuntimeError("Redis authentication failed")
    except redis.ConnectionError as e:
        logger.error(f"Redis connection failed: {str(e)}")
        raise RuntimeError("Redis connection failed")

@app.get("/", response_class=HTMLResponse)
async def registration_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/")
async def register_user(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    db: redis.Redis = Depends(get_redis)
):
    try:
        if not validate_email(email):
            return templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Invalid email format"
            }, status_code=400)

        if db.hexists("users:emails", email):
            return templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Email already registered"
            }, status_code=400)

        user_id = db.incr("users:count")
        user_key = f"user:{user_id}"
        db.hset(user_key, mapping={
            "name": name.strip(),
            "email": email.lower().strip(),
            "id": user_id
        })
        db.hset("users:emails", email.lower().strip(), user_id)
        logger.info(f"New user registered: {email}")
        return RedirectResponse(url="/success", status_code=303)
    except redis.RedisError as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database operation failed")

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_form(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.post("/admin/login")
async def admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: redis.Redis = Depends(get_redis)
):
    if verify_admin(username, password, db):
        request.session["admin_logged_in"] = True
        logger.info("Admin logged in successfully")
        return RedirectResponse(url="/admin", status_code=303)
    
    logger.warning("Failed admin login attempt")
    return templates.TemplateResponse("admin_login.html", {
        "request": request,
        "error": "Invalid credentials"
    }, status_code=401)

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not request.session.get("admin_logged_in"):
        return RedirectResponse(url="/admin/login", status_code=303)
    
    return templates.TemplateResponse("admin.html", {"request": request})

@app.post("/admin/broadcast")
async def broadcast_message(
    request: Request,
    message: str = Form(...),
    db: redis.Redis = Depends(get_redis)
):
    if not request.session.get("admin_logged_in"):
        return RedirectResponse(url="/admin/login", status_code=303)

    try:
        users = []
        for key in db.scan_iter("user:*"):
            user = db.hgetall(key)
            users.append({
                "name": user.get("name"),
                "email": user.get("email")
            })

        for user in users:
            personalized_message = message.replace("{{Student_name}}", user["name"])
            await send_email(
                to=user["email"],
                subject="New Announcement",
                body=personalized_message
            )

        logger.info(f"Broadcast message sent to {len(users)} users")
        return templates.TemplateResponse("admin.html", {
            "request": request,
            "success": "Message broadcasted successfully"
        })
    except (redis.RedisError, AttributeError) as e:
        logger.error(f"Broadcast error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process broadcast")

@app.get("/logs", response_class=HTMLResponse)
async def view_logs(request: Request):
    if not request.session.get("admin_logged_in"):
        return RedirectResponse(url="/admin/login", status_code=303)
    
    try:
        with open("logs.txt", "r") as f:
            logs = f.read()
        return templates.TemplateResponse("logs.html", {
            "request": request,
            "logs": logs
        })
    except FileNotFoundError:
        logger.error("Log file not found")
        raise HTTPException(status_code=404, detail="Logs not available")

@app.get("/success", response_class=HTMLResponse)
async def success_page(request: Request):
    return templates.TemplateResponse("success.html", {"request": request})

@app.post("/admin/logout")
async def admin_logout(request: Request):
    request.session.clear()
    logger.info("Admin logged out")
    return RedirectResponse(url="/admin/login", status_code=303)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=75038)
