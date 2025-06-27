from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Optional
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Datenbankverbindung
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:postgres@db:5432/zieltracker"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Passwort-Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT-Konfiguration
SECRET_KEY = "dein_geheimer_schluessel"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Datenbankmodelle
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    goals = relationship("GoalModel", back_populates="owner")

class GoalModel(Base):
    __tablename__ = "goals"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    progress = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("UserModel", back_populates="goals")

Base.metadata.create_all(bind=engine)

# Pydantic-Modelle
class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class GoalIn(BaseModel):
    title: str
    progress: int = Field(..., ge=0, le=100)

class Goal(GoalIn):
    id: int

class GoalUpdate(BaseModel):
    title: Optional[str] = None
    progress: Optional[int] = Field(None, ge=0, le=100)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Hilfsfunktionen
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db, username: str):
    return db.query(UserModel).filter(UserModel.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    db = SessionLocal()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Ungültiger Token")
        user = get_user(db, username)
        if user is None:
            raise HTTPException(status_code=401, detail="Benutzer nicht gefunden")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token ungültig")

# Endpunkte
@app.post("/register", response_model=User)
def register(user: UserCreate):
    db = SessionLocal()
    if get_user(db, user.username):
        raise HTTPException(status_code=400, detail="Benutzername bereits vergeben")
    hashed = get_password_hash(user.password)
    db_user = UserModel(username=user.username, hashed_password=hashed)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    db.close()
    return User(id=db_user.id, username=db_user.username)


@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    auth_user = authenticate_user(db, form_data.username, form_data.password)
    if not auth_user:
        raise HTTPException(status_code=400, detail="Falscher Benutzername oder Passwort")
    token = create_access_token(
        data={"sub": auth_user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}

@app.get("/goals", response_model=List[Goal])
def list_goals(current_user: UserModel = Depends(get_current_user)):
    db = SessionLocal()
    goals = db.query(GoalModel).filter(GoalModel.user_id == current_user.id).all()
    db.close()
    return [Goal(id=g.id, title=g.title, progress=g.progress) for g in goals]

@app.post("/goals", response_model=Goal, status_code=201)
def create_goal(goal: GoalIn, current_user: UserModel = Depends(get_current_user)):
    db = SessionLocal()
    db_goal = GoalModel(title=goal.title, progress=goal.progress, user_id=current_user.id)
    db.add(db_goal)
    db.commit()
    db.refresh(db_goal)
    db.close()
    return Goal(id=db_goal.id, title=db_goal.title, progress=db_goal.progress)

@app.patch("/goals/{goal_id}", response_model=Goal)
def update_goal(goal_id: int, patch: GoalUpdate, current_user: UserModel = Depends(get_current_user)):
    db = SessionLocal()
    goal = db.query(GoalModel).filter(GoalModel.id == goal_id, GoalModel.user_id == current_user.id).first()
    if not goal:
        raise HTTPException(status_code=404, detail="Ziel nicht gefunden")
    if patch.title is not None:
        goal.title = patch.title
    if patch.progress is not None:
        goal.progress = patch.progress
    db.commit()
    db.refresh(goal)
    db.close()
    return Goal(id=goal.id, title=goal.title, progress=goal.progress)

@app.delete("/goals/{goal_id}", status_code=204)
def delete_goal(goal_id: int, current_user: UserModel = Depends(get_current_user)):
    db = SessionLocal()
    goal = db.query(GoalModel).filter(GoalModel.id == goal_id, GoalModel.user_id == current_user.id).first()
    if not goal:
        raise HTTPException(status_code=404, detail="Ziel nicht gefunden")
    db.delete(goal)
    db.commit()
    db.close()

