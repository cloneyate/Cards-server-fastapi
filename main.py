from bson import ObjectId
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import Depends, FastAPI, HTTPException, status, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
import pymongo
from bson.objectid import ObjectId
from fastapi.middleware.cors import CORSMiddleware


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

DATABASE = pymongo.MongoClient("mongodb://localhost:27017/")["cards"]
users_coll = DATABASE["users"]
cards_coll = DATABASE["cards"]


class PyObjectId(ObjectId):

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError('Invalid objectid')
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type='string')


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id")
    username: str
    email: Optional[str] = None
    avatar_url: Optional[str] = None
    nickname: Optional[str] = None
    disabled: Optional[bool] = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class UserInDB(User):
    hashed_password: str
    cards: Optional[list] = []


class Card(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id")
    cover_url: Optional[str] = None
    time: Optional[datetime] = datetime.now()
    title: Optional[str] = None
    creator: Optional[PyObjectId] = None
    blocks: Optional[list] = None

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


class CardInUser(BaseModel):
    id: PyObjectId = Field(alias="_id")
    bookmarked: Optional[bool] = False

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user_dict = users_coll.find_one({"username": username})
    if user_dict:
        return UserInDB(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    result = {"access_token": access_token, "token_type": "bearer"}
    return result


@app.get("/users/", response_model=List[User])
async def list_users():
    users = []
    for user in users_coll.find():
        users.append(User(**user))
    return users


@app.post("/users/")
async def register(user: User, password: str):
    if hasattr(user, 'id'):
        delattr(user, 'id')
    user_dict = user.dict(by_alias=True)
    user_dict.update(
        {'hashed_password': get_password_hash(password), 'cards': []})
    inserted_id = users_coll.insert(user_dict)
    user.id = inserted_id
    return user


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.put("/users/me/avatar/")
async def change_users_me_avatar(avatar_url: str, current_user: User = Depends(get_current_active_user)):
    return users_coll.update({"username": current_user.username}, {'$set': {'avatar_url': avatar_url}})


@app.get("/users/me/cards/", response_model=List[CardInUser])
async def read_own_cards(current_user: User = Depends(get_current_active_user)):
    user = users_coll.find_one(
        {"username": current_user.username}, {"cards": 1})
    return user['cards']


@app.post("/users/me/cards/")
async def collect_card(card_in_user: CardInUser, current_user: User = Depends(get_current_active_user)):
    # users_coll.update({"username": current_user.username},{$set:{"":}})
    if users_coll.find_one({"username": current_user.username, "cards._id": card_in_user.dict(by_alias=True)["_id"]}):
        raise HTTPException(status_code=400, detail="Already collected")
    else:
        return users_coll.update({"username": current_user.username}, {
            '$addToSet': {"cards": card_in_user.dict(by_alias=True)}})


@app.put("/users/me/cards/")
async def edit_card_in_user_me(card_in_user: CardInUser, current_user: User = Depends(get_current_active_user)):
    input_dict = card_in_user.dict(by_alias=True)
    prev_dict = users_coll.find_one({"username": current_user.username},
                                    {"cards": {'$elemMatch': {'_id': input_dict["_id"]}}})["cards"][0]
    prev_dict.update(input_dict)
    return users_coll.update({"username": current_user.username, "cards._id": input_dict["_id"]}, {
        '$set': {"cards.$": prev_dict}})


@app.delete("/users/me/cards/{cid}")
async def drop_a_card(current_user: User = Depends(get_current_active_user), cid: str = Path(..., title="The ID of the card to collect")):
    return users_coll.update({"username": current_user.username}, {
        '$pull': {"cards": {"_id": ObjectId(cid)}}})


@app.get("/cards/", response_model=List[Card])
async def get_cards():
    cards = []
    for card in cards_coll.find():
        cards.append(Card(**card))
    return cards


@app.post("/cards/")
async def create_a_card(card: Card, current_user: User = Depends(get_current_active_user)):
    if hasattr(card, 'id'):
        delattr(card, 'id')
    card.creator = current_user.id
    card_dict = card.dict(by_alias=True)
    card_dict.update({"creator": current_user.id})
    inserted_id = cards_coll.insert(card_dict)
    card.id = inserted_id
    return card


@app.put("/cards/")
async def edit_a_card_only_creator(card: Card, current_user: User = Depends(get_current_active_user)):
    card_dict = card.dict(by_alias=True)
    if current_user.id == card_dict.creator:
        cards_coll.update_one({"_id": card_dict["_id"]}, {"$set": card_dict})
    else:
        raise HTTPException(status_code=400, detail="You are not creator")


@app.get("/cards/{cid}", response_model=Card)
async def get_cards(cid: str):
    output = cards_coll.find_one({"_id": ObjectId(cid)})
    if output:
        return Card(**output)
    else:
        raise HTTPException(status_code=404)
