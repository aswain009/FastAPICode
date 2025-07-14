from __future__ import annotations
import asyncio
from collections import defaultdict
import jwt
import bcrypt
import uvicorn
from uuid import uuid4
import logging
import urllib.parse
import httpx
from httpx import AsyncClient
from typing import Annotated, List, Dict, Union
from jwt.exceptions import PyJWTError
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, Query, WebSocket, WebSocketDisconnect
from passlib.exc import InvalidTokenError
from sqlalchemy import func
from sqlmodel import Session, select
from passlib.context import CryptContext
from starlette.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketDisconnect, WebSocket
from datetime import datetime
from sqlalchemy.exc import IntegrityError

from fastapi_utils.tasks import repeat_every

from models import (User, Employee, Positions, UserPublic, UserCreate, engine, EmployeePublic,
                    PositionsPublic, PositionsBase, EmployeeBase, TestUser, TestUserInDB, Token, TokenData,
                    LoginRequest, UserBase, Messages, MessagesBase, MessagesPublic, DeviceToken, NotificationQueue,
                    UpdatePasswordRequest)


# from sqlalchemy.orm import Session
from typing import List
import httpx

from pyfcm import FCMNotification

# Mock database (replace with your actual database)
messages = []


# users = {}  # Add your user database logic

logging.basicConfig(level=logging.INFO)
def get_session():
    with Session(engine) as session:
        yield session


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt
    """
    return pwd_context.hash(password)


############ FAKE INFO FOR OAUTH TESTING############


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        self.active_connections.pop(user_id, None)

    async def broadcast(self, message: dict):
        disconnected_users = []
        for user_id, connection in self.active_connections.items():
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected_users.append(user_id)

        for user_id in disconnected_users:
            self.disconnect(user_id)

manager = ConnectionManager()

# @app.websocket("/ws/{user_id}")
# async def websocket_endpoint(websocket: WebSocket, user_id: str):
#     await manager.connect(websocket, user_id)
#     try:
#         while True:
#             data = await websocket.receive_json()
#             await manager.broadcast({
#                 "type": "message",
#                 "data": {
#                     "text": data["text"],
#                     "userId": user_id,
#                     "createdAt": datetime.now().isoformat()
#                 }
#             })
#     except WebSocketDisconnect:
#         manager.disconnect(user_id)
#         await manager.broadcast({
#             "type": "system",
#             "data": f"User {user_id} left the chat"
#         })

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)



def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_from_username(username: str):
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        results = session.execute(statement)
        user = results.scalar_one_or_none()
    return user


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return TestUserInDB(**user_dict)
    return None


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def verify_login(username: str, password: str):
    user = get_user_from_username(username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username", headers={"WWW-Authenticate": "Bearer"})

    if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid password", headers={"WWW-Authenticate": "Bearer"})

    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: Session = Depends(get_session)):
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
        except PyJWTError:
            raise credentials_exception

        statement = select(User).where(User.username == username)
        user = session.execute(statement).scalar_one_or_none()
        if user is None:
            raise credentials_exception
        return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_last_user_id():
    with Session(engine) as session:
        stmt = select(User.id).order_by(User.id.desc()).limit(1)
        result = session.execute(stmt)
        last_id = result.scalar()  # Extract the first column value
        if last_id is None:
            raise HTTPException(status_code=404, detail="No users found")
        return last_id


def check_user_exists(email):
    with Session(engine) as session:
        statement = select(User).where(User.email == email)
        results = session.execute(statement)
        for user in results:
            return user
        return None

def check_if_user_is_admin(user_id: int):
    with Session(engine) as session:
        statement = select(Employee).where(Employee.user_id == user_id, Employee.supervisor_id == 0)
        results = session.execute(statement)
        return results.scalar_one_or_none() is not None


async def send_push_notification(tokens: List[str], message: str):
    expo_api = "https://exp.host/--/api/v2/push/send"
    logging.info(f"Sending push notification to: {tokens}")

    # Group tokens by project
    project_tokens = defaultdict(list)
    for token in tokens:
        project_id = token.split('[')[1].split(']')[0]  # Extract project ID from token
        project_tokens[project_id].append(token)

    responses = []
    async with httpx.AsyncClient() as client:
        for project_id, tokens in project_tokens.items():
            notifications = [
                {
                    "to": token,
                    "sound": "default",
                    "title": "New Message",
                    "body": message,
                }
                for token in tokens
            ]
            logging.info(f"Sending notifications for project {project_id}: {notifications}")
            response = await client.post(expo_api, json=notifications)
            logging.info(f"Push notification response for project {project_id}: {response.json()}")
            responses.append(response.json())

    return responses


# @app.on_event("startup")
# @repeat_every(seconds=60)  # Adjust the interval as needed
# async def check_unread_messages():
#     with Session(engine) as session:
#         unread_messages = session.exec(select(NotificationQueue).where(NotificationQueue.read == False)).all()
#         for notification in unread_messages:
#             message = session.get(Messages, notification.message_id)
#             tokens = session.exec(select(DeviceToken.token).where(DeviceToken.user_id == notification.user_id)).all()
#             if tokens:
#                 await send_push_notification(tokens, message.text)
#                 notification.read = True
#                 session.add(notification)
#                 session.commit()


def send_welcome_message(user: User):
    with Session(engine) as session:
        welcome_message = MessagesBase(
            text=f"Welcome {user.first_name} {user.last_name} to the Columbia Woodlands concierge app!",
            FromUserId=1,  # Assuming user ID 1 is the admin or system user
            ToUserId=user.id,
            newMessage=False,
            readMessage=True,
            createdAt=datetime.now(timezone.utc)
        )
        message = Messages.model_validate(welcome_message)
        db_message = Messages(**message.model_dump())
        session.add(db_message)
        session.commit()
        session.refresh(db_message)
    logging.info(f"Welcome message sent to {user.username}")

@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = get_user_from_username(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username", headers={"WWW-Authenticate": "Bearer"})

    # Use pwd_context to verify password
    if not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password", headers={"WWW-Authenticate": "Bearer"})

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/check-token/{token}", response_model=bool)
def check_token(token: str, session: Session = Depends(get_session)):
    exists = session.execute(
        select(DeviceToken).where(DeviceToken.token == token)
    ).scalar_one_or_none() is not None
    return exists


@app.post("/save-token/")
async def save_token(token_data: DeviceToken, db: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    logging.info(f"Received token: {token_data}")
    db_token = DeviceToken(
        UserId=token_data.UserId,
        token=token_data.token,
        id=str(uuid4()),  # Convert UUID to string
    )
    try:
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
    except IntegrityError:
        db.rollback()
        existing_token = db.execute(select(DeviceToken).where(DeviceToken.token == token_data.token)).scalar_one_or_none()
        if existing_token:
            existing_token.UserId = token_data.UserId
            db.commit()
            db.refresh(existing_token)
            return {"status": "success", "message": "Token updated successfully"}
    return {"status": "success", "message": "Token saved successfully"}


#Compare messages to send-message to make sure the data from the messages is getting to the DB in the send-message function
#Will replace the message function with the send-message function to use the Push Notification
@app.post("/messages/", response_model=Dict[str, Union[str, MessagesPublic]])
def create_message(*, session: Session = Depends(get_session), message: MessagesBase, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Create a new message
    message = Messages.model_validate(message)
    db_message = Messages(**message.model_dump())
    session.add(db_message)
    session.commit()
    session.refresh(db_message)
    return {"message": "Message created successfully", "data": db_message}


@app.post("/send-message/")
async def send_message(message: MessagesBase, session: Session = Depends(get_session), response_model=Dict[str, str], user: User = Depends(get_current_active_user)):
    logging.info("Received message to send", {user})
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    logging.info("Received message to send")

    # Validate and convert the message to the correct model
    message_data = Messages.model_validate(message)
    db_message = Messages(**message_data.model_dump())

    # Save message to database
    try:
        session.add(db_message)
        session.commit()
        session.refresh(db_message)
        logging.info(f"Message saved to database: {db_message}")
    except Exception as e:
        session.rollback()
        logging.error(f"Error saving message to database: {e}")
        raise HTTPException(status_code=500, detail="Error saving message to database")

    # Check if a notification has already been sent for this conversation
    try:
        existing_notification = session.execute(
            select(NotificationQueue).where(
                NotificationQueue.user_id == message.ToUserId,
                NotificationQueue.message_id == db_message.id,
                NotificationQueue.read == False
            )
        ).first()
        logging.info(f"Existing notification: {existing_notification}")
    except Exception as e:
        logging.error(f"Error checking existing notifications: {e}")
        raise HTTPException(status_code=500, detail="Error checking existing notifications")

    if not existing_notification and message.ToUserId != message.FromUserId:
        # Get receiver's device tokens
        try:
            tokens = session.execute(select(DeviceToken.token).where(DeviceToken.UserId == message.ToUserId)).scalars().all()
            unique_tokens = list(set(tokens))  # Remove duplicate tokens
            logging.info(f"Unique device tokens: {unique_tokens}")
        except Exception as e:
            logging.error(f"Error retrieving device tokens: {e}")
            raise HTTPException(status_code=500, detail="Error retrieving device tokens")

        if unique_tokens:
            # Write to NotificationQueue
            try:
                notification = NotificationQueue(
                    user_id=message.ToUserId,
                    message_id=db_message.id,
                    created_at=datetime.now(timezone.utc),
                    read=False
                )
                session.add(notification)
                session.commit()
                logging.info(f"NotificationQueue entry created: {notification}")
            except Exception as e:
                session.rollback()
                logging.error(f"Error writing to NotificationQueue: {e}")
                raise HTTPException(status_code=500, detail="Error writing to NotificationQueue")

            # Send push notification
            try:
                await send_push_notification(
                    tokens=unique_tokens,
                    message=f"New message from {message.FromUserId}"
                )
                # Mark the notification as read after sending
                notification.read = True
                session.add(notification)
                session.commit()
            except Exception as e:
                logging.error(f"Error sending push notification: {e}")
                raise HTTPException(status_code=500, detail="Error sending push notification")
        else:
            logging.warning("No device tokens found for user")
    else:
        logging.info("Notification already sent for this conversation or message is from the same user")

    return {"status": "success"}

# @app.get("/testusers/me/", response_model=TestUser)
# async def read_users_me(
#         current_user: Annotated[TestUser, Depends(get_current_active_user)],
# ):
#     return current_user
#
#
# @app.get("/testusers/me/items/")
# async def read_own_items(
#         current_user: Annotated[TestUser, Depends(get_current_active_user)],
# ):
#     return [{"item_id": "Foo", "owner": current_user.username}]


############ FAKE INFO FOR OAUTH TESTING############


@app.get("/messages", response_model=List[MessagesPublic])
def get_messages(*, session: Session = Depends(get_session), limit: int = 100, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    data = session.execute(select(Messages).limit(limit)).all()
    return data


#Build an endpoint that returns all messages sent by a user
@app.get("/messages/sent", response_model=List[MessagesPublic])
def get_sent_messages(*, session: Session = Depends(get_session), fromuserid: int, limit: int = 100, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Filter messages based on the `fromuserid` parameter
    data = session.execute(select(Messages).where(Messages.FromUserId == fromuserid).limit(limit)).all()
    return data


#Build an endpoint that returns all messages sent to a user
@app.get("/messages/received", response_model=List[MessagesPublic])
def get_received_messages(*, session: Session = Depends(get_session), touserid: int, limit: int = 100, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Filter messages based on the `fromuserid` parameter
    data = session.execute(select(Messages).where(Messages.ToUserId == touserid).limit(limit)).all()
    return data


@app.get("/distinct-users/", response_model=List[Dict[str, Union[int, str]]])
def get_distinct_user_names(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    """
    Endpoint to fetch distinct user IDs (both senders and receivers) and their corresponding user names.
    """
    try:
        # Query distinct FromUserId values
        from_users = session.execute(select(Messages.FromUserId).distinct()).scalars().all()

        # Query distinct ToUserId values
        to_users = session.execute(select(Messages.ToUserId).distinct()).scalars().all()

        # Combine and remove duplicates and None values
        distinct_user_ids = list(set([user_id for user_id in from_users + to_users if user_id is not None]))

        # Log the found user IDs for debugging
        logging.info(f"Found {len(distinct_user_ids)} distinct user IDs: {distinct_user_ids}")

        # Empty check with helpful message
        if not distinct_user_ids:
            logging.warning("No messages found in the database")
            return []

        # Fetch user names for each distinct user_id
        users = []
        for user_id in distinct_user_ids:
            user = session.get(User, user_id)
            if user:
                users.append({
                    "id": user.id,
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                })
                logging.info(f"Found user: {user.username}")
            else:
                users.append({"id": user_id, "name": "Unknown User"})
                logging.warning(f"No user found with ID {user_id}")

        return users
    except Exception as e:
        logging.error(f"Error in distinct-users endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/messages/{message_id}", response_model=MessagesPublic)
def read_message(message_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    message = session.get(Messages, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return message


@app.post("/user/", response_model=UserPublic)
def create_user(*, session: Session = Depends(get_session), user: UserCreate, validUser: User = Depends(get_current_active_user)):
    if not validUser:
        raise HTTPException(status_code=401, detail="Not authenticated")
    hashed_password = hash_password(user.password)
    extra_data = {"hashed_password": hashed_password}
    db_user = User.model_validate(user, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    if not User:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        **current_user.model_dump(),
        "verified": True  # or some logic to determine True/False
    }


#TODO: Add better error handling to spit out a response when data is given that does not match data in the table
@app.post("/user/update-password")
def update_password(request: UpdatePasswordRequest, session: Session = Depends(get_session), validUser: User = Depends(get_current_active_user)):
    if not validUser:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = session.execute(select(User).where(User.username == request.username, User.email == request.email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed_password = get_password_hash(request.new_password)
    user.hashed_password = hashed_password
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"status": "success", "message": "Password updated successfully"}



@app.get("/user/{first_name}/{last_name}/{email}", response_model=List[UserBase])
def read_user(first_name: str, last_name: str, email: str, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    decoded_email = urllib.parse.unquote(email)
    user = session.execute(select(User).where(User.first_name == first_name, User.last_name == last_name, User.email == decoded_email)).first()
    if user:
        return user
    raise HTTPException(status_code=404, detail="User not found")


@app.get("/user/", response_model=List[UserPublic])
def read_users(
        *,
        session: Session = Depends(get_session),
        offset: int = 0,
        limit: int = Query(default=100, le=100),
        validUser: User = Depends(get_current_active_user)
):
    if not validUser:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = session.execute(select(User).offset(offset).limit(limit)).all()
    return user


@app.get("/user/{user_id}", response_model=UserPublic)
def read_user(user_id: int, session: Session = Depends(get_session), validUser: User = Depends(get_current_active_user)):
    if not validUser:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = session.get(User, user_id)
    return user


@app.post("/employee/", response_model=EmployeePublic)
def create_employee(*, session: Session = Depends(get_session), employee: EmployeeBase, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    employee = Employee.model_validate(employee)
    session.add(employee)
    session.commit()
    session.refresh(employee)
    return employee

@app.get("/employee/{user_id}", response_model=List[EmployeePublic])
def read_employee(user_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    employees = session.execute(select(Employee).where(Employee.user_id == user_id)).scalars().all()
    return employees


@app.post("/positions/", response_model=PositionsPublic)
def create_positions(*, session: Session = Depends(get_session), position: PositionsBase, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    position = Positions.model_validate(position)
    session.add(position)
    session.commit()
    session.refresh(position)
    return position


@app.get("/conversation/{current_user}/{selected_user}", response_model=List[MessagesPublic])
def get_conversation(current_user: int, selected_user: int, session: Session = Depends(get_session), verifiedUser: User = Depends(get_current_active_user)):
    if not verifiedUser:
        raise HTTPException(status_code=401, detail="Not authenticated")
    """
    Endpoint to fetch the conversation between two users.
    """
    if current_user != verifiedUser.id:
        raise HTTPException(status_code=403, detail="Unauthorized access")

    if check_if_user_is_admin(current_user):
        logging.info("User is an admin, allowing access to all conversations")
        try:
            data = session.execute(
                select(Messages).where(
                    (Messages.ToUserId == selected_user) | (Messages.FromUserId == selected_user)
                )
            ).scalars().all()
            return data
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    try:
        data = session.execute(
            select(Messages).where(
                (Messages.FromUserId == current_user) | (Messages.ToUserId == current_user)
            )
        ).scalars().all()
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Authentication endpoints
@app.post("/auth/register")
async def register(user: User):
    lowercase_username = user.username.lower()
    with Session(engine) as session:
        existing_user = session.exec(
            select(User).where(func.lower(User.username) == lowercase_username)
        ).first()
        existing_email = session.exec(
            select(User).where(User.email == user.email)
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Username already exists"
            )
        if existing_email:
            raise HTTPException(
                status_code=400,
                detail="Email already exists"
            )

    # Hash password using pwd_context instead of direct bcrypt
    user.id = get_last_user_id() + 1
    user.hashed_password = hash_password(user.hashed_password)
    user.username = lowercase_username
    with Session(engine) as session:
        session.add(user)
        session.commit()
        session.refresh(user)

    # Send welcome message
    send_welcome_message(user)
    return {"message": "User created successfully"}


@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = verify_login(form_data.username, form_data.password)

    token = create_access_token({
        "email": user.email,
        "user_id": user.username
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user.email,
            "user_name": user.username,
            "user_id": user.id
        }
    }


@app.post("/messages/create")
async def create_message(message: Messages, user: User = Depends(get_current_active_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    messages.append(message.dict())
    return message


# # WebSocket endpoint
# @app.websocket("/ws/{token}")
# async def websocket_endpoint(websocket: WebSocket, token: str):
#     try:
#         # Verify token and get user data
#         user_data = verify_token(token)
#         await manager.connect(websocket, user_data.username)
#
#         try:
#             while True:
#                 data = await websocket.receive_json()
#                 # Broadcast the message to all connected clients
#                 await manager.broadcast({
#                     "type": "message",
#                     "data": {
#                         "text": data["text"],
#                         "userId": user_data.username,
#                         "userEmail": user_data.email,
#                         "createdAt": datetime.now().isoformat()
#                     }
#                 })
#         except WebSocketDisconnect:
#
#             manager.disconnect(user_data.username)
#             await manager.broadcast({
#                 "type": "system",
#                 "data": f"User {user_data.email} left the chat"
#             })
#     except Exception as e:
#         await websocket.close()

if __name__ == "__main__":
    # Main code goes here
    pass
