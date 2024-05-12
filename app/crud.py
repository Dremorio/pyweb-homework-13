from sqlalchemy.orm import Session
from . import models, schemas
from datetime import date, timedelta
from sqlalchemy import or_
from fastapi import HTTPException, status
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
SECRET_KEY = "secret_key"


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.UserCreate):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="Email already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, user: schemas.UserCreate):
    db_user = get_user_by_email(db, email=user.email)
    if not db_user:
        raise HTTPException(
            status_code=401, detail="Incorrect email or password")
    if not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=401, detail="Incorrect email or password")
    return db_user


def get_contacts(db: Session, skip: int = 0, limit: int = 100, user_id: int = None):
    if user_id:
        return (
            db.query(models.Contact)
            .filter(models.Contact.owner_id == user_id)
            .offset(skip)
            .limit(limit)
            .all()
        )
    else:
        return db.query(models.Contact).offset(skip).limit(limit).all()


def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    db_contact = models.Contact(**contact.dict(), owner_id=user_id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


def get_contact(db: Session, contact_id: int, user_id: int):
    contact = db.query(models.Contact).filter(
        models.Contact.id == contact_id, models.Contact.owner_id == user_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


def update_contact(db: Session, contact_id: int, contact: schemas.ContactUpdate, user_id: int):
    db_contact = get_contact(db, contact_id, user_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    for key, value in contact.dict(exclude_unset=True).items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact


def delete_contact(db: Session, contact_id: int, user_id: int):
    db_contact = get_contact(db, contact_id, user_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return db_contact


def search_contacts(db: Session, query: str, user_id: int):
    return db.query(models.Contact).filter(
        models.Contact.owner_id == user_id,
        or_(
            models.Contact.first_name.ilike(f"%{query}%"),
            models.Contact.last_name.ilike(f"%{query}%"),
            models.Contact.email.ilike(f"%{query}%")
        )
    ).all()


def get_contacts_with_upcoming_birthdays(db: Session, user_id: int):
    today = date.today()
    next_week = today + timedelta(days=7)
    return db.query(models.Contact).filter(
        models.Contact.owner_id == user_id,
        models.Contact.birthday >= today,
        models.Contact.birthday < next_week
    ).all()
