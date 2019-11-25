#!/usr/bin/env python3

"""catalog_db_setup.py: Creates the catalog.db
This code was adapted from the Full Stack Web Developer Nanodegree Program
Core Curriculum 4. Servers, Authoriztion and CRUD
Lesson 1 Working with CRUD
which was initially designed for a Restaurant Menu application
"""

__author__ = "Ellis,Philip"
__copyright__ = "Copyright 2019, Planet Earth"

import os
import sys

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import random
import string

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in range(32))


# User table
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String(250))
    email = Column(String(250), index=True)

    def get_id(self):
        return self.id

    @property
    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'picture': self.picture,
            'email': self.email,
        }


# Category parent table
class Category(Base):

    __tablename__ = 'category'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id
        }


# AnItem child table of Category table
class AnItem(Base):

    __tablename__ = 'items'

    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    title = Column(String(80), nullable=False)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serializeItemLong(self):
        return {
            'ADDED_BY': self.user.username,
            'category_id': self.category_id,
            'CATEGORY_NAME': self.category.name,
            'description': self.description,
            'id': self.id,
            'title': self.title,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
