#!/usr/bin/env python3

"""add_data.py: This program loads up the catalog.db"""

__author__ = "Ellis,Philip"
__copyright__ = "Copyright 2019, Planet Earth"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from catalog_db_setup import Base, User, Category, AnItem

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

try:
    # delete all items
    allitems = session.query(AnItem).delete()
    session.commit()

    # delete all categories
    allcats = session.query(Category).delete()
    session.commit()

    # delete all users
    allusers = session.query(User).delete()
    session.commit()

except BaseException:
    session.rollback()
    exit()


User1 = User(username="John Smith", email="john.smith@gmail.com", picture="NA")
session.add(User1)
session.commit()

# Theropoda
Category1 = Category(name="Theropoda", user_id=1)
session.add(Category1)
session.commit()

item1 = AnItem(
    title="Herrerasauria",
    description="Early bipedal carnivores",
    category=Category1, user_id=1)
session.add(item1)
session.commit()

item2 = AnItem(
    title="Coelophysoidea",
    description="Small, early theropods," +
                "includes Coelophysis and close relatives",
    category=Category1,
    user_id=1)
session.add(item2)
session.commit()

item3 = AnItem(
    title="Dilophosauridae",
    description="Early crested and carnivorous theropods",
    category=Category1, user_id=1)
session.add(item3)
session.commit()

item4 = AnItem(
    title="Ceratosauria",
    description="Generally elaborately horned, the dominant " +
                "southern carnivores of the Cretaceous",
    category=Category1, user_id=1)
session.add(item4)
session.commit()

item5 = AnItem(
    title="Tetanurae",
    description="stiff tails; includes most theropods",
    category=Category1, user_id=1)
session.add(item5)
session.commit()

# Sauropodomorpha
Category2 = Category(name="Sauropodomorpha", user_id=1)
session.add(Category2)
session.commit()

item1 = AnItem(
    title="Buriolestes",
    description="From the Late Triassic Santa Maria Formation" +
                " of the Paraná Basin in southern Brazil",
    category=Category2, user_id=1)
session.add(item1)
session.commit()

item2 = AnItem(
    title="Nyasasaurus",
    description="From the Middle Triassic Manda Formation" +
                " of Tanzania that appears to be the earliest known dinosaur",
    category=Category2, user_id=1)
session.add(item2)
session.commit()

item3 = AnItem(
    title="Guaibasauridae",
    description="Known from fossil remains of late " +
                "Triassic period formations in Brazil and Argentina",
    category=Category2, user_id=1)
session.add(item3)
session.commit()

item4 = AnItem(
    title="Bagualosauria", description="New", category=Category2, user_id=1)
session.add(item4)
session.commit()

# Ornithischia
Category3 = Category(name="Ornithischia", user_id=1)
session.add(Category3)
session.commit()

item1 = AnItem(
    title="Thyreophora ",
    description="Group of armored ornithischian dinosaurs that " +
                "lived from the early Jurassic Period until the " +
                "end of the Cretaceous",
    category=Category3, user_id=1)
session.add(item1)
session.commit()

item2 = AnItem(
    title="Cerapoda",
    description="Two groups: Ornithopoda (bird-foot) and " +
                "Marginocephalia (fringed heads).",
    category=Category3, user_id=1)
session.add(item2)
session.commit()

print("All Done!")
