#!/usr/bin/env python3

"""project.py: This program serves a website"""

__author__ = "Ellis,Philip"
__copyright__ = "Copyright 2019, Planet Earth"

import json
import random
import string
import bleach
import requests
import http.client
import urllib.request

from catalog_db_setup import AnItem, Base, Category, User
from flask import (Flask, flash, jsonify, make_response, redirect,
                   render_template, request)
from flask import session
from flask import url_for
from flask_httpauth import HTTPBasicAuth
from oauth2client.client import (FlowExchangeError, flow_from_clientsecrets,
                                 OAuth2WebServerFlow)
from sqlalchemy import create_engine, asc, desc, join
from sqlalchemy.orm import sessionmaker
from authlib.client import OAuth2Session

SESSION_COOKIE_SECURE = True
REMEMBER_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_HTTPONLY = True

app = Flask(__name__)

# Reminders
CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']
PROJECT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['project_id']
USER_AGENT = json.loads(open(
    'client_secrets.json', 'r').read())['web']['user-agent']
CLIENT_SECRET = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_secret']
AUTH_URI = json.loads(open(
    'client_secrets.json', 'r').read())['web']['auth_uri']
AUTH_CERT = json.loads(open(
    'client_secrets.json', 'r').read())['web']['auth_provider_x509_cert_url']
REDIRECT_URIS = json.loads(open(
    'client_secrets.json', 'r').read())['web']['redirect_uris']
TOKEN_URI = json.loads(open(
    'client_secrets.json', 'r').read())['web']['token_uri']

SCOPES = "openid profile email"

# Create session and connect to catalog.db, ignore thread transitions
engine = create_engine(
    'sqlite:///catalog.db',
    connect_args={'check_same_thread': False},
    echo=True)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
sessionDB = DBSession()


# Method to obtain a user record set from an email
def getUserID(email):
    try:
        userRS = sessionDB.query(User).filter_by(email=email).one()
        return userRS
    except BaseException:
        return None


# Method to obtain a user record set from the user_id
def getUserInfo(user_id):
    try:
        userRS = sessionDB.query(User).filter_by(id=user_id).one()
        return userRS
    except BaseException:
        return None


# Method to create a user for the Item Catalog
def createUser(session):
    newUser = User(username=session['username'],
                   email=session['email'],
                   picture=session['picture'])
    sessionDB.add(newUser)
    sessionDB.commit()
    userRS = sessionDB.query(User).filter_by(
        email=session['email']).one()
    return userRS


# Method to generate a state key
def genState():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    session['state'] = state
    session.modified = True
    return state


# Method to obtain session's state key
def getState():
    try:
        state = session['state']
        return state
    except BaseException:
        flash('Cannot read/write Cookies')
        return redirect(url_for('showLogin'))


# Route for login using anti-fogery state token
@app.route('/login')
def showLogin():
    state = genState()
    try:
        allusers = sessionDB.query(User).all()
        allcats = sessionDB.query(Category).all()
        allitems = sessionDB.query(Category.name, AnItem.title, AnItem.id,
                                   AnItem.user_id).filter(
            Category.id == AnItem.category_id).order_by(
            desc(AnItem.id)).limit(10)
        return render_template('login.html', STATE=state, category=allcats,
                               items=allitems, users=allusers)
    except BaseException:
        return "Catalog database cannot be queried."


# Route to sign into Google and login to Item Catalog
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Make sure request is from our user
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # STEP1 Proceed to get one time authorization code from server
    code = request.data
    try:
        # STEP2 Upgrade the authorization code into a credentials
        # object (contains access_token)
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='',
            redirect_uri='http://localhost:8000')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/userinfo/v2/me?access_token=%s' % access_token)  # noqa
    try:
        r = requests.get(url)
        responseJSON = r.json()
    except BaseException:
        response = make_response(json.dumps('Unable to obtain token.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # If there was an error in the access token info, abort.
    if responseJSON.get('error') is not None:
        response = make_response(responseJSON['error'], 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    # Return 'gplus_id= '+gplus_id
    if responseJSON['id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user ID does not match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check to see if user is already logged in
    stored_credentials = session.get('credentials')
    stored_access_token = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    # Skip rest if user already logged in
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        flash("Current user is already connected")
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    session['access_token'] = credentials.access_token
    session['gplus_id'] = gplus_id
    # Get user info
    session['username'] = responseJSON['name']
    session['picture'] = responseJSON['picture']
    session['email'] = responseJSON['email']
    # See if user exists, if it doesn't make a new one
    userRS = getUserID(session['email'])
    if not userRS:
        # Create User
        userRS = createUser(session)
        # Create initial Category
        firstCategory = Category(
            name="Your_1st_Category",
            user_id=userRS.id)
        sessionDB.add(firstCategory)
        sessionDB.commit()
        # Get Category ID
        theCat = sessionDB.query(Category).filter_by(
            name="Your_1st_Category", user_id=userRS.id).one()
        # Create initial Item
        firstItem = AnItem(
            category_id=theCat.id,
            title="Your_1st_Item",
            description="The description (250 chars max)",
            user_id=userRS.id)
        sessionDB.add(firstItem)
        sessionDB.commit()
    session['user_id'] = userRS.id
    session.modified = True
    # Report back results
    flash("Welcome " + session.get('username') + " you are now logged in.")
    response = make_response(json.dumps(
        "Welcome "+session['username']+"!"), 200)
    response.headers['Content-Type'] = 'application/json'
    # response.set_cookie('somekey', 'someval',
    # domain='.mydomain.com', samesite='None')
    # response.set_cookie('same-site-cookie',
    # 'foo', SameSite='Lax')
    # response.headers.add('Set-Cookie',
    # 'cross-site-cookie=bar; SameSite=None; Secure')
    return response


# Route to disconnect Google and log out of Item Catalog
@app.route('/gdisconnect', methods=['POST'])
def gdisconnect():
    access_token = session.get('access_token')
    if access_token is None:
        # Clear out user anyway
        del session['gplus_id']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        session.modified = True
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % session['access_token']  # noqa
    r = requests.get(url)
    responseJSON = r.json()
    # Drop all user session info
    if r.status_code == 200:
        del session['access_token']
        del session['gplus_id']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        session.modified = True
        response = make_response(json.dumps(
            'Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # Clear out user anyway
        del session['access_token']
        del session['gplus_id']
        del session['username']
        del session['email']
        del session['picture']
        del session['user_id']
        session.modified = True
        flash("Failed to revoke Google token: "+r.status_code)
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Route to obtain JSON for all users
@app.route('/catalog_user.json')
def JSONcatalogUsers():
    userlist = sessionDB.query(User).all()
    return jsonify(Users=[u.serialize for u in userlist])


# Route to obtain entire Catalog JSON
@app.route('/catalog.json')
def JSONcatalog():
    allUsers = sessionDB.query(User).all()
    thisGuy = []
    for u in allUsers:
        thisCategory = []
        allCategory = sessionDB.query(Category).filter_by(user_id=u.id).all()
        for c in allCategory:
            thisItem = []
            allAnItem = sessionDB.query(AnItem).filter_by(
                category_id=c.id).all()
            for i in allAnItem:
                thisItem.append({"id": i.id,
                                 "category_id": i.category_id,
                                 "title": i.title,
                                 "description": i.description,
                                 "user_id": i.user_id})
            thisCategory.append({"name": c.name,
                                 "id": c.id,
                                 "user_id": c.user_id,
                                 "zItem": thisItem})
        thisGuy.append({"email": "priviledged info",
                        "id": u.id,
                        "picture": u.picture,
                        "username": u.username,
                        "zCategory": thisCategory})
    theUsers = {'User': thisGuy}
    return jsonify(theUsers)


# Route to obtain entire JSON for user
@app.route('/catalog/<int:user_id>/JSON')
def JSONcatalogUser(user_id):
    allUsers = sessionDB.query(User).filter_by(id=user_id).all()
    thisGuy = []
    for u in allUsers:
        thisCategory = []
        allCategory = sessionDB.query(Category).filter_by(user_id=u.id).all()
        for c in allCategory:
            thisItem = []
            allAnItem = sessionDB.query(AnItem).filter_by(
                category_id=c.id).all()
            for i in allAnItem:
                thisItem.append({"id": i.id,
                                 "category_id": i.category_id,
                                 "title": i.title,
                                 "description": i.description,
                                 "user_id": i.user_id})
            thisCategory.append({"name": c.name,
                                 "id": c.id,
                                 "user_id": c.user_id,
                                 "zItem": thisItem})
        thisGuy.append({"email": "priviledged info",
                        "id": u.id,
                        "picture": u.picture,
                        "username": u.username,
                        "zCategory": thisCategory})
    theUsers = {'User': thisGuy}
    return jsonify(theUsers)


# Route to obtain JSON for all items in a Category
@app.route('/catalog/<string:category_name>/<int:user_id>/JSON')
def JSONcatalogCategory(category_name, user_id):
    cat = bleach.clean(category_name)
    allUsers = sessionDB.query(User).filter_by(id=user_id).all()
    thisGuy = []
    for u in allUsers:
        thisCategory = []
        allCategory = sessionDB.query(Category).filter_by(
            user_id=u.id, name=cat).all()
        for c in allCategory:
            thisItem = []
            allAnItem = sessionDB.query(AnItem).filter_by(
                category_id=c.id).all()
            for i in allAnItem:
                thisItem.append({"id": i.id,
                                 "category_id": i.category_id,
                                 "title": i.title,
                                 "description": i.description,
                                 "user_id": i.user_id})
            thisCategory.append({"name": c.name,
                                 "id": c.id,
                                 "user_id": c.user_id,
                                 "zItem": thisItem})
        thisGuy.append({"email": "priviledged info",
                        "id": u.id,
                        "picture": u.picture,
                        "username": u.username,
                        "zCategory": thisCategory})
    theUsers = {'User': thisGuy}
    return jsonify(theUsers)


# Route to obtain one item JSON
@app.route('/catalog/' +
           '<string:category_name>/<string:item_title>/<int:user_id>/JSON')
def JSONcatalogItem(category_name, item_title, user_id):
    cat = bleach.clean(category_name)
    it = bleach.clean(item_title)
    category = sessionDB.query(Category).filter_by(
        name=cat, user_id=user_id).one()
    item = sessionDB.query(AnItem).filter_by(
        category_id=category.id, title=it).one()
    return jsonify(Item=item.serializeItemLong)


# Redirect to user's Catalog or login screen
@app.route('/')
def CatalogViewer():
    state = getState()
    try:
        if 'user_id' in session:
            firstcat = sessionDB.query(Category).filter_by(
                user_id=session['user_id']).first()
            return redirect(url_for(
                'CategoryViewer',
                category_name=firstcat.name,
                user_id=session['user_id']))
        else:
            return redirect(url_for('showLogin'))
    except BaseException:
        flash("Catalog Viewer failed")
        return redirect(url_for('showLogin'))


# Route to view user's Catalog
@app.route('/catalog/<string:category_name>/<int:user_id>/Items')
def CategoryViewer(category_name='Brick', user_id=1):
    cat = bleach.clean(category_name)
    state = getState()
    # If a user is logged in
    try:
        if 'user_id' in session:
            # If logged in user selects Item not in user's list
            if session['user_id'] != user_id:
                allcats = sessionDB.query(Category).filter_by(
                    user_id=user_id).all()
                allitems = sessionDB.query(
                    Category.id, Category.name, AnItem.title,
                    AnItem.user_id).filter(
                    Category.id == AnItem.category_id).filter_by(
                    name=cat, user_id=user_id).order_by(
                    asc(AnItem.title))
                thisUser = sessionDB.query(User).filter_by(
                    id=user_id).one()
                mine = sessionDB.query(Category).filter_by(
                    user_id=session['user_id']).all()
                count = allitems.count()
                return render_template(
                    'catalog.html',
                    STATE=state, category=allcats, items=allitems,
                    count=count, User=thisUser, mine=mine)
            else:
                # User selects Items user owns
                allcats = sessionDB.query(Category).filter_by(
                    user_id=session['user_id']).all()
                allitems = sessionDB.query(
                    Category.id, Category.name, AnItem.title,
                    AnItem.user_id).filter(
                    Category.id == AnItem.category_id).filter_by(
                    name=cat,
                    user_id=session['user_id']).order_by(asc(AnItem.title))
                thisUser = sessionDB.query(User).filter_by(
                    id=session['user_id']).one()
                count = allitems.count()
                return render_template(
                    'catalog.html',
                    STATE=state, category=allcats, items=allitems,
                    count=count, User=thisUser, mine=allcats)
    except BaseException:
        return 'Category Viewer failed for your Items'
    # If a user is not logged in
    try:
        allcats = sessionDB.query(Category).filter_by(
            user_id=user_id).all()
        allitems = sessionDB.query(
            Category.id, Category.name, AnItem.title, AnItem.id,
            AnItem.user_id).filter(
            Category.id == AnItem.category_id).filter_by(
            name=cat, user_id=user_id).order_by(asc(AnItem.id))
        thisUser = sessionDB.query(User).filter_by(id=user_id).one()
        count = allitems.count()
        return render_template(
            'catalog.html', STATE=state,
            category=allcats, items=allitems,
            count=count, User=thisUser,
            mine=allcats)
    except BaseException:
        flash("No Items found for this Category and User.")
        return redirect(url_for('showLogin'))


# Route to view an Item's details
@app.route('/catalog/<string:category_name>/' +
           '<string:item_title>/<int:user_id>')
def ItemDetails(category_name='Brick', item_title='1x1', user_id=1):
    cat = bleach.clean(category_name)
    it = bleach.clean(item_title)
    state = getState()
    try:
        thisUser = sessionDB.query(User).filter_by(id=user_id).one()
        thisCat = sessionDB.query(Category).filter_by(
            name=cat, user_id=user_id).one()
        thisItem = sessionDB.query(AnItem).filter_by(
            category_id=thisCat.id, title=it,
            user_id=user_id).one()
        return render_template(
            'itemDetails.html',
            STATE=state, category=thisCat,
            items=thisItem, user=thisUser)
    except BaseException:
        flash("Item does not exist for this Category and User")
        return redirect(url_for('showLogin'))


# Route to create a new Category
@app.route('/catalog/newCat', methods=['GET', 'POST'])
def newCategory():
    state = getState()
    if 'user_id' not in session:
        flash("Must be logged in to create New Catgories")
        return redirect('/login')
    else:
        user_id = session['user_id']
        allcats = sessionDB.query(Category).filter_by(
            user_id=user_id).all()
    if request.method == 'POST':
        try:
            # Grab user-entered Item title
            thisCategory = bleach.clean(
                request.form['chosenCat'].replace(" ", "_"))

            # Ensure proper data entry
            if thisCategory == "":
                flash("You must enter a Category Name")
                return redirect(url_for('newCategory'))

            # Check if user already has this Category
            checkNewCat = sessionDB.query(Category).filter_by(
                user_id=session['user_id']).all()

            # Iterate existing Items to see if new item exists already
            for c in checkNewCat:
                if c.name == thisCategory:
                    flash("The Category you entered already exists,"
                          " no changes were made.")
                    return redirect(url_for('newCategory'))

            # Add new Category
            newCategory = Category(
                name=thisCategory,
                user_id=session['user_id'])
            sessionDB.add(newCategory)
            sessionDB.commit()

            # Add default Item
            theCat = sessionDB.query(Category).filter_by(
                name=thisCategory, user_id=session['user_id']).one()
            # Create initial Item
            firstItem = AnItem(
                category_id=theCat.id,
                title=thisCategory+"_1st_Item",
                description="The description (250 chars max)",
                user_id=session['user_id'])
            sessionDB.add(firstItem)
            sessionDB.commit()

            # Reassure user of item addition
            flash("New Category ["+thisCategory+"] created, "
                  "please edit the default item.")
            return redirect(url_for(
                'editAnItem',
                category_name=thisCategory,
                item_title=thisCategory+"_1st_Item",
                user_id=session['user_id']))
        except BaseException:
            flash("newCategory POST failed.")
            return redirect(url_for('CatalogViewer'))
    else:
        return render_template(
            'newCat.html',
            STATE=state,
            category=allcats)


# Route to create a new Item
@app.route('/catalog/new', methods=['GET', 'POST'])
def newItem():
    state = getState()
    if 'user_id' not in session:
        flash("Must be logged in to create New Items")
        return redirect('/login')
    else:
        user_id = session['user_id']
        allcats = sessionDB.query(Category).filter_by(
            user_id=user_id).all()
    if request.method == 'POST':
        try:
            # Grab user-entered Item title
            thisTitle = bleach.clean(
                request.form['chosenTitle'].replace(" ", "_"))
            # Grab user-entered Item description
            thisDescription = bleach.clean(request.form['chosenDescription'])

            # Ensure proper data entry
            if thisTitle == "" or thisDescription == "":
                flash("You must enter a title and a description")
                return redirect(url_for('newItem'))

            # Not possible with GUI, fail-safe only
            if not request.form['selectedCategory']:
                flash("You must select a Category")
                return redirect(url_for('newItem'))

            # Grab user-selected category
            newCat = bleach.clean(request.form['selectedCategory'])

            # Check if user already has this Item and Category
            checkNewCat = sessionDB.query(Category).filter_by(
                name=newCat, user_id=session['user_id']).one()
            checkNewCatItem = sessionDB.query(AnItem).filter_by(
                category_id=checkNewCat.id,
                user_id=session['user_id']).all()

            # Iterate existing Items to see if new item exists already
            for c in checkNewCatItem:
                if c.title == thisTitle:
                    flash("The Category you selected already has this item: "
                          + thisTitle + " no changes were made.")
                    return redirect(url_for(
                        'CategoryViewer',
                        category_name=checkNewCat.name,
                        user_id=session['user_id']))

            # Add new Item
            newItem = AnItem(
                title=thisTitle,
                description=thisDescription,
                category_id=checkNewCat.id,
                user_id=session['user_id'])
            sessionDB.add(newItem)
            sessionDB.commit()
            # Reassure user of item addition
            flash("New item ["+thisTitle+"] created!")
            return redirect(url_for(
                'CategoryViewer',
                category_name=checkNewCat.name,
                user_id=session['user_id']))
        except BaseException:
            flash("newItem POST failed.")
            return redirect(url_for('CatalogViewer'))
    else:
        return render_template(
            'newItem.html',
            STATE=state,
            category=allcats)


# Route to Edit an Item in a Category
@app.route('/catalog/<string:category_name>/' +
           '<string:item_title>/<int:user_id>/edit',
           methods=['GET', 'POST'])
def editAnItem(category_name, item_title, user_id):
    cat = bleach.clean(category_name)
    it = bleach.clean(item_title)
    state = getState()
    # Force user to login to edit items
    if 'user_id' not in session:
        flash("Must be logged in to edit Items")
        return redirect('/login')
    # Process only if logged in user owns this Item
    try:
        if user_id == session['user_id']:
            # Setup recordsets
            allcats = sessionDB.query(Category).filter_by(
                user_id=session['user_id']).all()
            thiscat = sessionDB.query(Category).filter_by(
                name=cat, user_id=session['user_id']).one()
            thisitem = sessionDB.query(AnItem).filter_by(
                category_id=thiscat.id, title=it).one()
            editedItem = sessionDB.query(AnItem).filter_by(
                title=it, category_id=thiscat.id,
                user_id=session['user_id']).one()
    except BaseException:
        flash("Unable to find Item.")
        return redirect('/login')

    # Handle devious page loads
    try:
        if user_id != session['user_id']:
            u = sessionDB.query(User).filter_by(id=user_id).one()
            flash("You cannot edit this Item, it is owned by "+u.username)
            return redirect('/login')
    except BaseException:
        flash("You cannot edit this Item, USER_ID=" + user_id +
              " does not exist.")
        return redirect('/login')

    if request.method == 'POST':
        try:
            # INIT Local Vars (to retain non-edited values)
            newTitle = editedItem.title
            newDesc = editedItem.description
            newCat = thiscat.name
            # Grab category option from category selection
            if bleach.clean(request.form['selectedCategory']) != newCat:
                newCat = bleach.clean(request.form['selectedCategory'])
                checkNewCat = sessionDB.query(Category).filter_by(
                    name=newCat, user_id=session['user_id']).one()
                checkNewCatItem = sessionDB.query(AnItem).filter_by(
                    category_id=checkNewCat.id,
                    user_id=session['user_id']).all()
                for c in checkNewCatItem:
                    if c.title == newTitle:
                        flash("The Category you selected already has " +
                              "an item "+newTitle+" no changes were made.")
                        return redirect(url_for(
                            'CategoryViewer',
                            category_name=cat,
                            user_id=session['user_id']))
            countItems = sessionDB.query(AnItem).filter_by(
                category_id=thiscat.id).count()
            # Do not allow a user to leave a category with no items
            if countItems == 1 and thiscat.name != request.form['selectedCategory']:
                flash("You cannot move the last item out of a Category. " +
                      "No changes were made.")
                return redirect(url_for(
                        'CategoryViewer',
                        category_name=cat,
                        user_id=session['user_id']))
            # Change item's assigned Category
            if thiscat.name != request.form['selectedCategory']:
                c = sessionDB.query(Category).filter_by(
                    name=request.form['selectedCategory']).one()
                editedItem.category_id = c.id
                sessionDB.add(editedItem)
                sessionDB.commit()
            # If chosenTitle or chosenDescription not altered, don't change
            # Grab edited Item title
            if bleach.clean(request.form['chosenTitle']) != "":
                newTitle = bleach.clean(request.form['chosenTitle'])
                editedItem.title = newTitle
                sessionDB.add(editedItem)
                sessionDB.commit()
            # Grab edited Item description
            if bleach.clean(request.form['chosenDescription']) != "":
                newDesc = bleach.clean(request.form['chosenDescription'])
                editedItem.description = newDesc
                sessionDB.add(editedItem)
                sessionDB.commit()
            # Reassure user of update
            flash("Item updated: ["+newTitle+"]")
            return redirect(url_for(
                'CategoryViewer',
                category_name=cat,
                user_id=session['user_id']))
        except BaseException:
            flash('editAnItem POST failed')
            return redirect(url_for('CatalogViewer'))
    else:
        return render_template(
            'editItem.html', STATE=state,
            category=allcats, thiscat=thiscat, items=thisitem,
            user_id=session['user_id'])


# Route to Delete an Item from a Category
@app.route('/catalog/<string:category_name>/<string:item_title>/' +
           '<int:user_id>/delete', methods=['GET', 'POST'])
def deleteAnItem(category_name, item_title, user_id):
    cat = bleach.clean(category_name)
    it = bleach.clean(item_title)
    state = getState()
    # Force user to login to delete items
    if 'user_id' not in session:
        flash("Must be logged in to delete Items")
        return redirect('/login')

    # Process only if logged in user owns this Item
    try:
        if user_id == session['user_id']:
            inCat = sessionDB.query(Category).filter_by(
                name=cat, user_id=session['user_id']).one()
            inItem = sessionDB.query(AnItem).filter_by(
                title=it, category_id=inCat.id,
                user_id=session['user_id']).one()
    except BaseException:
        flash("Unable to find Item.")
        return redirect('/login')

    # Handle devious page loads
    try:
        if user_id != session['user_id']:
            u = sessionDB.query(User).filter_by(id=user_id).one()
            flash("You cannot delete this Item, it is owned by "+u.username)
            return redirect('/login')
    except BaseException:
        flash("You cannot delete this Item, USER_ID=" + user_id +
              " does not exist.")
        return redirect('/login')

    if request.method == 'POST':
        # Make sure user is not trying to delete category's only item
        thisCat = sessionDB.query(Category).filter_by(
            name=cat, user_id=session['user_id']).one()
        allitems = sessionDB.query(AnItem.id).filter_by(
                user_id=session['user_id'],
                category_id=thisCat.id).count()
        if allitems == 1:
            flash("You must have at least one item in each Category.")
            return render_template(
                'deleteItem.html', STATE=state,
                category=inCat, item=inItem, user_id=user_id)
        try:
            # Delete the item and provide feedback
            sessionDB.delete(inItem)
            sessionDB.commit()
            flash(" Item [" + it + "] deleted!")
            return redirect(url_for(
                'CategoryViewer',
                category_name=cat,
                user_id=user_id))
        except BaseException:
            flash("deleteAnItem POST failed")
            return redirect('/login')

    else:
        return render_template(
            'deleteItem.html', STATE=state,
            category=inCat, item=inItem, user_id=user_id)


if __name__ == '__main__':
    try:
        app.secret_key = 'wherever you go there you are'
        app.debug = True
        app.run(host='0.0.0.0', port=8000)
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()
        # Close any broken threads due to AT&T firewall
        try:
            sys.stdout.close()
        except BaseException:
            pass
        try:
            sys.stderr.close()
        except BaseException:
            pass
