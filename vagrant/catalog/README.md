
#Item Catalog Project

## Web application that provides a list of items within a variety of categories
## Includes third party authentication via Google OAuth

  This program achieves the following goals including CRUD ops, OAuth, and JSON endpoints

  1. Homepage displays all current categories with a list of the latest items
  2. Selecting a category displays the list of items in the category (READ)
  3. Selecting an item displays the item's details
  4. After logging in via Google OAuth and permitting Google user profile access:
	* User can add a new item (CREATE)
	* User can edit an item (UPDATE)
	* User can delete an item (DELETE)
	* Optional ability to add a Category provided; however, I chose not to allow Category edit or delete
  5. JSON endpoints are made available including Catalog, Category, Item

## Prerequisites

  * If you want to add Catagories or Items to the system, you must have a [Google account](https://accounts.google.com/signup/v2/webcreateaccount?continue=https%3A%2F%2Fwww.google.com%2F%3Fhl%3Den-US&hl=en&gmb=exp&biz=false&flowName=GlifWebSignIn&flowEntry=SignUp)

  * Follow the instruction here including VirtualBox, Vagrant, Git fork and [clone project](https://github.com/udacity/fullstack-nanodegree-vm) 
    [Instructions](https://www.udacity.com/wiki/ud088/vagrant)

  	* Project runs via Python3 - https://www.python.org/downloads/
  	* VirtualBox - https://www.virtualbox.org/
  	* Vagrant - https://www.google.com/url?q=http://vagrantup.com/&sa=D&ust=1574639771872000
  	* After running `vagrant up` run `vagrant ssh` to make the following updates (prefix with `sudo` if necessary)
	  *** I found these in the vagrant file, but had to run them again, maybe due to order of ops in vagrant file or mistake on my part ***

    ```
    pip3 install sqlalchemy flask-sqlalchemy psycopg2-binary bleach requests
    pip3 install flask packaging oauth2client redis passlib flask-httpauth
    pip3 install authlib==0.11
    ```

## Program prepwork

    * Clone this project from github to the _catalog_ directory you cloned above: !!!

    * Ensure the database is created:

	```
	python3 catalog_db_setup.py
	```

    * Preload some data (this will also reset the database if needed--**this truncates the DB!!** and loads example data)

	```
	python3 add_data.py
	```
## Program execution

    * Start the web server:
    ```
    python3 /vagrant/catalog/application.py
    ```

    * Visit the web site, http://localhost:8000


## Known issues

  I've seen problems logging out of the application if/when user is logged in for an extended period.

## Authors

  **Philip Ellis**

## Credits & Updates

  * Code was carved from the FullStack Nanodegree Training 
  * Insights for OAuth were used from Ellis E [comment](https://knowledge.udacity.com/questions/56880)
  * Example data was harvested from Wikipedia.org

