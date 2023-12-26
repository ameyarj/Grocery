
# eGrocery
The eGrocery web app is a platform designed for both Users and the Business owners. Users can signup, login, Search, Buy, See Purchase History, Edit Profile, Give Feedback. Business Owners have two Roless - Store Manager and Admin. Store Manager can Signup, Login(Only when Approved by Admin), Add Product, Edit Product, Export sales and Inventory as CSV, Submit Request to Admin to Add a New Category, Send Messages to Admin, Graphically view the Sales and Stock charts. Admin can Create a New Category(only for Amdin), Edit Category, Approve/Reject -> (Signup requests, Add Category Requests , Messages) from Store Manager. Asynchronous processing of tasks using Celery -> Sending Reminders to users to visit website, Sending Purchase History ad Montlhy Activity Report to the Users. Data storage using SQLite.Caching with Redis.


## Technologies Used

- **Python Flask:** A web framework for building the backend of the application.
- **SQLite:** A lightweight and easy-to-use database for data storage.
- **Redis:** An in-memory data structure store for caching.
- **Celery:** A distributed task queue for handling asynchronous tasks.
- **Vue.js:** A progressive JavaScript framework for building user interfaces.

# Getting Started
### Prerequisites
To run BlogLite on your local device, you will need to have the following installed:

- Python 3
- Pip
- Node.js

### Installation
#### Frontend

```sh
npm install
```

```sh
npm run serve
```

#### Backend
```
start the redis server
```
redis-server
```
start the celery beat
```
celery -A send.celery beat --loglevel=info
```
```
start the celery worker

celery -A send.celery worker -l info -P eventlet
```
start the app

```
pyhton app.py

```


