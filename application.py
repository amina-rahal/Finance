import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    TOT = 0
    rows = db.execute("""SELECT symbol, SUM(shares) AS totalshares
                        FROM transactions
                        WHERE user_id = :user_id
                        GROUP BY symbol
                        HAVING totalshares > 0""", user_id=session['user_id'])

    owns = []
    for row in rows:
        quote = lookup(row['symbol'])
        owns.append({
            'Symbol': quote['symbol'],
            'Shares': row['totalshares'],
            'Price': usd(quote['price']),
            'Total': usd(quote['price'] * row['totalshares'])
        })
        TOT += quote['price'] * row['totalshares']

    # show user's cash
    roww = db.execute('SELECT cash FROM users WHERE id=:user_id', user_id=session['user_id'])
    cash = roww[0]['cash']
    TOT += cash

    return render_template('index.html', owns=owns, cash=usd(cash), TOT=usd(TOT))
    

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'GET':
        return render_template('buy.html')

    if request.method == 'POST':
        # check inputs
        if request.form.get("symbol"):
            # get stock quote from API
            sym = lookup(request.form.get("symbol"))
        else:
            return apology("Missing Stock Name!", 400)
        # check for invalid symbol
        if sym == None:
            return apology("Invalid Stock Name!", 400)
        
        if not request.form.get('shares'):
            return apology('please enter a number of shares', 400)

        if not request.form.get('shares').isdigit():
            return apology('please enter a valid number of shares!', 400)

        elif int(request.form.get('shares')) < 1:
            return apology('please enter a postive integer', 400)

        # save the data
        price = sym.get('price')
        share = int(request.form.get('shares'))
        symbol = request.form.get('symbol').upper()

        # buying process
        cash = db.execute('SELECT cash FROM users WHERE id = :id', id=session['user_id'])
        Cash = cash[0]['cash']
        total = share * price
        cash_new = Cash - total
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # check if there is enough cash
        if cash_new >= price:
            # insert data into db
            db.execute('INSERT INTO transactions (user_id, price, shares, symbol, transacted) VALUES (:user_id, :price, :shares, :symbol, :transacted)', 
                       user_id=session['user_id'], price=price, shares=share, symbol=symbol, transacted=timestamp)

            # update user's cash when the purchase is made
            db.execute('UPDATE users SET cash= :cash_new WHERE id = :id', cash_new=cash_new, id=session['user_id'])

            # flash a success message
            flash("bought!")
            return redirect("/")
        else:
            return apology("Not enough cash!")
            

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol AS Symbol, shares AS Shares, price AS Price, transacted AS Timestamp \
                                FROM transactions WHERE user_id = :u_id", u_id=session['user_id'])

    return render_template("history.html", transactions=transactions)
    

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Please enter valid symbol", 400)
        else:
            symbol = quote.get("symbol")
            price = quote.get("price")
            return render_template("quoted.html", symbol=symbol, price=usd(price))
            

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing username!", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing password!", 400)

        # Ensure password equals condirmation password submitted
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)
        else:
            # Ensure username doesn't exist already in database
            if len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) == 0:
                # hash the password
                pwdhash = generate_password_hash(request.form.get("password"))
                # insert user to the database
                uid = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                                 username=request.form.get("username"), hash=pwdhash)
                session["user_id"] = uid
                # Redirect user to home page
                flash("Registered successfully!")
                return redirect("/")
            else:
                return apology("Please choose another username!", 400)

    return render_template("register.html")
    

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    rows = db.execute(
        "SELECT symbol AS Symbol, SUM(shares) AS Shares FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session['user_id'])

    # Create stock dropdown list for buy form
    if request.method == "GET":
        symbols = []
        for stock in rows:
            symbols.append(stock.get("Symbol"))
        return render_template("sell.html", symbols=symbols)

    if request.method == 'POST':
        # save inputs
        shares = request.form.get("shares")
        symbol_sale = request.form.get("symbol")

        share_stock = db.execute(
            "SELECT SUM(shares) as shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol", user_id=session['user_id'], symbol=symbol_sale)
        share_stock = int(share_stock[0]["shares"])
        # checking valid inputs
        if not shares:
            return apology("Missing Share Quantity!", 400)
        elif not shares.isdigit():
            return apology("Please enter a positive numeric number", 400)
        elif int(shares) < 1:
            return apology("Please enter a positive number", 400)
        # check if user has enough shares to sell
        elif int(shares) > share_stock:
            return apology("Not enough shares in your portfolio", 400)
        else:
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session['user_id'])
            balance = cash[0]["cash"]
            quote = lookup(symbol_sale)
            price = quote.get("price")
            shares_sale = int(shares)
            new_balance = balance + price * shares_sale
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # update cash in user account
            db.execute("UPDATE users SET cash = :cash WHERE id=:id", cash=new_balance, id=session["user_id"])

            # store transaction data in the database
            db.execute("INSERT INTO transactions (symbol, shares, transacted, user_id, price) \
            VALUES(:symbol, :shares, :transacted, :user_id, :price)", symbol=symbol_sale, shares=-shares_sale, transacted=timestamp, user_id=session["user_id"], price=price)

        # flash a success message
        flash("Successfully sold!")
        return redirect("/")


@app.route("/change_pw", methods=["GET", "POST"])
@login_required
def change_pw():
    """Let user change the password"""
    if request.method == "GET":
        return render_template("change_pw.html")

    if request.method == "POST":
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("Missing password!", 400)

        # Ensure password equals condirmation password submitted
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)
        else:
            # hash the password
            pwdhash = generate_password_hash(request.form.get("password"))
            db.execute("UPDATE users SET hash = :hash WHERE id=:id", hash=pwdhash, id=session["user_id"])
            # Redirect user to home page
            flash("Password changed!")
            return redirect("/")
            

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
