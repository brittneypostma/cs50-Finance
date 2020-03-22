import os
import sqlite3
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from cachelib.file import FileSystemCache

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

# Configure CS50 Library to use SQLite database sqlite:///
conn = sqlite3.conn("finance.db")
db = conn.cursor()

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT symbol, shares FROM holdings WHERE user_id = ?", session["user_id"])
    users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = users[0]["cash"]
    value = 0
    quotes = []


    for row in rows:
        if row["shares"] != 0:
            quote = {}
            quote["name"] = lookup(row["symbol"]).get('name')
            quote["price"] = lookup(row["symbol"]).get('price')
            quote["total"] = quote["price"] * row["shares"]
            quote["symbol"] = row["symbol"]
            quote["shares"] = row["shares"]
            value += quote["total"]
            quotes.append(quote)

    total = cash + value

    # render template quoted with quote
    return render_template("index.html", quotes=quotes, rows=rows, users=users, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # Check if Post
    if request.method == "POST":

        # Get stock symbol and shares
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Lookup stock symbol return name, price, symbol
        quote = lookup(symbol)
        price = int(quote["price"])
        total = price * shares

        # Check for valid inputs
        if not quote:
            return apology("Sorry, the requested company does not exist.", 403)

        elif not symbol:
            return apology("Symbol cannot be blank.", 403)

        elif not shares:
            return apology("Shares cannot be blank.", 403)

        elif shares < 0:
            return apology("Shares must be a positive number.", 403)

        # Get user
        user = session["user_id"]

        # Variables
        totalShares = 0

        # Query db for users cash
        users = db.execute("SELECT cash FROM users WHERE id = :user", user=user)

        cash = users[0]["cash"]

        # Query db for holdings symbols, shares for users
        holdings = db.execute("SELECT symbol, shares FROM holdings WHERE id = ?", user)

        # Loop over holdings to get list of symbols, shares
        if len(holdings) != 0:
            for row in holdings:
                updShares = shares + row["shares"]
                # Check if symbol exist in holdings
                if row["symbol"] == symbol:
                    # Update shares for that holding
                    db.execute("UPDATE holdings SET shares = ? WHERE id = ? AND symbol = ?",
                               updShares, user, symbol)
                # Else symbol is not in holdings
                else:
                    # Add symbol, shares to holdings
                    db.execute("INSERT INTO holdings (user_id, symbol, shares) VALUES(?, ?, ?)",
                               user, symbol, updShares)

        else:
            db.execute("INSERT INTO holdings (user_id, symbol, shares) VALUES(?, ?, ?)",
                       user, symbol, shares)

        if not cash > total:
            return apology("Sorry, you do not have enough cash to complete transaction.", 403)

        else:
            # Update cash in users to new value
            newCash = cash - total
            db.execute("UPDATE users SET cash = :newCash WHERE id = :user",
                       newCash=newCash, user=user)
            # Insert buy into buy table
            db.execute("INSERT INTO buy (user_id, symbol, shares) VALUES(?, ?, ?)",
                       user, symbol, shares)

        # render template quoted with quote
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user = session["user_id"]

    # Query for buys
    buys = db.execute("SELECT * FROM buy WHERE user_id = :user", user=user)

    # Query for sells
    sells = db.execute("SELECT * FROM sell WHERE user_id = :user", user=user)

    # render template quoted with quote
    return render_template("history.html", buys=buys, sells=sells)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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

    # Check if Post
    if request.method == "POST":

        # Get stock symbol
        symbol = request.form.get("symbol")

        # Lookup stock symbol return name, price, symbol
        quote = lookup(symbol)

        # render template quoted with quote
        return render_template("quoted.html", quote=quote)


    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        name = request.form.get("username")
        pw = request.form.get("password")

        # Ensure username was submitted
        if not name:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not pw:
            return apology("must provide password", 403)

        elif not pw == request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=name)

        # Check if username exists
        if len(rows) > 0:
            return apology("username taken")

        # Hash the password
        hashedPw = generate_password_hash(pw)

        # Insert into db
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=name, hash=hashedPw)


        # Login user
        login()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
        # Check if Post
    if request.method == "POST":

        # Get stock symbol and shares
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Lookup stock symbol return name, price, symbol
        quote = lookup(symbol)

        price = int(quote["price"])
        total = price * shares

        user = session["user_id"]

        # Check for valid inputs
        if not quote:
            return apology("Sorry, the requested company does not exist.", 403)

        elif not symbol:
            return apology("Symbol cannot be blank.", 403)

        elif not shares:
            return apology("Shares cannot be blank.", 403)

        elif shares < 0:
            return apology("Shares must be a positive number.", 403)

        # Query db for users cash
        query = db.execute("SELECT cash FROM users WHERE id = :user", user=user)

        cash = query[0]["cash"]

        # Query holdings for symbol, shares
        holdings = db.execute("SELECT symbol, shares FROM holdings WHERE user_id = ?", user)

        # Check if holdings exists
        if len(holdings) != 0:
            totalShares = holdings[0]["shares"]
            # Check if enough shares to sell
            if totalShares >= shares:
                updShares = totalShares - shares
                # Sell shares
                db.execute("INSERT INTO sell (user_id, symbol, shares) VALUES(?, ?, ?)",
                           user, symbol, shares)
                # Update holdings
                db.execute("UPDATE holdings SET shares = ? WHERE user_id = ? AND symbol = ?",
                           updShares, user, symbol)

            else:
                return apology("Sorry, you do not have that many shares.", 403)
        else:
            return apology("Sorry, you don't own that stock.", 403)


        return redirect("/")

    else:
        return render_template("sell.html")


@app.route("/balance", methods=["GET", "POST"])
@login_required
def balance():
    """Check Balance and Add Money"""
    # Get user
    user = session["user_id"]

   # Query for cash
    query = db.execute("SELECT cash FROM users WHERE id = :user", user=user)
    cash = query[0]["cash"]

    if request.method == "POST":
        # Get amount to add
        amount = request.form.get("amount")

        # total cash
        totalCash = int(amount) + int(cash)

        # Add cash
        db.execute("UPDATE users SET cash = :totalCash WHERE id = :user", totalCash=totalCash, user=user)

        return redirect("/")

    else:
        return render_template("balance.html", cash=cash)



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
