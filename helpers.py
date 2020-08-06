import os
import requests
import random

from flask import redirect, render_template, flash, session, request, url_for
from functools import wraps

def captcha_check(form_response):
    reCaptcha_SECRET_KEY = "" # UPDATE THIS
    api_request = requests.post("https://www.google.com/recaptcha/api/siteverify", {"secret": reCaptcha_SECRET_KEY, "response": form_response})
    return api_request.json()["success"]

# Python program to convert seconds into hours, minutes and seconds
# https://www.geeksforgeeks.org/python-program-to-convert-seconds-into-hours-minutes-and-seconds/
def convert(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    return "%d:%02d:%02d" % (hour, minutes, seconds)

def filter_shuffle(lst):
    """Shuffle the questions"""
    random.shuffle(lst)
    return lst

def redir(msg, url="endpoint"):
    """Redirect the user and display message"""
    flash(msg)

    if url == "endpoint":
        return redirect(url_for(request.endpoint))

    return redirect(url)

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def not_logged_in(f):
    """Decorate routes to restrict access for logged-in users"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is not None:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def generate_token():
    # Make the call
    call = requests.get("https://opentdb.com/api_token.php", params={"command": "request"})

    # Ensure api call was successfull
    if call.status_code != 200:
        return message("Something went wrong ...", 1)

    # Call data to dictionary
    call = call.json()

    # Check Response Codes
    code = call["response_code"]

    if code == 0:
        session["trivia_token"] = call["token"]
    else:
        return message("Something went wrong ...", 1)

def reset_token():
    # Make the call
    call = requests.get("https://opentdb.com/api_token.php", params={"command": "reset", "token": session["trivia_token"]})

    # Ensure api call was successfull
    if call.status_code != 200:
        return message("Something went wrong ...", 1)

    # Call data to dictionary
    call = call.json()

    # Check Response Codes
    code = call["response_code"]

    if code != 0:
        return message("Something went wrong resetting the token ...", 1)

def check_api_code(call):
    # Ensure API call was successfull
    if call.status_code != 200:
        return message("Something went wrong ...", 1)

    # Call data to dictionary
    call = call.json()

    # Check Response Codes
    code = call["response_code"]

    if code == 0:
        return True
    elif code == 1:
        return message("Could not return results. The website doesn't have enough questions for your query. (Ex. Asking for 50 Questions in a Category that only has 20.)", 1)
    elif code == 2:
        return message("Contains an invalid parameter. Arguements passed in aren't valid. (Ex. Amount = Five)", 1)
    elif code == 3:
        generate_token()
        return message("Session Token does not exist. Try again now.", 1)
    elif code == 4:
        reset_token()
        return message("Session Token has returned all possible questions for the specified query. Resetting the Token is necessary. Try again now.", 1)
