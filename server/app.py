#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()

        if 'username' not in json or 'password' not in json:
            return{'message': 'Username and password are required'}, 400

        # Check if user already exists
        existing_user = User.query.filter_by(username=json['username']).first()
        if existing_user:
            return {'message': 'Username already exists'}, 400

        # Create the new user and hash the password
        user = User(username=json['username'])
        user.password_hash = json['password']

        # Save user to the database
        db.session.add(user)
        db.session.commit()

        # Save the user's ID in the session to keep them logged in
        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        # Check if the user is logged in by verifying session data
        if 'user_id' not in session:
            return {}, 204  # No user in session, return 204 No Content

        # Find the user from the session
        user = User.query.get(session['user_id'])
        if not user:
            return {'message': 'User not found'}, 404
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        json = request.get_json()

        # Ensure that username and password are provided
        if 'username' not in json or 'password' not in json:
            return {'message': 'Username and password are required'}, 400

        # Find the user by username
        user = User.query.filter_by(username=json['username']).first()
        # Authenticate the user by checking the hashed password
        if user is None or not user.authenticate(json['password']):
            return {'message': 'Invalid username or password'}, 401

        # Save the user's ID in the session to keep them logged in
        session['user_id'] = user.id

        return user.to_dict(), 200

class Logout(Resource):
    def delete(self):
        # Properly clear session on logout
        session.pop('user_id', None)  # Clear 'user_id' from the session
        return {}, 204


api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
