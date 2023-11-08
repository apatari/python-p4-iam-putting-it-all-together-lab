#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        try:
            user = User(
                username=json.get('username'),
                image_url=json.get('image_url'),
                bio=json.get('bio'),
            )
            user.password_hash=json.get("password")
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except Exception as err:
            
            return {"errors": [repr(err)]}, 422

class CheckSession(Resource):
    
    def get(self):
        user = User.query.filter_by(id=session.get('user_id')).first()

        if user:
            response_body = {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }
            return response_body, 200
        else:
            return {"message": "Error, user not logged in"}, 401

class Login(Resource):
    
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            response_body = {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }
            return response_body, 200
        else:
            return {"errors": ["Error: invalid username and/or password"]}, 401


class Logout(Resource):
    
    def delete(self):

        user = User.query.filter_by(id=session.get('user_id')).first()

        if user:
            session['user_id'] = None
            return {}, 204
        else:
            return {"message": "error, cannot log out, you are not logged in"}, 401


class RecipeIndex(Resource):
    
    def get(self):

        if session.get('user_id'):
            response_body = [recipe.to_dict() for recipe in Recipe.query.all()]
            return response_body, 200
        else:
            return {"message": "error, not logged in"}, 401
        
    def post(self):
        if session.get('user_id'):
            try:
                json = request.get_json()
                new_recipe = Recipe(
                    user_id=session['user_id'],
                    title=json['title'],
                    instructions=json['instructions'],
                    minutes_to_complete=json['minutes_to_complete']
                )
                db.session.add(new_recipe)
                db.session.commit()

                return new_recipe.to_dict(), 201
            
            except Exception as err: 
                return {"error": repr(err)}, 422 
        else:
            return {"message": "error, not logged in"}, 401



api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)