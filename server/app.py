#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):

        new_user = User(
            username = request.get_json().get("username"),
            image_url = request.get_json().get("image_url"),
            bio = request.get_json().get("bio")
        )

        new_user.password_hash = request.get_json().get("password")

        try:
            db.session.add(new_user)
            db.session.commit()

            session["user_id"] = new_user.id

            print(new_user.to_dict())

            return new_user.to_dict(), 201
        
        except IntegrityError:
            return {"error": "422 Unprocessable Entity"}, 422


class CheckSession(Resource):
    def get(self):
        if session.get("user_id"):
            user = User.query.filter(User.id == session["user_id"]).first()

            return user.to_dict(), 200
        
        return {"error": "401 Unauthorized"}, 401

class Login(Resource):
    def post(self):
        username = request.get_json().get("username")
        password = request.get_json().get("password")

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return {"error": "401 Unauthorized"}, 401


class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session["user_id"] = None

            return {}, 204

        return {"error": "401 Unauthrized"}, 401

class RecipeIndex(Resource):
    def get(self):
        if session.get("user_id"):
            user = User.query.filter(User.id == session["user_id"]).first()
            return [recipe.to_dict() for recipe in user.recipes], 200

        return {"error": "401 Unauthorized"}, 401

    def post(self):
        if session.get("user_id"):
            try:
                new_recipe = Recipe(
                    title = request.get_json().get("title"),
                    instructions = request.get_json().get("instructions"),
                    minutes_to_complete = request.get_json().get("minutes_to_complete"),
                    user_id = session["user_id"],
                )

                db.session.add(new_recipe)
                db.session.commit()

                return new_recipe.to_dict(), 201

            except IntegrityError:
                return {"error": "422 Unprocessable Entity"}, 422

        return {"error": "401 Unauthorized"}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
