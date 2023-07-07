from flask import Flask, make_response, redirect, request, render_template
from urllib.parse import urlencode
from flask_restful import Resource, Api
from dotenv import load_dotenv, find_dotenv
import secrets
import requests
import os

app = Flask(__name__)
api = Api(app)
load_dotenv(find_dotenv())

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
BASE_URL = os.getenv('BASE_URL')
MAL_AUTH_URL = 'https://myanimelist.net/v1/oauth2/authorize'
MAL_TOKEN_URL = 'https://myanimelist.net/v1/oauth2/token'

class Login(Resource):
    def get(self):
        state = secrets.token_urlsafe(16)
        code_challenge = secrets.token_urlsafe(50)

        params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'plain'
        }

        resp = make_response(redirect(
            MAL_AUTH_URL
            + '?'
            + urlencode(query=params)
        ))

        resp.set_cookie('state', state)
        resp.set_cookie('code_challenge', code_challenge)

        return resp
    
class Callback(Resource):
    def get(self):
        code = request.args.get('code')
        state = request.args.get('state')

        if state != request.cookies.get('state'):
            return make_response('Invalid state', 400)
        
        code_verifier = request.cookies.get('code_challenge')

        r = requests.post(MAL_TOKEN_URL, headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }, data = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code"
            })

        accessTokens = r.json()

        responce = make_response(redirect(f"{BASE_URL}/authenticated"))

        responce.set_cookie('access_token', accessTokens['access_token'])
        responce.set_cookie('refresh_token', accessTokens['refresh_token'])

        return responce

class Authenticated(Resource):
    def get(self):
        accessToken = request.cookies.get('access_token')
        refreshToken = request.cookies.get('refresh_token')

        return make_response(render_template(
            "authenticated.html",
            accessToken = accessToken,
            refreshToken = refreshToken
        ))

api.add_resource(Login, '/login')
api.add_resource(Callback, '/callback')
api.add_resource(Authenticated, '/authenticated')

if __name__ == '__main__':
    app.run(debug=True, port=8000)