import os

class Config:
    SECRET_KEY = 'secreta_jwt'
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///campus.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'