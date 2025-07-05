# backend/app.py
from flask import Flask
from routes import employee_routes
from auth import init_jwt
from models import db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

init_jwt(app)
db.init_app(app)
app.register_blueprint(employee_routes)

@app.route("/health")
def health():
    return {"status": "healthy"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
