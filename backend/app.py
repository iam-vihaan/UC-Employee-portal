# backend/app.py
from flask import Flask
from routes import employee_routes

app = Flask(__name__)
app.register_blueprint(employee_routes)

@app.route("/health")
def health():
    return {"status": "healthy"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
