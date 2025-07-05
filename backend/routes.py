# backend/routes.py
from flask import Blueprint, request, jsonify
from models import db, Employee

employee_routes = Blueprint("employee_routes", __name__)

@employee_routes.route("/api/employees", methods=["GET"])
def get_employees():
    name = request.args.get("name")
    department = request.args.get("department")
    query = Employee.query
    if name:
        query = query.filter(Employee.name.ilike(f"%{name}%"))
    if department:
        query = query.filter(Employee.department == department)
    employees = query.all()
    return jsonify([{
        "id": e.id,
        "name": e.name,
        "department": e.department,
        "email": e.email,
        "phone": e.phone
    } for e in employees])

@employee_routes.route("/api/employees/<int:emp_id>", methods=["PUT"])
def update_employee(emp_id):
    employee = Employee.query.get(emp_id)
    if not employee:
        return {"error": "Not found"}, 404
    data = request.json
    for field in ["name", "department", "email", "phone"]:
        if field in data:
            setattr(employee, field, data[field])
    db.session.commit()
    return {"status": "updated"}

@employee_routes.route("/api/employees/<int:emp_id>", methods=["DELETE"])
def delete_employee(emp_id):
    employee = Employee.query.get(emp_id)
    if not employee:
        return {"error": "Not found"}, 404
    db.session.delete(employee)
    db.session.commit()
    return {"status": "deleted"}
