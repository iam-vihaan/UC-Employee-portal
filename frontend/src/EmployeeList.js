// frontend/src/EmployeeList.js
import React, { useEffect, useState } from 'react';

function EmployeeList() {
  const [employees, setEmployees] = useState([]);

  useEffect(() => {
    fetch('/api/employees')
      .then(res => res.json())
      .then(data => setEmployees(data));
  }, []);

  return (
    <div>
      <h2>Employee List</h2>
      <ul>
        {employees.map(emp => (
          <li key={emp.id}>{emp.name} - {emp.department}</li>
        ))}
      </ul>
    </div>
  );
}

export default EmployeeList;
