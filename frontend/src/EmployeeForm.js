// frontend/src/EmployeeForm.js
import React, { useState } from 'react';

function EmployeeForm() {
  const [formData, setFormData] = useState({ name: '', department: '', email: '', phone: '' });

  const handleChange = e => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = e => {
    e.preventDefault();
    fetch('/api/employees', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    }).then(() => alert('Employee added'));
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="name" placeholder="Name" onChange={handleChange} />
      <input name="department" placeholder="Department" onChange={handleChange} />
      <input name="email" placeholder="Email" onChange={handleChange} />
      <input name="phone" placeholder="Phone" onChange={handleChange} />
      <button type="submit">Add</button>
    </form>
  );
}

export default EmployeeForm;
