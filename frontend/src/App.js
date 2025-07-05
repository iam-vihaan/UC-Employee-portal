// frontend/src/App.js
import React from 'react';
import EmployeeList from './EmployeeList';
import EmployeeForm from './EmployeeForm';

function App() {
  return (
    <div className="App">
      <h1>Employee Directory</h1>
      <EmployeeForm />
      <EmployeeList />
    </div>
  );
}

export default App;
