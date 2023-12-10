package com.david.mysql.repository;

import com.david.mysql.entity.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Integer> {
    // Basic CRUD methods are already provided by JpaRepository

    // You can add custom methods if required
    // Example: List<Employee> findByDepartment(String department);
}

