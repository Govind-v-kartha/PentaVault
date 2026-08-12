# Quantum Computing Frameworks — Questions and Answers

# Qiskit — Questions with Answers

## Basic Level

### 1. What is Qiskit?
**Answer:**  
Qiskit is an open-source Python-based quantum computing SDK developed by IBM for designing, simulating, and running quantum circuits on simulators or real quantum computers.

---

### 2. Why was Qiskit developed?
**Answer:**  
Qiskit was developed to provide researchers, students, and developers with tools to program quantum computers using Python.

---

### 3. What is a quantum circuit?
**Answer:**  
A quantum circuit is a sequence of quantum gates and measurements applied to qubits to perform computation.

---

### 4. What is a qubit?
**Answer:**  
A qubit is the basic unit of quantum information. Unlike a classical bit, it can exist in superposition.

---

### 5. What is superposition?
**Answer:**  
Superposition allows a qubit to exist in multiple states simultaneously until measurement.

Mathematically:

\[
|\psi\rangle = \alpha|0\rangle + \beta|1\rangle
\]

where:

\[
|\alpha|^2 + |\beta|^2 = 1
\]

---

### 6. What does the Hadamard gate do?
**Answer:**  
The Hadamard gate creates superposition.

Example:

\[
H|0\rangle = \frac{|0\rangle + |1\rangle}{\sqrt{2}}
\]

---

### 7. What is entanglement?
**Answer:**  
Entanglement is a quantum phenomenon where qubits become correlated such that measuring one instantly affects the other.

---

### 8. What is a CNOT gate?
**Answer:**  
A Controlled-NOT gate flips the target qubit if the control qubit is 1.

| Control | Target | Output |
|---|---|---|
|0|0|00|
|0|1|01|
|1|0|11|
|1|1|10|

---

### 9. What does measurement do?
**Answer:**  
Measurement collapses a qubit from superposition into a classical state (0 or 1).

---

### 10. What is a backend in Qiskit?
**Answer:**  
A backend is the execution target for a quantum circuit, such as:
- Simulator
- Real IBM Quantum hardware

---

# Intermediate Level

### 11. What is transpilation?
**Answer:**  
Transpilation converts a quantum circuit into hardware-compatible instructions optimized for a specific backend.

It includes:
- Gate decomposition
- Qubit mapping
- Circuit optimization

---

### 12. Why is qubit connectivity important?
**Answer:**  
Real quantum hardware has limited qubit connections. If two qubits are not directly connected, SWAP operations are inserted, increasing circuit depth and errors.

---

### 13. What is circuit depth?
**Answer:**  
Circuit depth is the number of sequential layers of operations in a quantum circuit.

Lower depth is preferred because:
- Less decoherence
- Fewer errors
- Faster execution

---

### 14. What is a noisy quantum system?
**Answer:**  
A noisy system experiences errors due to:
- Decoherence
- Thermal noise
- Gate imperfections
- Readout errors

---

### 15. What is a parameterized circuit?
**Answer:**  
A parameterized circuit contains adjustable parameters used in optimization algorithms.

Example:

\[
R_y(\theta)
\]

where \(\theta\) is trainable.

---

### 16. What is VQE?
**Answer:**  
Variational Quantum Eigensolver is a hybrid quantum-classical algorithm used to estimate ground-state energies of molecules.

Workflow:
1. Prepare parameterized circuit
2. Measure expectation values
3. Classical optimizer updates parameters
4. Repeat until convergence

---

### 17. What is QAOA?
**Answer:**  
Quantum Approximate Optimization Algorithm solves combinatorial optimization problems using alternating quantum operators.

---

### 18. What are Sampler and Estimator primitives?
**Answer:**  

#### Sampler
Returns measurement probabilities/counts.

#### Estimator
Computes expectation values of observables.

---

### 19. What is decoherence?
**Answer:**  
Decoherence is the loss of quantum information due to environmental interaction.

It destroys:
- Superposition
- Entanglement

---

### 20. What is quantum volume?
**Answer:**  
Quantum Volume is a benchmark metric measuring overall quantum computer capability considering:
- Qubit count
- Error rates
- Connectivity
- Circuit depth

---

# Advanced Level

### 21. What is OpenQASM?
**Answer:**  
OpenQASM is a quantum assembly language used to describe quantum circuits.

Example:

```qasm
OPENQASM 2.0;
qreg q[2];
h q[0];
cx q[0],q[1];