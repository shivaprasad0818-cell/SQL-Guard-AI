# SQL-Guard AI
### Machine Learning-Based SQL Injection Detection and Security Monitoring System

**Project Domain:** Cybersecurity | Machine Learning | Web Application Security | Digital Forensics

## 1. Project Overview

SQL-Guard AI is a machine learning-based SQL injection detection and security monitoring system designed to identify potentially malicious SQL inputs and distinguish them from legitimate queries.

The system uses Natural Language Processing techniques and machine learning classification algorithms to analyse SQL input patterns and generate security alerts.

It provides a real-time monitoring dashboard with attack statistics, detection history and forensic event reporting.

## 2. Objectives

- Develop a machine learning model for SQL injection detection.
- Classify SQL inputs as normal or malicious.
- Compare multiple machine learning algorithms.
- Provide a real-time security monitoring dashboard.
- Maintain security event logs for forensic investigation.
- Generate downloadable CSV reports.

## 3. Technologies Used

| Component | Technology |
|---|---|
| Programming Language | Python |
| Machine Learning | Scikit-learn |
| NLP | TF-IDF |
| Backend | Flask |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Data Analysis | Pandas, NumPy |
| Visualization | Chart.js |
| Development | Google Colab, VS Code |

## 4. Machine Learning Algorithms

The training experiments include:

- Logistic Regression
- Random Forest
- Linear Support Vector Machine

The models are evaluated using accuracy, precision, recall, F1-score and confusion matrix.

## 5. Main Features

- SQL injection detection using machine learning.
- Normal and malicious input classification.
- Red and white hacker-themed dashboard.
- Animated Matrix-style background.
- Real-time security statistics.
- Attack analytics visualization.
- Security event logging.
- CSV forensic report export.

## 6. Project Structure

```text
SQL-Guard-AI/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── models/
├── dataset/
├── screenshots/
└── docs/
```

## 7. Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd SQL-Guard-AI
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Place the trusted trained model and vectorizer files in the `models` directory according to `models/MODEL_INSTRUCTIONS.md`.

## 8. Run the Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## 9. Dashboard Modules

1. SQL Query Analyzer
2. Machine Learning Detection Engine
3. Attack Analytics
4. Security Event Logging
5. Forensic CSV Report Generation

## 10. Model Evaluation

Model performance should be reported using experimentally measured results on an independent test dataset.

Do not treat synthetic-data accuracy as proof of real-world SQL injection detection performance.

## 11. Security and Limitations

This project is an educational detection and monitoring prototype. It does not execute SQL queries or provide production-grade database protection.

Production applications should also implement parameterized queries, authentication, authorization, input validation and other security controls.

Only test with authorized systems and controlled environments.

## 12. Future Enhancements

- BiLSTM and Transformer-based SQL injection detection.
- Explainable AI using SHAP.
- Advanced attack categorization.
- Real-time application firewall integration.
- Evidence integrity hashing.
- Advanced forensic investigation reports.

## 13. Author

**Project:** SQL-Guard AI

**Academic Area:** MSc Digital Forensics and Information Security

**Repository:** Machine Learning-Based SQL Injection Detection and Prevention System
