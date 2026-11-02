
import os
import re
import io
import csv
import math
import sqlite3
import joblib

from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, Response, render_template_string



app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "models", "sql_guard_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "sql_guard_vectorizer.pkl")
DATABASE_PATH = os.path.join(BASE_DIR, "security_logs.db")


# =========================================================
# LOAD MACHINE LEARNING MODEL
# =========================================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("SQL Guard ML model not found!")

if not os.path.exists(VECTORIZER_PATH):
    raise FileNotFoundError("SQL Guard vectorizer not found!")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("[+] ML model loaded")
print("[+] Vectorizer loaded")


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():

    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            sql_input TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            model_score REAL,
            source_ip TEXT
        )
    """)

    conn.commit()
    conn.close()


initialize_database()


# =========================================================
# SQL PREPROCESSING
# =========================================================

def preprocess_sql(query):

    query = str(query).lower()
    query = re.sub(r"\s+", " ", query)

    return query.strip()


# =========================================================
# ML DETECTION ENGINE
# =========================================================

def detect_sql(query):

    cleaned = preprocess_sql(query)

    features = vectorizer.transform([cleaned])

    prediction = int(model.predict(features)[0])

    score = None

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(features)[0]
        classes = list(model.classes_)

        if 1 in classes:
            score = float(probabilities[classes.index(1)])

    elif hasattr(model, "decision_function"):

        decision = float(model.decision_function(features)[0])
        decision = max(-30, min(30, abs(decision)))

        # Decision-derived score, not a calibrated probability
        score = 1 / (1 + math.exp(-decision))

    if prediction == 1:
        result = "SQL INJECTION"
        risk = "HIGH"
    else:
        result = "NORMAL"
        risk = "LOW"

    return {
        "prediction": result,
        "risk": risk,
        "score": score
    }


# =========================================================
# SAVE SECURITY EVENT
# =========================================================

def save_event(query, result):

    conn = get_connection()

    conn.execute("""
        INSERT INTO security_events
        (timestamp, sql_input, prediction, risk_level, model_score, source_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        query,
        result["prediction"],
        result["risk"],
        result["score"],
        request.remote_addr or "unknown"
    ))

    conn.commit()
    conn.close()




HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>SQL-GUARD AI | Hacker Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    background: #080808;
    color: #ffffff;
    font-family: "Courier New", monospace;
    overflow-x: hidden;
}

/* MATRIX BACKGROUND */

#matrix {
    position: fixed;
    inset: 0;
    width: 100%;
    height: 100%;
    z-index: 0;
    pointer-events: none;
    opacity: 0.20;
}

.sidebar, .main {
    position: relative;
    z-index: 1;
}

/* SIDEBAR */

.sidebar {
    width: 245px;
    height: 100vh;
    position: fixed;
    top: 0;
    left: 0;
    background: rgba(15, 5, 5, 0.96);
    border-right: 2px solid #ff2020;
    padding: 25px 18px;
    box-shadow: 5px 0 25px rgba(255,0,0,0.12);
}

.sidebar h2 {
    color: #ff2525;
    font-size: 21px;
    text-shadow: 0 0 12px red;
    margin-bottom: 40px;
}

.sidebar .label {
    color: #ff5555;
    font-size: 11px;
    margin-bottom: 15px;
}

.sidebar a {
    display: block;
    color: white;
    padding: 14px;
    margin-bottom: 10px;
    text-decoration: none;
    border: 1px solid transparent;
    border-radius: 5px;
    transition: .3s;
}

.sidebar a:hover {
    color: #ff3030;
    border-color: #ff2020;
    background: rgba(255,0,0,.10);
    box-shadow: 0 0 15px rgba(255,0,0,.2);
}

.online {
    color: #ff3838;
    font-size: 12px;
    margin-top: 30px;
}

/* MAIN */

.main {
    margin-left: 245px;
    padding: 30px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    margin-bottom: 30px;
}

header h1 {
    font-size: 28px;
    color: white;
    text-shadow: 0 0 12px rgba(255,0,0,.5);
}

header p {
    color: #bbbbbb;
    margin-top: 8px;
}

.status {
    background: rgba(255,0,0,.13);
    border: 1px solid #ff2525;
    color: #ff5555;
    padding: 10px 15px;
    border-radius: 5px;
    font-size: 12px;
    box-shadow: 0 0 12px rgba(255,0,0,.2);
}

/* STATISTICS */

.stats {
    display: grid;
    grid-template-columns: repeat(4,1fr);
    gap: 18px;
    margin-bottom: 25px;
}

.card {
    background: rgba(22,12,12,.94);
    border: 1px solid #7d1515;
    border-left: 4px solid #ff2020;
    border-radius: 8px;
    padding: 23px;
    transition: .3s;
}

.card:hover {
    transform: translateY(-5px);
    border-color: #ff3030;
    box-shadow: 0 0 20px rgba(255,0,0,.23);
}

.card p {
    color: #dddddd;
    font-size: 13px;
}

.card h2 {
    margin-top: 16px;
    font-size: 32px;
}

#attacks {
    color: #ff3030;
    text-shadow: 0 0 12px red;
}

#normal {
    color: white;
}

/* PANELS */

.panel {
    background: rgba(15,10,10,.95);
    border: 1px solid #7d1515;
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 0 15px rgba(255,0,0,.08);
}

.panel h2 {
    color: white;
    margin-bottom: 10px;
}

.subtitle {
    color: #bbbbbb;
    font-size: 13px;
    margin-bottom: 20px;
}

/* INPUT */

textarea {
    width: 100%;
    height: 130px;
    background: #080808;
    color: #ff5555;
    border: 1px solid #aa2020;
    border-radius: 6px;
    padding: 16px;
    font-size: 14px;
    resize: vertical;
    outline: none;
    font-family: Consolas, monospace;
}

textarea:focus {
    border-color: #ff2222;
    box-shadow: 0 0 15px rgba(255,0,0,.25);
}

.analyzer-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-top: 15px;
}

.analyzer-footer span {
    color: #bbbbbb;
    font-size: 12px;
}

/* BUTTONS */

button, .export {
    background: #c90000;
    color: white;
    padding: 12px 20px;
    border: 1px solid #ff4040;
    border-radius: 5px;
    cursor: pointer;
    font-weight: bold;
    text-decoration: none;
    display: inline-block;
    transition: .3s;
}

button:hover, .export:hover {
    background: #ff1717;
    box-shadow: 0 0 20px #ff2020;
}

button:disabled {
    opacity: .6;
    cursor: wait;
}

/* RESULTS */

.result {
    padding: 17px;
    margin-top: 20px;
    background: #100808;
    border: 1px solid #777;
    border-radius: 6px;
    overflow-wrap: anywhere;
}

.normal {
    color: white;
    border-color: white;
}

.malicious {
    color: #ff4545;
    border-color: #ff2020;
    box-shadow: 0 0 12px rgba(255,0,0,.2);
}

.error {
    color: #ffb3b3;
    border-color: #ff7777;
}

/* CHART */

.chart-container {
    max-width: 600px;
    height: 300px;
    margin: auto;
}

/* TABLE */

.table-wrapper {
    width: 100%;
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 700px;
}

th, td {
    padding: 13px;
    text-align: left;
    border-bottom: 1px solid #492020;
    font-size: 12px;
}

th {
    color: #ff5555;
    background: #170909;
}

td {
    color: #eeeeee;
}

.badge-normal {
    color: white;
    font-weight: bold;
}

.badge-danger {
    color: #ff3535;
    font-weight: bold;
    text-shadow: 0 0 7px red;
}

footer {
    text-align: center;
    padding: 20px;
    color: #ff5555;
    font-size: 12px;
    border-top: 1px solid #661111;
}

/* RESPONSIVE */

@media(max-width:1000px) {
    .stats {
        grid-template-columns: repeat(2,1fr);
    }
}

@media(max-width:650px) {
    .sidebar {
        width: 100%;
        height: auto;
        position: relative;
    }

    .main {
        margin-left: 0;
        padding: 15px;
    }

    .stats {
        grid-template-columns: 1fr;
    }

    header {
        align-items: flex-start;
        flex-direction: column;
    }

    .analyzer-footer {
        align-items: flex-start;
        flex-direction: column;
    }
}

</style>

</head>

<body>

<canvas id="matrix"></canvas>

<div class="sidebar">

    <h2>🛡 SQL-GUARD AI</h2>

    <p class="label">SECURITY OPERATIONS</p>

    <a href="#overview">▦ Dashboard</a>
    <a href="#analyzer">⌕ SQL Analyzer</a>
    <a href="#analytics">◷ Analytics</a>
    <a href="#logs">▤ Security Logs</a>

    <div class="online">● ML ENGINE READY</div>

</div>


<div class="main">

<header>

    <div>
        <h1>THREAT MONITORING CENTER</h1>
        <p>AI Powered SQL Injection Detection System</p>
    </div>

    <div class="status">● SYSTEM ONLINE</div>

</header>


<!-- STATISTICS -->

<section id="overview" class="stats">

    <div class="card">
        <p>TOTAL QUERIES</p>
        <h2 id="total">0</h2>
    </div>

    <div class="card">
        <p>SQL INJECTION ATTACKS</p>
        <h2 id="attacks">0</h2>
    </div>

    <div class="card">
        <p>NORMAL QUERIES</p>
        <h2 id="normal">0</h2>
    </div>

    <div class="card">
        <p>LAST 24 HOURS</p>
        <h2 id="recent">0</h2>
    </div>

</section>


<!-- SQL ANALYZER -->

<section id="analyzer" class="panel">

    <h2>⌕ SQL QUERY ANALYZER</h2>

    <p class="subtitle">
        Submit SQL input for machine learning security analysis.
    </p>

    <textarea
        id="sqlInput"
        maxlength="5000"
        placeholder="Enter SQL query or user input here..."
    ></textarea>

    <div class="analyzer-footer">

        <span>MAXIMUM 5000 CHARACTERS</span>

        <button id="analyzeButton" onclick="analyzeQuery()">
            ANALYZE QUERY
        </button>

    </div>

    <div id="result" class="result">
        Waiting for SQL input...
    </div>

</section>


<!-- ANALYTICS -->

<section id="analytics" class="panel">

    <h2>◷ ATTACK ANALYTICS</h2>

    <p class="subtitle">
        Normal versus malicious input distribution.
    </p>

    <div class="chart-container">
        <canvas id="attackChart"></canvas>
    </div>

</section>


<!-- EVENT LOGS -->

<section id="logs" class="panel">

    <div class="analyzer-footer">

        <div>
            <h2>▤ SECURITY EVENT LOGS</h2>
            <p class="subtitle">Latest 100 detection events.</p>
        </div>

        <a href="/export" class="export">
            EXPORT CSV
        </a>

    </div>

    <div class="table-wrapper">

        <table>

            <thead>
                <tr>
                    <th>ID</th>
                    <th>TIMESTAMP</th>
                    <th>SQL INPUT</th>
                    <th>PREDICTION</th>
                    <th>RISK</th>
                    <th>SOURCE IP</th>
                </tr>
            </thead>

            <tbody id="eventTable">
                <tr>
                    <td colspan="6">Loading...</td>
                </tr>
            </tbody>

        </table>

    </div>

</section>


<footer>
    SQL-GUARD AI | RED ALERT SECURITY MONITORING SYSTEM
</footer>

</div>


<script>


const matrixCanvas = document.getElementById("matrix");
const matrixCtx = matrixCanvas.getContext("2d");

const characters = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&<>";

let matrixColumns = [];
const fontSize = 15;

function resizeMatrix() {

    matrixCanvas.width = window.innerWidth;
    matrixCanvas.height = window.innerHeight;

    const columns = Math.ceil(
        matrixCanvas.width / fontSize
    );

    matrixColumns = Array(columns).fill(1);
}

resizeMatrix();

window.addEventListener("resize", resizeMatrix);

function drawMatrix() {

    matrixCtx.fillStyle = "rgba(0,0,0,0.09)";

    matrixCtx.fillRect(
        0, 0,
        matrixCanvas.width,
        matrixCanvas.height
    );

    matrixCtx.font = fontSize + "px monospace";

    matrixColumns.forEach((y, index) => {

        const character = characters[
            Math.floor(Math.random() * characters.length)
        ];

        matrixCtx.fillStyle =
            Math.random() > 0.96 ? "#ffffff" : "#ff2525";

        matrixCtx.fillText(
            character,
            index * fontSize,
            y * fontSize
        );

        if (
            y * fontSize > matrixCanvas.height &&
            Math.random() > 0.975
        ) {
            matrixColumns[index] = 0;
        }

        matrixColumns[index]++;

    });

}

setInterval(drawMatrix, 55);


// =====================================================
// ATTACK ANALYTICS CHART
// =====================================================

const chart = new Chart(
    document.getElementById("attackChart"),
    {
        type: "doughnut",

        data: {
            labels: [
                "NORMAL QUERIES",
                "SQL INJECTION"
            ],

            datasets: [{
                data: [0, 0],
                backgroundColor: [
                    "#ffffff",
                    "#ff2020"
                ],
                borderWidth: 0
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#ffffff",
                        padding: 20
                    }
                }
            }
        }
    }
);


// =====================================================
// ANALYZE SQL INPUT
// =====================================================

async function analyzeQuery() {

    const query = document.getElementById("sqlInput").value.trim();

    const result = document.getElementById("result");

    const button = document.getElementById("analyzeButton");

    if (!query) {

        result.textContent = "Please enter SQL input.";

        result.className = "result error";

        return;
    }

    button.disabled = true;
    button.textContent = "ANALYZING...";

    result.textContent = "ML engine analysing query...";
    result.className = "result";

    try {

        const response = await fetch("/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                query: query
            })

        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
        }

        const score = data.model_score === null
            ? "Unavailable"
            : (data.model_score * 100).toFixed(2) + "%";

        result.textContent =
            "PREDICTION: " + data.prediction +
            " | RISK: " + data.risk +
            " | MODEL SCORE: " + score;

        result.className =
            data.prediction === "SQL INJECTION"
            ? "result malicious"
            : "result normal";

        await refreshDashboard();

    }

    catch(error) {

        result.textContent = error.message;
        result.className = "result error";

    }

    finally {

        button.disabled = false;
        button.textContent = "ANALYZE QUERY";

    }

}


// =====================================================
// LOAD STATISTICS
// =====================================================

async function loadStats() {

    try {

        const response = await fetch("/stats");

        if (!response.ok) throw new Error("Statistics failed");

        const data = await response.json();

        document.getElementById("total").textContent = data.total;
        document.getElementById("attacks").textContent = data.attacks;
        document.getElementById("normal").textContent = data.normal;
        document.getElementById("recent").textContent = data.recent;

        chart.data.datasets[0].data = [
            data.normal,
            data.attacks
        ];

        chart.update();

    }

    catch(error) {
        console.error(error);
    }

}


// =====================================================
// LOAD EVENT LOGS
// =====================================================

async function loadEvents() {

    try {

        const response = await fetch("/events");

        if (!response.ok) throw new Error("Events failed");

        const events = await response.json();

        const table = document.getElementById("eventTable");

        table.replaceChildren();

        if (events.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 6;
            cell.textContent = "No events recorded.";

            row.appendChild(cell);
            table.appendChild(row);

            return;
        }

        events.forEach(event => {

            const row = document.createElement("tr");

            const values = [
                event.id,
                new Date(event.timestamp).toLocaleString(),
                event.sql_input,
                event.prediction,
                event.risk_level,
                event.source_ip
            ];

            values.forEach((value, index) => {

                const cell = document.createElement("td");

                cell.textContent = value ?? "";

                if (index === 3) {

                    cell.className =
                        value === "SQL INJECTION"
                        ? "badge-danger"
                        : "badge-normal";

                }

                row.appendChild(cell);

            });

            table.appendChild(row);

        });

    }

    catch(error) {
        console.error(error);
    }

}


// =====================================================
// DASHBOARD REFRESH
// =====================================================

async function refreshDashboard() {

    await Promise.all([
        loadStats(),
        loadEvents()
    ]);

}

refreshDashboard();

setInterval(refreshDashboard, 3000);

</script>

</body>
</html>
"""


# =========================================================
# DASHBOARD ROUTE
# =========================================================

@app.route("/")
def dashboard():

    return render_template_string(HTML)


# =========================================================
# SQL ANALYSIS API
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON input"}), 400

    query = data.get("query", "")

    if not isinstance(query, str) or not query.strip():
        return jsonify({"error": "Enter SQL input"}), 400

    if len(query) > 5000:
        return jsonify({"error": "Input too long"}), 413

    try:

        result = detect_sql(query)

        save_event(query, result)

        return jsonify({

            "success": True,

            "prediction": result["prediction"],

            "risk": result["risk"],

            "model_score": result["score"],

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat()

        })

    except Exception:

        app.logger.exception("Detection failed")

        return jsonify({
            "error": "ML analysis failed"
        }), 500


# =========================================================
# STATISTICS API
# =========================================================

@app.route("/stats")
def stats():

    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0]

    attacks = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE prediction='SQL INJECTION'"
    ).fetchone()[0]

    normal = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE prediction='NORMAL'"
    ).fetchone()[0]

    recent = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE timestamp >= ?",
        (
            (datetime.now(timezone.utc) -
             timedelta(hours=24)).isoformat(),
        )
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "total": total,
        "attacks": attacks,
        "normal": normal,
        "recent": recent
    })


# =========================================================
# SECURITY EVENT API
# =========================================================

@app.route("/events")
def events():

    conn = get_connection()

    rows = conn.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return jsonify([
        dict(row) for row in rows
    ])


# =========================================================
# CSV FORENSIC REPORT
# =========================================================

@app.route("/export")
def export():

    conn = get_connection()

    rows = conn.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "SQL Input",
        "Prediction",
        "Risk Level",
        "Model Score",
        "Source IP"
    ])

    for row in rows:

        writer.writerow([
            row["id"],
            row["timestamp"],
            row["sql_input"],
            row["prediction"],
            row["risk_level"],
            row["model_score"],
            row["source_ip"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=sql_guard_forensic_report.csv"
        }
    )


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    print("\n==========================================")
    print("          SQL-GUARD AI")
    print("    RED HACKER SECURITY DASHBOARD")
    print("==========================================")
    print("[+] Machine Learning: READY")
    print("[+] Vectorizer: READY")
    print("[+] Database: READY")
    print("[+] Matrix Background: ENABLED")
    print("[+] Dashboard: http://127.0.0.1:5000")
    print("==========================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
