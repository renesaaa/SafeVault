from flask import Flask, request, jsonify
from database import initialize_database, get_connection
from werkzeug.utils import secure_filename
from pathlib import Path
from ai import analyze_text

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"

UPLOAD_FOLDER.mkdir(exist_ok=True)

# Make sure the database exists
initialize_database()


@app.route("/")
def home():
    return "SafeVault Backend is Running!"


@app.route("/api/evidence", methods=["POST"])
def add_evidence():
    data = request.get_json()

    filename = data.get("filename")
    evidence_type = data.get("evidence_type")
    incident_date = data.get("incident_date")
    category = data.get("category")
    severity = data.get("severity")
    summary = data.get("summary")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, evidence_type, incident_date, category, severity, summary)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        filename,
        evidence_type,
        incident_date,
        category,
        severity,
        summary
    ))

    connection.commit()

    new_id = cursor.lastrowid

    connection.close()

    return jsonify({
        "message": "Evidence added successfully!",
        "id": new_id
    }), 201
@app.route("/api/evidence", methods=["GET"])
def get_evidence():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            evidence_type,
            incident_date,
            category,
            severity,
            summary,
            created_at
        FROM evidence
        ORDER BY incident_date ASC
    """)

    rows = cursor.fetchall()

    connection.close()

    evidence_list = []

    for row in rows:
        evidence_list.append({
            "id": row[0],
            "filename": row[1],
            "evidence_type": row[2],
            "incident_date": row[3],
            "category": row[4],
            "severity": row[5],
            "summary": row[6],
            "created_at": row[7]
        })

    return jsonify(evidence_list)
@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({
            "error": "No file uploaded"
        }), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({
            "error": "No file selected"
        }), 400

    filename = secure_filename(file.filename)

    file_path = UPLOAD_FOLDER / filename

    file.save(file_path)

    return jsonify({
        "message": "File uploaded successfully!",
        "filename": filename
    }), 201

@app.route("/api/analyze-evidence", methods=["POST"])
def analyze_evidence():

    data = request.get_json()

    text = data.get("text")

    if not text:
        return jsonify({
            "error": "Evidence text is required"
        }), 400

    # Send the evidence to Gemini
    analysis = analyze_text(text)

    # Get optional information from the request
    filename = data.get("filename", "text-evidence")
    evidence_type = data.get("evidence_type", "text")

    # Save AI analysis to database
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, evidence_type, incident_date, category, severity, summary)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        filename,
        evidence_type,
        analysis.get("incident_date"),
        analysis.get("category"),
        analysis.get("severity"),
        analysis.get("summary")
    ))

    connection.commit()

    new_id = cursor.lastrowid

    connection.close()

    return jsonify({
        "message": "Evidence analyzed and saved successfully!",
        "id": new_id,
        "analysis": analysis
    }), 201
if __name__ == "__main__":
    app.run(debug=True)