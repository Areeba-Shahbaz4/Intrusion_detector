# ZERO TRUST AI INTRUSION DETECTION SYSTEM
# MAIN FLASK APPLICATION
import os
import sqlite3
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from werkzeug.utils import secure_filename
from gmail_integration import fetch_latest_network_file
from predict import predict_csv
from analytics import create_detection_chart
# FLASK APPLICATION
app = Flask(__name__)
# APPLICATION CONFIGURATION
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {
    "csv",
    "txt"
}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
# app.secret_key = "AI_IDS_2026_SECRET_KEY"
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
# FILE VALIDATION
def allowed_file(filename):
    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )
# HOME
@app.route("/")
def home():
    return render_template(
        "index.html"
    )
# LOGIN
@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    if request.method == "POST":
        username = request.form.get(
            "username",
            ""
        ).strip()
        password = request.form.get(
            "password",
            ""
        )
        if not username or not password:
            flash(
                "Please enter username and password.",
                "danger"
            )
            return redirect("/login")
        # DATABASE
        conn = sqlite3.connect(
            "ids.db"
        )
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT password
            FROM users
            WHERE username = ?
            """,
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        # VERIFY PASSWORD
        if (
            user
            and
            check_password_hash(
                user[0],
                password
            )
        ):
            session["user"] = username
            flash(
                "Login successful.",
                "success"
            )
            return redirect(
                "/dashboard"
            )
        flash(
            "Invalid username or password.",
            "danger"
        )
        return redirect(
            "/login"
        )
    return render_template(
        "login.html"
    )
# REGISTER
@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():
    if request.method == "POST":
        full_name = request.form.get(
            "full_name",
            ""
        ).strip()
        username = request.form.get(
            "username",
            ""
        ).strip()
        email = request.form.get(
            "email",
            ""
        ).strip()
        password_input = request.form.get(
            "password",
            ""
        )
        # VALIDATION
        if not all(
            [
                full_name,
                username,
                email,
                password_input
            ]
        ):
            flash(
                "All fields are required.",
                "danger"
            )
            return redirect(
                "/register"
            )
        # HASH PASSWORD
        password = generate_password_hash(
            password_input
        )
        # DATABASE
        conn = sqlite3.connect(
            "ids.db"
        )
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO users
                (
                    full_name,
                    email,
                    username,
                    password
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    full_name,
                    email,
                    username,
                    password
                )
            )
            conn.commit()
            flash(
                "Registration successful. Please login.",
                "success"
            )
            return redirect(
                "/login"
            )
        except sqlite3.IntegrityError:
            flash(
                "Username or email already exists.",
                "danger"
            )
            return redirect(
                "/register"
            )
        finally:
            conn.close()
    return render_template(
        "register.html"
    )
# DASHBOARD
@app.route("/dashboard")
def dashboard():
    # ZERO TRUST AUTHENTICATION
    if "user" not in session:
        return redirect(
            "/login"
        )
    conn = sqlite3.connect(
        "ids.db"
    )
    cursor = conn.cursor()
    # LATEST SCAN
    cursor.execute(
        """
        SELECT
            total_records,
            normal_records,
            attack_records,
            attack_percentage,
            security_status,
            ml_normal,
            ml_attack,
            ml_attack_percentage,
            ml_confidence,
            dl_normal,
            dl_attack,
            dl_attack_percentage,
            dl_confidence,
            model_agreement,
            model_agreement_percentage,
            scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT 1
        """
    )
    latest = cursor.fetchone()
    # SCAN HISTORY
    cursor.execute(
        """
        SELECT
            total_records,
            normal_records,
            attack_records,
            attack_percentage,
            security_status,
            scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT 10
        """
    )
    history = cursor.fetchall()
    conn.close()
    # DASHBOARD
    return render_template(
        "dashboard.html",
        latest=latest,
        history=history
    )
# REPORTS
@app.route("/reports")
def reports():
    # ZERO TRUST AUTHENTICATION
    if "user" not in session:
        return redirect(
            "/login"
        )
    # DATABASE CONNECTION
    conn = sqlite3.connect(
        "ids.db"
    )
    cursor = conn.cursor()
    # GET ALL SCAN REPORTS
    cursor.execute(
        """
        SELECT
            total_records,
            normal_records,
            attack_records,
            attack_percentage,
            security_status,
            ml_normal,
            ml_attack,
            ml_attack_percentage,
            ml_confidence,
            dl_normal,
            dl_attack,
            dl_attack_percentage,
            dl_confidence,
            model_agreement,
            model_agreement_percentage,
            scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT 50
        """
    )
    reports_data = cursor.fetchall()
    conn.close()
    # REPORT PAGE
    return render_template(
        "reports.html",
        reports=reports_data
    )
# ABOUT
@app.route("/about")
def about():
    return render_template(
        "about.html"
    )
# CONTACT
@app.route("/contact")
def contact():
    return render_template(
        "contact.html"
    )
# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "/login"
    )
#gmail scan
@app.route("/gmail-scan")
def gmail_scan():

    if "user" not in session:
        return redirect("/login")

    filepath = None

    try:
        filepath = fetch_latest_network_file(
            app.config["UPLOAD_FOLDER"]
        )

        result = predict_csv(filepath)

        chart_path = create_detection_chart(
            result["normal"],
            result["attack"]
        )

        conn = sqlite3.connect("ids.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scan_history
            (
                total_records,
                normal_records,
                attack_records,
                attack_percentage,
                security_status,
                ml_normal,
                ml_attack,
                ml_attack_percentage,
                ml_confidence,
                dl_normal,
                dl_attack,
                dl_attack_percentage,
                dl_confidence,
                model_agreement,
                model_agreement_percentage
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["total_records"],
                result["normal"],
                result["attack"],
                result["attack_percentage"],
                result["security_status"],
                result["ml_normal"],
                result["ml_attack"],
                result["ml_attack_percentage"],
                result["ml_confidence"],
                result["dl_normal"],
                result["dl_attack"],
                result["dl_attack_percentage"],
                result["dl_confidence"],
                result["model_agreement"],
                result["model_agreement_percentage"]
            )
        )

        conn.commit()
        conn.close()

        return render_template(
            "predict.html",
            result=result,
            chart_path=chart_path,
            error=None
        )

    except Exception as e:

        print("Gmail Scan Error:", str(e))

        return render_template(
            "predict.html",
            result=None,
            chart_path=None,
            error=f"Gmail Scan Error: {str(e)}"
        )

    finally:

        if filepath and os.path.exists(filepath):
            os.remove(filepath)
# AI PREDICTION / SCANNER
@app.route(
    "/predict",
    methods=["GET", "POST"]
)
def predict():
    # ZERO TRUST AUTHENTICATION
    if "user" not in session:
        return redirect(
            "/login"
        )
    # GET REQUEST
    if request.method == "GET":
        return render_template(
            "predict.html",
            result=None,
            error=None
        )
    filepath = None
    try:
        # GET FILE
        file = request.files.get(
            "file"
        )
        # FILE EXISTENCE CHECK
        if (
            file is None
            or
            file.filename == ""
        ):
            return render_template(
                "predict.html",
                result=None,
                error="Please select a CSV or TXT file."
            )
        # FILE TYPE CHECK
        if not allowed_file(
            file.filename
        ):
            return render_template(
                "predict.html",
                result=None,
                error=(
                    "File rejected. "
                    "Only CSV and TXT files are allowed."
                )
            )
        # SECURE FILE NAME
        filename = secure_filename(
            file.filename
        )
        if not filename:
            return render_template(
                "predict.html",
                result=None,
                error="Invalid file name."
            )
        # CREATE UPLOAD DIRECTORY
        os.makedirs(
            app.config["UPLOAD_FOLDER"],
            exist_ok=True
        )
        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )
        # SAVE FILE
        file.save(
            filepath
        )
        # AI PREDICTION
        result = predict_csv(
            filepath
        )
        # CREATE DETECTION CHART
        chart_path = create_detection_chart(
            result["normal"],
            result["attack"]
        )
        # SAVE SCAN RESULT
        conn = sqlite3.connect(
            "ids.db"
        )
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history
            (
                total_records,
                normal_records,
                attack_records,
                attack_percentage,
                security_status,
                ml_normal,
                ml_attack,
                ml_attack_percentage,
                ml_confidence,
                dl_normal,
                dl_attack,
                dl_attack_percentage,
                dl_confidence,
                model_agreement,
                model_agreement_percentage
            )
            VALUES
            (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                result["total_records"],
                result["normal"],
                result["attack"],
                result["attack_percentage"],
                result["security_status"],
                result["ml_normal"],
                result["ml_attack"],
                result["ml_attack_percentage"],
                result["ml_confidence"],
                result["dl_normal"],
                result["dl_attack"],
                result["dl_attack_percentage"],
                result["dl_confidence"],
                result["model_agreement"],
                result["model_agreement_percentage"]
            )
        )
        conn.commit()
        conn.close()
        # REMOVE TEMPORARY UPLOAD
        if filepath and os.path.exists(
            filepath
        ):
            os.remove(
                filepath
            )
        # SHOW RESULT
        return render_template(
            "predict.html",
            result=result,
            chart_path=chart_path,
            error=None
        )
    # ERROR HANDLING
    except Exception as e:
        print(
            "Prediction Error:",
            str(e)
        )
        # CLOSE DATABASE IF NEEDED
        try:
            conn.close()
        except Exception:
            pass
        # REMOVE TEMP FILE
        if filepath and os.path.exists(
            filepath
        ):
            os.remove(
                filepath
            )
        return render_template(
            "predict.html",
            result=None,
            chart_path=None,
            error=f"Prediction Error: {str(e)}"
        )
# RUN APPLICATION
if __name__ == "__main__":
    app.run(
        debug=True
    )