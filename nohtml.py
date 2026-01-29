import google.generativeai as genai
from PIL import Image
from flask import Flask, request, jsonify, render_template_string, redirect, url_for,session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import io
import os
import json
from datetime import datetime, timezone,timedelta # Import timezone for UTC timestamps
import pytz
import re
import uuid
import bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from sqlalchemy import func
from datetime import datetime, timedelta
import random
import smtplib
from flask import request, jsonify
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

from ingredients_analyzer import analyze_ingredients_to_json, analyze_single_ingredient_to_json

app = Flask(__name__)
# Define the upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads') 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///ingrify_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress a warning


app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'your_super_secret_jwt_key_please_change_me') # Use a strong, random key in production
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7) 

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app) 
load_dotenv()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=True) # Age can be optional
    password_hash = db.Column(db.String(255), nullable=False) # Stores the bcrypt hashed password
    email = db.Column(db.String(120), unique=True, nullable=True)

    search_history = db.relationship('SearchEntry', backref='user', lazy=True, cascade="all, delete-orphan")

    allergens = db.relationship('Allergen', backref='user', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class Allergen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    allergen_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    added_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(ist))

    def __repr__(self):
        return f"<Allergen '{self.allergen_name}' for User {self.user_id}>"

    
ist=pytz.timezone('Asia/Kolkata')
class SearchEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    search_text = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(ist)) # Store with timezone info
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    raw_ocr_text = db.Column(db.Text, nullable=True)
    analysis_json_str = db.Column(db.JSON, nullable=True)
    image_filename = db.Column(db.String(255), nullable=True)
    overall_safety = db.Column(db.JSON, nullable=True, default=lambda: {
        "score": 0,
        "safety_colour": "#FFFFFF"
    })

    

    def __repr__(self):
        return f"<SearchEntry {self.search_text} at {self.timestamp}>"

    def to_dict(self):
        # Convert timestamp to ISO 8601 string for easy frontend parsing
        return {
            'id': self.id,
            'query': self.search_text, # Keep 'query' key for API/frontend consistency if desired
            'timestamp': self.timestamp.isoformat()
        }
class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(ist))  # Use your IST timezone

    def __repr__(self):
        return f"<PasswordResetOTP {self.email} - {self.otp}>"

    def is_expired(self):
        now = datetime.now() 
        return now > self.created_at + timedelta(minutes=10)

class TempSignup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(ist))


with app.app_context():
    db.create_all()


try:
    API_KEY = os.environ["GEMINI_API_KEY"]
except KeyError:
    print("WARNING: GEMINI_API_KEY environment variable not found. ")

genai.configure(api_key=API_KEY)


# vision_model = genai.GenerativeModel(model_name="gemini-1.5-flash-latest")
vision_model = genai.GenerativeModel(model_name="gemma-3-4b-it")

@jwt_required()
def get_current_user_id():
    user_id = get_jwt_identity()   # gets the id from JWT
    return int(user_id) if user_id else None


#Summa for debugging created get request 
@app.route('/')
def index():
    return redirect(url_for('ocr_and_analyze'))




# / will redirect here (same summa for debugging)
@app.route('/ocr', methods=['GET', 'POST'])
def ocr_and_analyze():
    if request.method == 'GET':
        return jsonify({"message": "Use POST to upload an image and receive OCR & analysis."})

    elif request.method == 'POST':
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User not authenticated or not found"}), 401

        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        image_file = request.files['image']

        if not image_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            return jsonify({"error": "Invalid image file type"}), 400

        try:
            current_ist_time = datetime.now(ist)
            timestamp_string = current_ist_time.strftime('%Y%m%d_%H%M%S')
            original_filename = image_file.filename
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            unique_filename = f"INGRIFY_{timestamp_string}.{file_extension}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            image_file.save(image_path)

            with open(image_path, 'rb') as img_f:
                image_data_for_gemini = img_f.read()
            image_object_for_gemini = Image.open(io.BytesIO(image_data_for_gemini))

        #     combined_prompt = """
        #    From the provided image, perform OCR to accurately identify only actual product ingredients or components (such as chemical compounds, natural extracts, food additives, vitamins, oils, acids). Ignore all non-ingredient text including addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing or country-of-origin details, batch numbers, and expiry dates.
        #     ABSOLUTELY MUST FOLLOW:
        #     Only output ingredients actually present in the image.
        #     Do NOT add, guess, infer, or generate any ingredient not in the image. If it is not visible, it must not appear in the output.
        #     Ignore all non-ingredient text: addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing details, batch numbers, expiry dates, country-of-origin, or any other unrelated text like MRP, USP etc.
        #         If the image does not contain ingredients, output:
        # { "raw_ocr_text": "", "analysis": [] }
        # After identifying them, generate a single JSON object. This JSON object must have two top-level keys:
        #     1.  `raw_ocr_text`: A string containing a comma-separated list of all identified ingredients (as plain text).
        #     2.  `analysis`: A JSON array of objects, where each object represents an individual ingredient. Each ingredient object must have the following keys:
        #         - `name`: The exact name of the ingredient as identified.
        #         - `use`: A very simple explanation (max 1-2 sentences) of what the ingredient does in the product, using only easy-to-understand words suitable for a 10-year-old.
        #         - `Made from`: A one-line description of the ingredient's source or common origin.
        #         - `side_effects`: Any common or potential side effects or considerations.
        #         - `allergen`: A boolean (true/false) indicating if it is a common or potential allergen.

        #     Ensure the entire output is a single, valid JSON object and contains NO other text, markdown fences (like ```json), or explanations outside this JSON.
        # """
            
            combined_prompt="""From the provided image, perform OCR to accurately identify only actual product ingredients or components (such as chemical compounds, natural extracts, food additives, vitamins, oils, acids). 

Ignore all non-ingredient text including: addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing or country-of-origin details, batch numbers, expiry dates, MRP, USP, or any other unrelated text.

ABSOLUTELY MUST FOLLOW:
- Only output ingredients actually present in the image.
- Do NOT add, guess, infer, or generate any ingredient not in the image. If it is not visible, it must not appear in the output.
- If the image does not contain ingredients, output exactly:
{ "raw_ocr_text": "", "analysis": [], "overall_safety": { "score": 0, "safety_colour": "#95A5A6" } }

After identifying the ingredients, generate a single JSON object with these top-level keys:

1. `raw_ocr_text`: A string containing a comma-separated list of all identified ingredients (as plain text).

2. `analysis`: A JSON array of objects, where each object represents an individual ingredient. Each object must contain:
   - `name`: The exact name of the ingredient as identified.
   - `use`: A very simple explanation (max 1-2 sentences) of what the ingredient does in the product, using only easy words suitable for a 10-year-old.
   - `made_from`: A one-line description of the ingredient's source or common origin.
   - `side_effects`: Any common or potential side effects or considerations.
   - `allergen`: A boolean (true/false) indicating if it is a common or potential allergen.
   - `safety_colour`: Hex code (#2ECC71 for safe, #F1C40F for moderate risk, #E74C3C for high risk).

3. `overall_safety`: An object with two fields:
   - `score`:  A number between 0 and 100 that must be consistent with the individual ingredient safety levels. 
       * If **all ingredients have safety_colour = #2ECC71 (green)** → score must be between 0-20. 
       * If **at least one ingredient has safety_colour = #F1C40F (yellow)** → score must be between 30-60. 
       * If **at least one ingredient has safety_colour = #E74C3C (red)** → score must be between 70-100. 
   - `safety_colour`: Must strictly match the score:
       * 0-20 → #2ECC71 (green)
       * 30-60 → #F1C40F (yellow)
       * 70-100 → #E74C3C (red)

Ensure the output is:
- A single valid JSON object.
- Contains NO other text, explanations, or markdown fences.
"""

            combined_response = vision_model.generate_content(
                [image_object_for_gemini, combined_prompt],
                stream=False,
            )

            raw_model_output = combined_response.text.strip()
            
            if raw_model_output.startswith("```json") and raw_model_output.endswith("```"):
                raw_model_output = raw_model_output[7:-3].strip()

            parsed_combined_result = json.loads(raw_model_output)

            raw_ingredients_text = parsed_combined_result.get("raw_ocr_text", "N/A")
            analysis_data = parsed_combined_result.get("analysis")
            overall_safety=parsed_combined_result.get("overall_safety") # Get the raw 'analysis' key

            # --- NEW: Check if the analysis_data is a list. If not, make it an empty list. ---
            if not isinstance(analysis_data, list):
                print(f"Warning: AI model returned a non-list type for 'analysis'. Type was: {type(analysis_data)}")
                analysis_data = [] # Default to an empty list to prevent client crash
            # --- END NEW ---
            
            analysis_json_str = json.dumps(analysis_data)
            timestamp_label = f"IN_{timestamp_string}"

            new_search_entry = SearchEntry(
                search_text=timestamp_label,
                user_id=user_id,
                analysis_json_str=analysis_json_str,
                raw_ocr_text=raw_ingredients_text[:250],
                image_filename=unique_filename,
                overall_safety=overall_safety
            )
            db.session.add(new_search_entry)
            db.session.commit()

            output_for_cli = {
                "status": "success",
                "ocr_result": raw_ingredients_text,
                "analysis_result": analysis_data,
                "overall_safety":overall_safety,
                "image_filename": unique_filename,
                "search_reference": timestamp_label
            }

            print("\n--- JSON Response Output to CLI ---")
            print(json.dumps(output_for_cli, indent=2))
            print("-----------------------------------\n")

            return jsonify(output_for_cli), 200

        except json.JSONDecodeError as e:
            print(f"Error: JSON decoding failed. Raw model output:\n{raw_model_output}")
            return jsonify({"error": f"Failed to parse JSON response from AI: {e}", "raw_response": raw_model_output}), 500
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return jsonify({"error": str(e)}), 500
        




@app.route('/ocr_wo_jwt', methods=['GET', 'POST'])
def ocr_and_analyze_wo_jwt():
    if request.method == 'GET':
        return jsonify({"message": "Use POST to upload an image and receive OCR & analysis."})

    elif request.method == 'POST':
        user_id = 1

        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        image_file = request.files['image']

        if not image_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            return jsonify({"error": "Invalid image file type"}), 400

        try:
            current_ist_time = datetime.now(ist)
            timestamp_string = current_ist_time.strftime('%Y%m%d_%H%M%S')
            original_filename = image_file.filename
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            unique_filename = f"INGRIFY_{timestamp_string}.{file_extension}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            image_file.save(image_path)

            with open(image_path, 'rb') as img_f:
                image_data_for_gemini = img_f.read()
            image_object_for_gemini = Image.open(io.BytesIO(image_data_for_gemini))

        #     combined_prompt = """
        #    From the provided image, perform OCR to accurately identify only actual product ingredients or components (such as chemical compounds, natural extracts, food additives, vitamins, oils, acids). Ignore all non-ingredient text including addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing or country-of-origin details, batch numbers, and expiry dates.
        #     ABSOLUTELY MUST FOLLOW:
        #     Only output ingredients actually present in the image.
        #     Do NOT add, guess, infer, or generate any ingredient not in the image. If it is not visible, it must not appear in the output.
        #     Ignore all non-ingredient text: addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing details, batch numbers, expiry dates, country-of-origin, or any other unrelated text like MRP, USP etc.
        #         If the image does not contain ingredients, output:
        # { "raw_ocr_text": "", "analysis": [] }
        # After identifying them, generate a single JSON object. This JSON object must have two top-level keys:
        #     1.  `raw_ocr_text`: A string containing a comma-separated list of all identified ingredients (as plain text).
        #     2.  `analysis`: A JSON array of objects, where each object represents an individual ingredient. Each ingredient object must have the following keys:
        #         - `name`: The exact name of the ingredient as identified.
        #         - `use`: A very simple explanation (max 1-2 sentences) of what the ingredient does in the product, using only easy-to-understand words suitable for a 10-year-old.
        #         - `Made from`: A one-line description of the ingredient's source or common origin.
        #         - `side_effects`: Any common or potential side effects or considerations.
        #         - `allergen`: A boolean (true/false) indicating if it is a common or potential allergen.

        #     Ensure the entire output is a single, valid JSON object and contains NO other text, markdown fences (like ```json), or explanations outside this JSON.
        # """

            combined_prompt="""From the provided image, perform OCR to accurately identify only actual product ingredients or components (such as chemical compounds, natural extracts, food additives, vitamins, oils, acids). 

Ignore all non-ingredient text including: addresses, company names, emails, phone numbers, websites, slogans, instructions, manufacturing or country-of-origin details, batch numbers, expiry dates, MRP, USP, or any other unrelated text.

ABSOLUTELY MUST FOLLOW:
- Only output ingredients actually present in the image.
- Do NOT add, guess, infer, or generate any ingredient not in the image. If it is not visible, it must not appear in the output.
- If the image does not contain ingredients, output exactly:
{ "raw_ocr_text": "", "analysis": [], "overall_safety": { "score": 0, "safety_colour": "#95A5A6" } }

After identifying the ingredients, generate a single JSON object with these top-level keys:

1. `raw_ocr_text`: A string containing a comma-separated list of all identified ingredients (as plain text).

2. `analysis`: A JSON array of objects, where each object represents an individual ingredient. Each object must contain:
   - `name`: The exact name of the ingredient as identified.
   - `use`: A very simple explanation (max 1-2 sentences) of what the ingredient does in the product, using only easy words suitable for a 10-year-old.
   - `made_from`: A one-line description of the ingredient's source or common origin.
   - `side_effects`: Any common or potential side effects or considerations.
   - `allergen`: A boolean (true/false) indicating if it is a common or potential allergen.
   - `safety_colour`: Hex code (#2ECC71 for safe, #F1C40F for moderate risk, #E74C3C for high risk).

3. `overall_safety`: An object with two fields:
   - `score`:  A number between 0 and 100 that must be consistent with the individual ingredient safety levels. 
       * If **all ingredients have safety_colour = #2ECC71 (green)** → score must be between 0-20. 
       * If **at least one ingredient has safety_colour = #F1C40F (yellow)** → score must be between 30-60. 
       * If **at least one ingredient has safety_colour = #E74C3C (red)** → score must be between 70-100. 
   - `safety_colour`: Must strictly match the score:
       * 0-20 → #2ECC71 (green)
       * 30-60 → #F1C40F (yellow)
       * 70-100 → #E74C3C (red)

Ensure the output is:
- A single valid JSON object.
- Contains NO other text, explanations, or markdown fences.
"""

            combined_response = vision_model.generate_content(
                [image_object_for_gemini, combined_prompt],
                stream=False,
            )

            raw_model_output = combined_response.text.strip()
            
            if raw_model_output.startswith("```json") and raw_model_output.endswith("```"):
                raw_model_output = raw_model_output[7:-3].strip()

            parsed_combined_result = json.loads(raw_model_output)

            raw_ingredients_text = parsed_combined_result.get("raw_ocr_text", "N/A")
            analysis_data = parsed_combined_result.get("analysis") # Get the raw 'analysis' key
            overall_safety=parsed_combined_result.get("overall_safety")

            # --- NEW: Check if the analysis_data is a list. If not, make it an empty list. ---
            if not isinstance(analysis_data, list):
                print(f"Warning: AI model returned a non-list type for 'analysis'. Type was: {type(analysis_data)}")
                analysis_data = [] # Default to an empty list to prevent client crash
            # --- END NEW ---
            
            analysis_json_str = json.dumps(analysis_data)
            timestamp_label = f"IN_{timestamp_string}"

            new_search_entry = SearchEntry(
                search_text=timestamp_label,
                user_id=user_id,
                analysis_json_str=analysis_json_str,
                raw_ocr_text=raw_ingredients_text[:250],
                image_filename=unique_filename,
                overall_safety=overall_safety
            )
            db.session.add(new_search_entry)
            db.session.commit()

            output_for_cli = {
                "status": "success",
                "ocr_result": raw_ingredients_text,
                "analysis_result": analysis_data,
                "overall_safety":overall_safety,
                "image_filename": unique_filename,
                "search_reference": timestamp_label
            }

            print("\n--- JSON Response Output to CLI ---")
            print(json.dumps(output_for_cli, indent=2))
            print("-----------------------------------\n")

            return jsonify(output_for_cli), 200

        except json.JSONDecodeError as e:
            print(f"Error: JSON decoding failed. Raw model output:\n{raw_model_output}")
            return jsonify({"error": f"Failed to parse JSON response from AI: {e}", "raw_response": raw_model_output}), 500
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return jsonify({"error": str(e)}), 500

@app.route('/single_ingredient', methods=['GET', 'POST', 'PUT'])
def single_ingredient_analysis():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated or not found"}), 401

    # --- GET method ---
    if request.method == 'GET':
        ingredient_name = request.args.get('ingredient_name', '').strip()

        if not ingredient_name:
            return jsonify({
                "message": "Please provide an ingredient name using ?ingredient_name=..."
            }), 400

        try:
            analysis_json_str = analyze_single_ingredient_to_json(ingredient_name)
            return jsonify({
                "status": "success",
                "ingredient": ingredient_name,
                "analysis_result": analysis_json_str,
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- POST/PUT method ---
    elif request.method in ['POST', 'PUT']:
        if request.is_json:
            ingredient_name = request.json.get('ingredient_name', '').strip()
        else:
            ingredient_name = request.form.get('ingredient_name', '').strip()

        if not ingredient_name:
            return jsonify({"error": "Ingredient name is required"}), 400

        try:
            analysis_json_str = analyze_single_ingredient_to_json(ingredient_name)

            new_search_entry = SearchEntry(
                search_text=ingredient_name,
                user_id=user_id,
                analysis_json_str=analysis_json_str
            )
            db.session.add(new_search_entry)
            db.session.commit()
            
            output_for_cli = {
                "status": "success",
                "ingredient": ingredient_name,
               "analysis_result": analysis_json_str
            }

            print("\n--- JSON Response Output to CLI ---")
            print(json.dumps(output_for_cli, indent=2))
            print("-----------------------------------\n")

            return jsonify({
                "status": "success",
                "ingredient": ingredient_name,
                "analysis_result": analysis_json_str,
                "saved": True
            }), 201
            

        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/single_ingredient_wo_jwt', methods=['GET', 'POST', 'PUT'])
def single_ingredient_analysis_wo_jwt():
    user_id = 1

    # --- GET method ---
    if request.method == 'GET':
        ingredient_name = request.args.get('ingredient_name', '').strip()

        if not ingredient_name:
            return jsonify({
                "message": "Please provide an ingredient name using ?ingredient_name=..."
            }), 400

        try:
            analysis_json_str = analyze_single_ingredient_to_json(ingredient_name)
            
            return jsonify({
                "status": "success",
                "ingredient": ingredient_name,
                "analysis_result": analysis_json_str
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # --- POST/PUT method ---
    elif request.method in ['POST', 'PUT']:
        if request.is_json:
            ingredient_name = request.json.get('ingredient_name', '').strip()
        else:
            ingredient_name = request.form.get('ingredient_name', '').strip()

        if not ingredient_name:
            return jsonify({"error": "Ingredient name is required"}), 400

        try:
            analysis_json_str = analyze_single_ingredient_to_json(ingredient_name)

            new_search_entry = SearchEntry(
                search_text=ingredient_name,
                user_id=user_id,
                analysis_json_str=analysis_json_str
            )
            db.session.add(new_search_entry)
            db.session.commit()

            output_for_cli = {
                "status": "success",
                "ingredient": ingredient_name,
               "analysis_result": analysis_json_str
            }

            print("\n--- JSON Response Output to CLI ---")
            print(json.dumps(output_for_cli, indent=2))
            print("-----------------------------------\n")

            return jsonify({
                "status": "success",
                "ingredient": ingredient_name,
                "analysis_result": analysis_json_str,
                "saved": True
            }), 201

        except Exception as e:
            return jsonify({"error": str(e)}), 500
# Search history paakurathukku api
@app.route('/history', methods=['GET'])
def search_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "User not authenticated or not found"}), 401

    # Fetch all entries for this user, latest first
    history_entries = SearchEntry.query.filter_by(user_id=user_id).order_by(SearchEntry.timestamp.desc()).all()
    history_data = []

    for entry in history_entries:
        try:
            analysis_data = json.loads(entry.analysis_json_str) if entry.analysis_json_str else None
        except json.JSONDecodeError:
            analysis_data = {"error": "Invalid JSON format stored"}

        history_data.append({
            "search_text": entry.search_text,
            "timestamp": entry.timestamp.strftime('%Y-%m-%d %H:%M:%S %Z'),
            "analysis_data": analysis_data
        })

    return jsonify({
        "status": "success",
        "total_entries": len(history_data),
        "history": history_data
    }), 200

#user registration kaaga ithu
# @app.route('/signup', methods=['POST'])
# def signup():
#     data = request.get_json()

#     if not data:
#         return jsonify({"message": "Request must be JSON"}), 400
    
#     name = data.get('name')
#     age = data.get('age')
#     username = data.get('username')
#     password = data.get('password')
#     email = data.get('email')  # NEW: get email from request

#     print(f"Parsed name: {name}, username: {username}, password: {password}, email: {email}")

#     # --- VALIDATIONS ---
#     if not name or not isinstance(name, str) or name.strip() == "":
#         return jsonify({"message": "Name is required and cannot be empty"}), 400
#     if not username or not isinstance(username, str) or username.strip() == "":
#         return jsonify({"message": "Username is required and cannot be empty"}), 400
#     if not password or not isinstance(password, str) or password.strip() == "":
#         return jsonify({"message": "Password is required and cannot be empty"}), 400
#     if len(password) < 7:
#         return jsonify({"message": "Password must be at least 7 characters long"}), 400
#     if not email or not isinstance(email, str) or email.strip() == "":
#         return jsonify({"message": "Email is required"}), 400

#     # Basic email regex validation
#     email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
#     if not re.match(email_regex, email):
#         return jsonify({"message": "Invalid email format"}), 400

#     # Check if username already exists
#     if User.query.filter_by(username=username).first():
#         return jsonify({"message": "Username already taken"}), 409
#     # Check if email already exists
#     if User.query.filter_by(email=email).first():
#         return jsonify({"message": "Email already registered"}), 409

#     try:
#         new_user = User(
#             name=name,
#             age=age,
#             username=username,
#             email=email  # SAVE EMAIL
#         )

#         new_user.set_password(password)  # hash password

#         db.session.add(new_user)
#         db.session.commit()

#         # Generate JWT token
#         access_token = create_access_token(identity=str(new_user.id))

#         return jsonify(
#             message="Registration successful!",
#             userId=new_user.id,
#             userName=new_user.name,
#             email=new_user.email,
#             token=access_token
#         ), 201

#     except Exception as e:
#         db.session.rollback()
#         app.logger.error(f"Error during signup: {e}")
#         return jsonify({"message": f"An internal server error occurred: {str(e)}"}), 500

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    age = data.get('age')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # VALIDATIONS (same as before)
    if not all([name, username, email, password]):
        return jsonify({"message": "All fields are required"}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({"message": "Username or Email already exists"}), 409

    # Generate OTP
    otp = str(random.randint(100000, 999999))

    # Store temp user with OTP
    temp_user = TempSignup(
        name=name,
        age=age,
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        otp=otp
    )
    db.session.add(temp_user)
    db.session.commit()

    # Send OTP via email
    subject = "Your Signup OTP"
    body = f"Your OTP is: {otp}\nIt is valid for 10 minutes."
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("ingrify.help@gmail.com", "cdyh tner fzod vhji")
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail("ingrify.help@gmail.com", email, message)
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

    return jsonify({"message": "OTP sent to your email. Verify to complete signup."}), 200


# login panrathukku
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "Request must be JSON"}), 400

    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({"message": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Create an access token for the logged-in user
        access_token = create_access_token(identity=str(user.id))
        return jsonify(
            message="Login successful!",
            userId=user.id,
            name=user.name,
            userName=user.username,
            token=access_token
        ), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

#JWT valid ah iruntha than inga varum
@app.route('/add_search_entry', methods=['POST'])
@jwt_required() 
def add_search_entry():

    user_id = get_current_user_id() 


    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    data = request.get_json()
    if not data or 'search_text' not in data:
        return jsonify({"message": "Missing 'search_text' in request body"}), 400

    try:
        new_entry = SearchEntry(
            search_text=data['search_text'],
            user_id=user_id,
            raw_ocr_text=data.get('raw_ocr_text'),
            analysis_json_str=data.get('analysis_json_str'),
            image_filename=data.get('image_filename')
        )
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({"message": "Search entry added successfully!", "entryId": new_entry.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding search entry: {e}")
        return jsonify({"message": f"An internal server error occurred: {str(e)}"}), 500


@app.route('/allergens', methods=['POST'])
@jwt_required()
def add_allergens():
    
    user_id = get_current_user_id() 

    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    data = request.get_json()
    if not data or 'allergens' not in data or not isinstance(data['allergens'], list):
        return jsonify({"message": "Invalid request: 'allergens' (list of strings) is required"}), 400

    allergens_list = data['allergens']
    if not all(isinstance(a, str) and a.strip() for a in allergens_list):
        return jsonify({"message": "All allergens must be non-empty strings"}), 400

    try:
        added_count = 0
        existing_allergens = {
            a.allergen_name.lower() for a in Allergen.query.filter_by(user_id=user_id).all()
        }

        for allergen_name in allergens_list:
            normalized_name = allergen_name.strip().lower()
            
            if normalized_name and normalized_name not in existing_allergens:
                new_allergen = Allergen(
                    allergen_name=normalized_name,
                    user_id=user_id
                )
                db.session.add(new_allergen)
                existing_allergens.add(normalized_name) # Add to set to prevent duplicates within the same request
                added_count += 1
        
        db.session.commit()
        return jsonify({"message": f"Successfully added {added_count} new allergens.", "allergens_added": added_count}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding allergens for user {user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred while saving allergens: {str(e)}"}), 500

@app.route('/allergens', methods=['GET'])
@jwt_required()
def get_allergens():
    """
    Retrieves all allergen details for the authenticated user.
    Requires a valid JWT in the Authorization header.
    """
    user_id = get_current_user_id() 

    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    try:
        allergens = Allergen.query.filter_by(user_id=user_id).all()
        # Convert list of Allergen objects to a list of strings
        allergen_names = [a.allergen_name for a in allergens]
        return jsonify({"allergens": allergen_names}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving allergens for user {user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred while fetching allergens: {str(e)}"}), 500


@app.route('/allergens', methods=['DELETE'])
@jwt_required()
def delete_allergen():
    user_id = get_current_user_id()

    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    data = request.get_json()
    if not data or 'allergen' not in data or not isinstance(data['allergen'], str) or not data['allergen'].strip():
        return jsonify({"message": "Invalid request: 'allergen' (non-empty string) is required"}), 400

    allergen_name = data['allergen'].strip().lower()

    try:
        allergen = Allergen.query.filter_by(
            user_id=user_id,
            allergen_name=allergen_name
        ).first()

        if allergen:
            db.session.delete(allergen)
            db.session.commit()
            return jsonify({"message": f"Successfully deleted allergen '{allergen_name}'."}), 200
        else:
            return jsonify({"message": f"Allergen '{allergen_name}' not found."}), 404

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting allergen for user {user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred while deleting allergen: {str(e)}"}), 500
0


@app.route('/search_suggestions', methods=['GET'])
@jwt_required()
def search_suggestions():
    """
    Provides autocomplete suggestions for search terms based on user's past searches.
    Requires a valid JWT.
    Query parameter: 'q' (the partial search query).
    """
    user_id = get_current_user_id() 
    

    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    query_text = request.args.get('q', '').strip().lower()
    if not query_text:
        return jsonify({"suggestions": []}), 200 # Return empty list if no query

    try:
        # Fetch unique search terms from the current user's history that start with the query
        # Use func.lower() for case-insensitive matching
        suggestions = db.session.query(SearchEntry.search_text)\
                            .filter(SearchEntry.user_id == user_id)\
                            .filter(func.lower(SearchEntry.search_text).like(f"{query_text}%"))\
                            .distinct()\
                            .limit(10)\
                            .all()
        
        # Extract just the text from the query results
        suggestion_list = [s[0] for s in suggestions]
        return jsonify({"suggestions": suggestion_list}), 200
    except Exception as e:
        app.logger.error(f"Error fetching search suggestions for user {user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred while fetching search suggestions: {str(e)}"}), 500

@app.route('/allergen_suggestions', methods=['GET'])
@jwt_required()
def allergen_suggestions():
    """
    Provides autocomplete suggestions for allergen names.
    Suggestions can come from:
    1. User's previously saved allergens.
    2. A predefined list of common allergens (if no user-specific match or to augment).
    Requires a valid JWT.
    Query parameter: 'q' (the partial allergen query).
    """
    user_id = get_current_user_id() 

    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    query_text = request.args.get('q', '').strip().lower()
    
    # Define a common list of allergens (you can expand this)
    common_allergens = [
        "peanuts", "tree nuts", "milk", "eggs", "soy", "wheat", "fish", "shellfish",
        "gluten", "sesame", "mustard", "celery", "lupin", "sulfites"
    ]

    suggestions_set = set() # Use a set to store unique suggestions

    try:
        # 1. Add suggestions from user's own allergens
        user_allergens = db.session.query(Allergen.allergen_name)\
                                .filter(Allergen.user_id == user_id)\
                                .filter(func.lower(Allergen.allergen_name).like(f"{query_text}%"))\
                                .distinct()\
                                .all()
        for allergen in user_allergens:
            suggestions_set.add(allergen[0])

        # 2. Add suggestions from common allergens that match the query
        for common_allergen in common_allergens:
            if common_allergen.startswith(query_text):
                suggestions_set.add(common_allergen)
        
        # Convert set to sorted list for consistent order
        suggestion_list = sorted(list(suggestions_set))
        
        # Limit the number of suggestions if needed
        return jsonify({"suggestions": suggestion_list[:10]}), 200 # Limit to 10 suggestions

    except Exception as e:
        app.logger.error(f"Error fetching allergen suggestions for user {user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred while fetching allergen suggestions: {str(e)}"}), 500

@app.route('/user/profile', methods=['PUT', 'GET'])
@jwt_required()
def user_profile():
    """
    Handles updating and retrieving user profile information (name, username, age).
    PUT method: Updates user profile.
    GET method: Retrieves user profile.
    Requires a valid JWT in the Authorization header.
    """
    user_id = get_jwt_identity()  # Grab user id from JWT
    if not user_id:
        return jsonify({"message": "Authenticated user not found"}), 404

    # Fetch user using your User model with filter_by (not .get)
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    if request.method == 'PUT':
        data = request.get_json()
        if not data:
            return jsonify({"message": "Request must be JSON"}), 400

        updated_fields = []

        # Update Name
        if 'name' in data:
            new_name = data['name']
            if not isinstance(new_name, str) or new_name.strip() == "":
                return jsonify({"message": "Name must be a non-empty string"}), 400
            user.name = new_name.strip()
            updated_fields.append("name")

        # Update Username
        if 'username' in data:
            new_username = data['username']
            if not isinstance(new_username, str) or new_username.strip() == "":
                return jsonify({"message": "Username must be a non-empty string"}), 400
            
            # Check uniqueness (excluding current user)
            if new_username.strip() != user.username:
                existing_user = User.query.filter(
                    User.username == new_username.strip(),
                    User.id != user.id
                ).first()
                if existing_user:
                    return jsonify({"message": "Username already taken by another user"}), 409
            
            user.username = new_username.strip()
            updated_fields.append("username")

        # Update Age
        if 'age' in data:
            new_age = data['age']
            if new_age is not None and not isinstance(new_age, int) and not (isinstance(new_age, str) and new_age.isdigit()):
                return jsonify({"message": "Age must be an integer or null"}), 400
            
            user.age = int(new_age) if isinstance(new_age, str) and new_age.isdigit() else new_age
            updated_fields.append("age")

        if not updated_fields:
            return jsonify({"message": "No valid fields provided for update (name, username, or age)"}), 400

        try:
            db.session.commit()
            return jsonify({
                "message": f"Profile updated successfully. Changed fields: {', '.join(updated_fields)}",
                "user": {
                    "userId": user.id,
                    "username": user.username,
                    "name": user.name,
                    "age": user.age
                }
            }), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user profile for user {user.id}: {e}")
            return jsonify({"message": f"An internal server error occurred: {str(e)}"}), 500

    elif request.method == 'GET':
        return jsonify({
            "userId": user.id,
            "username": user.username,
            "name": user.name,
            "age": user.age
        }), 200

@app.route('/user/change_password', methods=['PUT'])
@jwt_required()
def change_password():

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"message": "Authenticated user not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"message": "Request must be JSON"}), 400

    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not all([current_password, new_password]):
        return jsonify({"message": "Both 'current_password' and 'new_password' are required"}), 400

    if not isinstance(new_password, str) or len(new_password) < 6:
        return jsonify({"message": "New password must be a string and at least 6 characters long"}), 400

    # Verify current password
    if not user.check_password(current_password):
        return jsonify({"message": "Incorrect current password"}), 401

    try:
        user.set_password(new_password) 
        db.session.commit()
        return jsonify({"message": "Password changed successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error changing password for user {user.id}: {e}")
        return jsonify({"message": f"An internal server error occurred during password change: {str(e)}"}), 500
    


    
@app.route('/user/account', methods=['DELETE'])
@jwt_required()
def delete_account():
    """
    Allows an authenticated user to delete their account.
    This will also delete all associated search entries and allergen preferences
    due to SQLAlchemy's cascade="all, delete-orphan" setting on relationships.
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"message": "Authenticated user not found"}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        # Optionally, you might want to revoke any existing JWTs for this user
        # if you have a token blocklist implemented.
        return jsonify({"message": f"User account '{user.username}' and all associated data deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting account for user {current_user_id}: {e}")
        return jsonify({"message": f"An internal server error occurred during account deletion: {str(e)}"}), 500
    
@app.route("/history/scan", methods=["GET"])
@jwt_required()
def get_scans():
    # Get user ID from JWT
    user_id = int(get_jwt_identity())
    limit = request.args.get("limit", default=5, type=int)

    scans = (
        SearchEntry.query.filter_by(user_id=user_id)
        .filter(SearchEntry.image_filename.isnot(None))  # only scans
        .order_by(SearchEntry.id.desc())
        .limit(limit)
        .all()
    )

    data = [
        {
            "id": s.id,
            "scan_name":s.search_text,
            "raw_ocr_text": s.raw_ocr_text,
            "analysis": s.analysis_json_str,
            "image_filename": s.image_filename,
            "created_at": s.timestamp.isoformat(),
            "overall_safety":s.overall_safety
        }
        for s in scans
    ]

    return jsonify({"status": "success", "type": "scan", "data": data}), 200


@app.route("/history/search", methods=["GET"])
@jwt_required()
def get_searches():
    user_id = int(get_jwt_identity())
    limit = request.args.get("limit", default=5, type=int)

    searches = (
        SearchEntry.query.filter_by(user_id=user_id)
        .filter(SearchEntry.image_filename.is_(None))
        .order_by(SearchEntry.id.desc())
        .limit(limit)
        .all()
    )

    data = [
        {
            "id": s.id,
            "query": s.search_text,
            "raw_ocr_text": s.raw_ocr_text,
            "analysis": s.analysis_json_str,
            "created_at": s.timestamp.isoformat(),
        }
        for s in searches
    ]

    return jsonify({"status": "success", "type": "search", "data": data}), 200


@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))

    # Save OTP in DB
    reset_entry = PasswordResetOTP(email=email, otp=otp)
    db.session.add(reset_entry)
    db.session.commit()

    # Send OTP via email
    subject = "Your OTP for Password Reset"
    body = f"Use this OTP to reset your password: {otp}\nIt is valid for 10 minutes."

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("ingrify.help@gmail.com", "cdyh tner fzod vhji")  # use app password
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail("ingrify.help@gmail.com", email, message)
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

    return jsonify({"message": "OTP sent to your email!"})
# ✅ New endpoint for verifying OTP
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")

    otp_entry = PasswordResetOTP.query.filter_by(email=email, otp=otp).first()
    if not otp_entry:
        return jsonify({"error": "Invalid OTP"}), 400
    if otp_entry.is_expired():
        return jsonify({"error": "OTP expired"}), 400

    return jsonify({"message": "OTP verified successfully"}), 200


# ✅ Updated reset-password endpoint (no OTP here)
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    new_password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.set_password(new_password)
    db.session.commit()

    # Optional: cleanup any old OTPs for this email
    PasswordResetOTP.query.filter_by(email=email).delete()
    db.session.commit()

    return jsonify({"message": "Password reset successful!"}), 200

@app.route('/signup/verify-otp', methods=['POST'])
def signup_verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    temp_user = TempSignup.query.filter_by(email=email, otp=otp).first()
    if not temp_user:
        return jsonify({"error": "Invalid OTP"}), 400

    # Check if OTP expired (10 mins)
    now = datetime.now()
    if now > temp_user.created_at + timedelta(minutes=10):
        db.session.delete(temp_user)
        db.session.commit()
        return jsonify({"error": "OTP expired"}), 400

    # Create actual user
    new_user = User(
        name=temp_user.name,
        age=temp_user.age,
        username=temp_user.username,
        email=temp_user.email
    )
    new_user.password_hash = temp_user.password_hash
    db.session.add(new_user)
    db.session.commit()

    # Remove temp user
    db.session.delete(temp_user)
    db.session.commit()

    access_token = create_access_token(identity=str(new_user.id))

    return jsonify({
        "message": "Signup successful!",
        "userId": new_user.id,
        "userName": new_user.name,
        "email": new_user.email,
        "token": access_token
    }), 201



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)