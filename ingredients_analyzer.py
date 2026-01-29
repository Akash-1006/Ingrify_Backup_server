import google.generativeai as genai
import os
import json

try:
    API_KEY = os.environ["GEMINI_API_KEY"]
except KeyError:
    # Fallback for demonstration/testing if env var isn't set.
    # For production, NEVER hardcode.
    API_KEY = "AIzaSyDeNmt-xztq84GxUp9qQfFrcsyDfMVKNd0" # <--- REPLACE WITH YOUR ACTUAL API KEY

genai.configure(api_key=API_KEY)

# vision_model = genai.GenerativeModel(model_name="gemini-1.5-flash-latest")
vision_model = genai.GenerativeModel(model_name="gemma-3-4b-it")

def analyze_ingredients_to_json(ingredient_list_str: str) -> str:
    """
    Converts an ingredients list into a JSON format with name, use, side_effects, and allergen.

    Args:
        ingredient_list_str: A string containing the list of ingredients.

    Returns:
        A JSON string containing the analysis of each ingredient.
        Returns an error message string if an error occurs.
    """

    prompt = f"""
    Convert the following ingredients list into a JSON array of objects. Each object should have the following keys:
    - `name`: The name of the ingredient.
    - `use`: A very simple explanation of what the ingredient does in the product, using only easy words that even a 10-year-old can understand. Do not use science or chemistry words like "humectant", "emollient", or "surfactant".
    - `Made from`: Provide a one-line source description of the ingredient (e.g., gelatin - derived from animal collagen).
    - `side_effects`: Any common or potential side effects or considerations (e.g., skin irritation, endocrine disruptor, generally safe). State "None identified" if no common side effects are known.
    - `allergen`: A boolean (true/false) indicating if it's a common or potential allergen.

    Ensure the output is a valid JSON array of objects.

    Ingredients:
    {ingredient_list_str}

    JSON Output:
    """

    try:
        response = vision_model.generate_content(prompt)
        json_output = response.text.strip()

        # Sometimes the model might wrap the JSON in markdown code block.
        # Try to clean it up.
        if json_output.startswith("```json") and json_output.endswith("```"):
            json_output = json_output[7:-3].strip()

        json.loads(json_output) 
        return json_output
    except json.JSONDecodeError as e:
        print(f"JSON decoding error in analyze_ingredients_to_json: {e}")
        print(f"Raw model response: {response.text}")
        return json.dumps({"error": f"Failed to parse JSON response from AI: {e}", "raw_response": response.text})
    except Exception as e:
        return json.dumps({"error": f"An error occurred during ingredient list analysis: {str(e)}"})

def analyze_single_ingredient_to_json(ingredient_name: str) -> str:
    prompt = f"""
    Analyze the following single ingredient and provide its details in a JSON object with the following keys:
    - `name`: The name of the ingredient.
    - `use`: A very simple explanation of what the ingredient does in the product, using only easy words that even a 10-year-old can understand. Do not use science or chemistry words like "humectant", "emollient", or "surfactant".
    - `Made from`: Provide a one-line source description of the ingredient (e.g., gelatin - derived from animal collagen).
    - `side_effects`: Any common or potential side effects or considerations (e.g., skin irritation, endocrine disruptor, generally safe). State "None identified" if no common side effects are known.
    - `allergen`: A boolean (true/false) indicating if it's a common or potential allergen.
   - `score`: Number between 0-100 where 0 = completely safe, 100 = extremely risky. 
              This score must be based on the most concerning ingredient(s). 
              For example:
                - If all ingredients are safe → score close to 0, colour = green (#2ECC71).
                - If some have moderate risk → score between 30-60, colour = yellow (#F1C40F).
                - If high-risk or banned → score above 70, colour = red (#E74C3C)."


    Ensure the output is a valid JSON object.

    Ingredient: {ingredient_name}

    JSON Output:
    """

    try:
        response = vision_model.generate_content(prompt)
        json_output = response.text.strip()

        if json_output.startswith("```json") and json_output.endswith("```"):
            json_output = json_output[7:-3].strip()

        # For a single ingredient, the output should be a single JSON object, not an array.
        # So we load it directly.
        json.loads(json_output) # Validate by loading
        return json_output
    except json.JSONDecodeError as e:
        print(f"JSON decoding error in analyze_single_ingredient_to_json: {e}")
        print(f"Raw model response: {response.text}")
        return json.dumps({"error": f"Failed to parse JSON response from AI: {e}", "raw_response": response.text})
    except Exception as e:
        return json.dumps({"error": f"An error occurred during single ingredient analysis: {str(e)}"})

