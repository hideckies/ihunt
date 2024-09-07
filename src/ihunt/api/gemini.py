# Docs: https://ai.google.dev/api?lang=python

import google.generativeai as genai
import json
from threading import Lock
from typing import Any
from ..models import Ihunt
from ..stdout import echo
from ..utils import create_prompt, extract_json_from_str, update_data_from_json

API_NAME = "Gemini"


# Query: All
def req_gemini(ihunt: Ihunt, lock: Lock, data_class: Any) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)

    genai.configure(api_key=ihunt.apikeys.gemini)
    model = genai.GenerativeModel("gemini-1.5-flash")
   
    try:
        with lock:
            resp = model.generate_content(create_prompt(ihunt.query.value, data_class))
            print(resp.text)
            json_str = extract_json_from_str(resp.text)
            print(json_str)
            if json_str is None:
                raise ValueError("JSON not found in the result.")
            update_data_from_json(ihunt.data, json.loads(json_str))
    except Exception as e:
         echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}...", ihunt.verbose)

