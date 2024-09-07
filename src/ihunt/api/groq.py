# Docs: https://console.groq.com/docs/quickstart

from groq import Groq
import json
from threading import Lock
from typing import Any
from ..models import Ihunt
from ..stdout import echo
from ..utils import create_prompt, extract_json_from_str, update_data_from_json

API_NAME = "Groq"


# Query: All
def req_groq(ihunt: Ihunt, lock: Lock, data_class: Any) -> None:
    echo(f"[*] Fetching {API_NAME}...", ihunt.verbose)
    
    client = Groq(
        api_key=ihunt.apikeys.groq,
    )

    try:
        with lock:
            results = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": create_prompt(ihunt.query.value, data_class),
                    }
                ],
                model="llama3-8b-8192",
                temperature=1,
                top_p=1,
                stream=False,
                # response_format={"type": "json_object"},
                stop=None,
                timeout=ihunt.timeout*2,
            )
            json_str = extract_json_from_str(results.choices[0].message.content)
            if json_str is None:
                raise ValueError("JSON not found in the result.")
            update_data_from_json(ihunt.data, json.loads(json_str))
    except Exception as e:
         echo(f"[x] {API_NAME} API error: {e}", ihunt.verbose)

    echo(f"[*] Finished fetching {API_NAME}...", ihunt.verbose)

