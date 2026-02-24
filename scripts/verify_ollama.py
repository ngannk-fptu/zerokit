import requests
import os
from dotenv import load_dotenv

load_dotenv()

def verify_ollama():
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model_name = os.getenv("OLLAMA_MODEL", "codellama:13b")
    
    print(f"Checking Ollama at {base_url}...")
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            model_names = [m.get("name") for m in models]
            print(f"Available models: {model_names}")
            
            if model_name in model_names or any(m.startswith(model_name) for m in model_names):
                print(f"✅ Success: Model '{model_name}' is available.")
                return True
            else:
                print(f"❌ Error: Model '{model_name}' not found. Please run 'ollama pull {model_name}'")
                return False
        else:
            print(f"❌ Error: Ollama service returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error: Could not connect to Ollama. Is it running? ({e})")
        return False

if __name__ == "__main__":
    if verify_ollama():
        print("\nOllama integration is ready!")
    else:
        print("\nOllama integration check failed.")
