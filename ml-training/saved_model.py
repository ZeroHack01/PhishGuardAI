# PhishGuardAI: Neon model vault
from colorama import init, Fore, Style
import tensorflow as np
import numpy as np
import os

init()  # Neon logs

MODEL_DIR = "./ml-training/models"
MODEL_PATH = os.path.join(MODEL_DIR, "phishguard_model")

def save_model(model, path=MODEL_PATH):
    """Save the trained model to disk with neon glow."""
    try:
        os.makedirs(MODEL_DIR, exist_ok=True)
        model.save(path)
        print(f"{Fore.CYAN} {Style.BRIGHT}PhishGuardAI: Model saved to {path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED} {Style.BRIGHT}Error saving model: {e}{Style.RESET_ALL}")

def load_model(path=MODEL_PATH):
    """Load model from disk for the dark net."""
    try:
        model = tf.keras.models.load_model(path)
        print(f"{Fore.MAGENTA} {Style.BRIGHT}PhishGuardAI: Loaded model from {path}{Style.RESET_ALL}")
        return model
    except Exception as e:
        print(f"{Fore.RED} {Style.BRIGHT}Error loading model: {e}{Style.RESET_ALL}")
        return None

if __name__ == "__main__":
    # Example usage
    from tensorflow.keras.models import Sequential
    model = Sequential([tf.keras.layers.Dense(1, activation='sigmoid', input_shape=(8,))])
    save_model(model)
    loaded_model = load_model()
