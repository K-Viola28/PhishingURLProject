
import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from analysis.features import FEATURE_ORDER, extract_features


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT / "models" / "grouped" / "random_forest.joblib"
)

EVALUATION_PATH = (
    PROJECT_ROOT / "results" / "grouped" / "evaluation_results.json"
)


@lru_cache(maxsize=1)
def load_predictor():
    """Load the trained model and its evaluation settings."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError("The trained model was not found.")

    if not EVALUATION_PATH.exists():
        raise FileNotFoundError("The evaluation report was not found.")

    model = joblib.load(MODEL_PATH)

    with open(EVALUATION_PATH, "r", encoding="utf-8") as file:
        evaluation = json.load(file)

    if evaluation["selected_model"] != "random_forest":
        raise ValueError("The selected model does not match.")

    if evaluation["feature_order"] != FEATURE_ORDER:
        raise ValueError("The model feature order does not match.")

    decision_threshold = evaluation["decision_threshold"]
    risk_thresholds = evaluation["risk_thresholds"]

    return model, decision_threshold, risk_thresholds


def predict_url(url):
    """Extract features and predict whether a URL is phishing."""

    model, decision_threshold, risk_thresholds = load_predictor()

    features = extract_features(url)

    input_data = pd.DataFrame(
        [features],
        columns=FEATURE_ORDER
    )

    probabilities = model.predict_proba(input_data)[0]

    phishing_index = list(model.classes_).index("phishing")

    phishing_probability = float(
        probabilities[phishing_index]
    )

    if phishing_probability >= decision_threshold:
        prediction = "phishing"
    else:
        prediction = "benign"

    if prediction == "benign":
        risk = "Low"
    elif phishing_probability < risk_thresholds["high_threshold"]:
        risk = "Medium"
    else:
        risk = "High"

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": phishing_probability,
        "risk": risk,
        "features": features,
    }
