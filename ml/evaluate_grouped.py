
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)

from analysis.features import FEATURE_ORDER


DATA_DIR = PROJECT_DIR / "data" / "processed" / "grouped"
MODEL_DIR = PROJECT_DIR / "models" / "grouped"
RESULTS_DIR = PROJECT_DIR / "results" / "grouped"

VALIDATION_FILE = RESULTS_DIR / "validation_data.csv"
TEST_FILE = DATA_DIR / "test.csv"

MODEL_NAMES = [
    "logistic_regression",
    "random_forest",
]


def load_data(file_path):
    """Load and validate a dataset partition."""

    if not file_path.exists():
        raise FileNotFoundError(file_path)

    data = pd.read_csv(file_path)

    required_columns = FEATURE_ORDER + ["label"]

    missing = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    if data[required_columns].isnull().any().any():
        raise ValueError("Missing values found.")

    X = data[FEATURE_ORDER].astype(float)
    y = data["label"].astype(str)

    if set(y.unique()) != {"benign", "phishing"}:
        raise ValueError("Both classes must be present.")

    return X, y


def get_phishing_probabilities(model, X):
    """Return probability estimates for the phishing class."""

    probabilities = model.predict_proba(X)

    phishing_index = list(model.classes_).index("phishing")

    return probabilities[:, phishing_index]


def calculate_metrics(y_true, predictions):
    """Calculate classification metrics."""

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=["benign", "phishing"]
    ).ravel()

    return {
        "accuracy": float(
            accuracy_score(y_true, predictions)
        ),
        "precision": float(
            precision_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0
            )
        ),
        "f1_score": float(
            f1_score(
                y_true, predictions,
                pos_label="phishing",
                zero_division=0
            )
        ),
        "false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0
        ),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def choose_threshold(y_true, probabilities):
    """Choose the threshold with the highest validation F1."""

    binary_labels = (y_true == "phishing").astype(int)

    precision, recall, thresholds = precision_recall_curve(
        binary_labels,
        probabilities
    )

    if len(thresholds) == 0:
        raise ValueError("No classification thresholds available.")

    f1_scores = (
        2 * precision[:-1] * recall[:-1]
        / (precision[:-1] + recall[:-1] + 1e-12)
    )

    best_index = int(np.argmax(f1_scores))

    return float(thresholds[best_index])


def choose_risk_thresholds(y_true, probabilities):
    """
    Select risk thresholds using validation data only.

    Low threshold: lowest threshold with FPR <= 5%.
    High threshold: lowest threshold with precision >= 80%.
    """

    binary_labels = (y_true == "phishing").astype(int)

    # Find the threshold that achieves an FPR of at most 5%.
    fpr, _, roc_thresholds = roc_curve(
        binary_labels,
        probabilities
    )

    valid_low_indices = np.where(
        (fpr <= 0.05) & np.isfinite(roc_thresholds)
    )[0]

    if len(valid_low_indices) > 0:
        low_index = valid_low_indices[
            np.argmin(roc_thresholds[valid_low_indices])
        ]
        low_threshold = float(roc_thresholds[low_index])
    else:
        low_threshold = float(np.max(probabilities))

    # Find the lowest threshold that achieves precision >= 80%.
    precision, _, thresholds = precision_recall_curve(
        binary_labels,
        probabilities
    )

    valid_high_indices = np.where(
        precision[:-1] >= 0.80
    )[0]

    if len(valid_high_indices) > 0:
        high_threshold = float(
            thresholds[valid_high_indices[0]]
        )
    else:
        high_threshold = float(
            np.percentile(probabilities, 90)
        )

    return {
        "low_threshold": low_threshold,
        "high_threshold": high_threshold,
    }


def evaluate_grouped():

    print("Loading grouped validation data...")
    X_validation, y_validation = load_data(VALIDATION_FILE)

    print("Loading grouped test data...")
    X_test, y_test = load_data(TEST_FILE)

    validation_results = {}
    validation_probabilities = {}

    print("\nEvaluating models on grouped validation data...")

    for name in MODEL_NAMES:

        model_path = MODEL_DIR / f"{name}.joblib"

        if not model_path.exists():
            raise FileNotFoundError(model_path)

        model = joblib.load(model_path)

        probabilities = get_phishing_probabilities(
            model,
            X_validation
        )

        validation_probabilities[name] = probabilities

        threshold = choose_threshold(
            y_validation,
            probabilities
        )

        predictions = np.where(
            probabilities >= threshold,
            "phishing",
            "benign"
        )

        metrics = calculate_metrics(
            y_validation,
            predictions
        )

        validation_results[name] = {
            "threshold": threshold,
            **metrics,
        }

        print(f"\n{name}")
        print(f"Validation F1: {metrics['f1_score']:.4f}")
        print(f"Validation precision: {metrics['precision']:.4f}")
        print(f"Validation recall: {metrics['recall']:.4f}")
        print(f"Validation FPR: {metrics['false_positive_rate']:.4f}")

    selected_model_name = max(
        validation_results,
        key=lambda name: validation_results[name]["f1_score"]
    )

    print(f"\nSelected model: {selected_model_name}")

    selected_model = joblib.load(
        MODEL_DIR / f"{selected_model_name}.joblib"
    )

    selected_probabilities = validation_probabilities[
        selected_model_name
    ]

    decision_threshold = validation_results[
        selected_model_name
    ]["threshold"]

    risk_thresholds = choose_risk_thresholds(
        y_validation,
        selected_probabilities
    )

    print("\nValidation-derived thresholds:")
    print("Decision threshold:", decision_threshold)
    print("Risk thresholds:", risk_thresholds)

    # Evaluate the selected model once on the reserved test set.
    print("\nEvaluating selected model on grouped test data...")

    start_time = time.perf_counter()

    test_probabilities = get_phishing_probabilities(
        selected_model,
        X_test
    )

    prediction_time = time.perf_counter() - start_time

    test_predictions = np.where(
        test_probabilities >= decision_threshold,
        "phishing",
        "benign"
    )

    test_metrics = calculate_metrics(
        y_test,
        test_predictions
    )

    risk_categories = np.where(
        test_predictions == "benign",
        "Low",
        np.where(
            test_probabilities < risk_thresholds["high_threshold"],
            "Medium",
            "High"
        )
    )

    risk_counts = {
        category: int(
            np.sum(risk_categories == category)
        )
        for category in ["Low", "Medium", "High"]
    }

    results = {
        "evaluation_date": datetime.now(timezone.utc).isoformat(),
        "experiment": "hostname_grouped",
        "split_method": "StratifiedGroupKFold",
        "grouping_column": "hostname",
        "feature_order": FEATURE_ORDER,
        "validation_results": validation_results,
        "selected_model": selected_model_name,
        "decision_threshold": decision_threshold,
        "risk_thresholds": risk_thresholds,
        "test_results": {
            **test_metrics,
            "test_records": int(len(y_test)),
            "prediction_time_seconds": prediction_time,
            "average_prediction_time_seconds": (
                prediction_time / len(y_test)
            ),
            "risk_category_counts": risk_counts,
        },
    }

    output_file = RESULTS_DIR / "evaluation_results.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(results, file, indent=4)

    print("\nGROUPED TEST RESULTS")
    print("=" * 45)
    print(f"Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"Precision: {test_metrics['precision']:.4f}")
    print(f"Recall: {test_metrics['recall']:.4f}")
    print(f"F1-score: {test_metrics['f1_score']:.4f}")
    print(
        "False positive rate:",
        f"{test_metrics['false_positive_rate']:.4f}"
    )
    print("Confusion matrix:", test_metrics["confusion_matrix"])
    print("Risk categories:", risk_counts)
    print(f"Prediction time: {prediction_time:.4f} seconds")

    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    evaluate_grouped()
