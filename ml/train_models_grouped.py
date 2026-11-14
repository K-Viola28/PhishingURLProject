
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import joblib
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight

from analysis.features import FEATURE_ORDER


DATA_DIR = PROJECT_DIR / "data" / "processed" / "grouped"
MODEL_DIR = PROJECT_DIR / "models" / "grouped"
RESULTS_DIR = PROJECT_DIR / "results" / "grouped"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42


def load_partition(filename):
    """Load and validate one grouped dataset partition."""

    file_path = DATA_DIR / filename

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    data = pd.read_csv(file_path)

    required_columns = FEATURE_ORDER + ["label"]

    missing_columns = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns in {filename}: {missing_columns}"
        )

    if data[required_columns].isnull().any().any():
        raise ValueError(
            f"Missing values found in {filename}."
        )

    X = data[FEATURE_ORDER].astype(float)
    y = data["label"].astype(str)

    if set(y.unique()) != {"benign", "phishing"}:
        raise ValueError(
            f"{filename} must contain both classes."
        )

    return X, y


def train_grouped_models():

    print("Loading grouped training and validation data...")

    X_train, y_train = load_partition("train.csv")
    X_validation, y_validation = load_partition(
        "validation.csv"
    )

    print(f"Training records: {len(X_train):,}")
    print(f"Validation records: {len(X_validation):,}")
    print(f"Features: {len(FEATURE_ORDER)}")

    # Calculate class weights from training data only.
    classes = np.array(["benign", "phishing"])

    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train
    )

    class_weights = dict(zip(classes, weights))

    print("\nClass weights:")
    print(class_weights)

    # Logistic Regression.
    logistic_model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(
            class_weight=class_weights,
            max_iter=1000,
            random_state=RANDOM_STATE
        ))
    ])

    # Random Forest.
    forest_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight=class_weights,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    models = {
        "logistic_regression": logistic_model,
        "random_forest": forest_model
    }

    print("\nTraining grouped models...")

    for name, model in models.items():

        print(f"\nTraining {name}...")

        model.fit(X_train, y_train)

        model_path = MODEL_DIR / f"{name}.joblib"

        joblib.dump(model, model_path)

        print(f"Saved model: {model_path}")

    # Save validation data for threshold selection.
    validation_data = X_validation.copy()
    validation_data["label"] = y_validation.values

    validation_file = RESULTS_DIR / "validation_data.csv"

    validation_data.to_csv(
        validation_file,
        index=False
    )

    # Save metadata.
    metadata = {
        "training_date": datetime.now(timezone.utc).isoformat(),
        "experiment": "hostname_grouped",
        "dataset": "malicious_phish.csv",
        "training_records": int(len(X_train)),
        "validation_records": int(len(X_validation)),
        "feature_order": FEATURE_ORDER,
        "class_weights": {
            key: float(value)
            for key, value in class_weights.items()
        },
        "random_state": RANDOM_STATE,
        "split_method": "StratifiedGroupKFold",
        "grouping_column": "hostname",
        "models": [
            "logistic_regression",
            "random_forest"
        ]
    }

    metadata_file = MODEL_DIR / "training_metadata.json"

    with open(
        metadata_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(metadata, file, indent=4)

    print("\nGrouped training completed.")
    print(f"Metadata saved: {metadata_file}")
    print(f"Validation data saved: {validation_file}")


if __name__ == "__main__":
    train_grouped_models()
