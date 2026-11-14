
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
import sys

# Add the project root to Python's import path.
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import pandas as pd
from sklearn.model_selection import train_test_split

from analysis.features import extract_features, FEATURE_ORDER

# Project paths

INPUT_FILE = PROJECT_DIR / "data" / "raw" / "malicious_phish.csv"
PROCESSED_DIR = PROJECT_DIR / "data" / "processed"

TRAIN_FILE = PROCESSED_DIR / "train.csv"
TEST_FILE = PROCESSED_DIR / "test.csv"
SUMMARY_FILE = PROCESSED_DIR / "cleaning_summary.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def prepare_url(url):
    """
    Prepare a dataset URL for offline feature extraction.

    URLs without a scheme receive a temporary http:// prefix.
    The original URL is retained separately.
    """

    url = str(url).strip()

    if not url:
        raise ValueError("Empty URL.")

    if any(character.isspace() or ord(character) < 32
           for character in url):
        raise ValueError("URL contains whitespace or control characters.")

    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        prepared_url = url
    else:
        prepared_url = "http://" + url

    parts = urlsplit(prepared_url)

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Unsupported URL scheme.")

    if not parts.hostname:
        raise ValueError("URL has no hostname.")

    # Accessing port also checks for malformed port values.
    _ = parts.port

    return prepared_url


def normalize_url(url):
    """
    Create a comparison version of a URL.

    Scheme and hostname are converted to lowercase.
    Path and query are preserved.
    """

    prepared_url = prepare_url(url)
    parts = urlsplit(prepared_url)

    normalized = (
        parts.scheme.lower()
        + "://"
        + parts.netloc.lower()
        + parts.path
    )

    if parts.query:
        normalized += "?" + parts.query

    if parts.fragment:
        normalized += "#" + parts.fragment

    return prepared_url, normalized


def label_counts(data):
    """Return class counts in a JSON-friendly format."""
    return {
        str(label): int(count)
        for label, count in data.value_counts().items()
    }


def prepare_dataset():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}"
        )

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading original dataset...")

    data = pd.read_csv(
        INPUT_FILE,
        usecols=["url", "type"],
        dtype=str
    )

    total_records = len(data)

    data["label"] = data["type"].str.strip().str.lower()

    data["url"] = data["url"].fillna("")

    # Remove records with missing URLs.
    data["url"] = data["url"].str.strip()
    missing_urls = int((data["url"] == "").sum())

    data = data[data["url"] != ""].copy()

    # Keep only the two classes required by the project.
    binary_labels = ["phishing", "benign"]

    binary_data = data[
        data["label"].isin(binary_labels)
    ].copy()

    excluded_non_binary = len(data) - len(binary_data)

    print("Preparing URLs...")

    prepared_urls = []
    normalized_urls = []
    valid_indices = []

    unparseable_urls = 0

    for index, url in zip(
        binary_data.index,
        binary_data["url"]
    ):
        try:
            prepared_url, normalized_url = normalize_url(url)

            # Confirm that the shared feature extractor accepts it.
            extract_features(prepared_url)

            prepared_urls.append(prepared_url)
            normalized_urls.append(normalized_url)
            valid_indices.append(index)

        except (ValueError, TypeError):
            unparseable_urls += 1

    binary_data = binary_data.loc[valid_indices].copy()

    binary_data["prepared_url"] = prepared_urls
    binary_data["normalized_url"] = normalized_urls

    print("Checking conflicting labels...")

    # Identify URLs assigned both phishing and benign labels.
    label_variations = (
        binary_data.groupby("normalized_url")["label"]
        .nunique()
    )

    conflicting_urls = set(
        label_variations[label_variations > 1].index
    )

    conflicting_rows = int(
        binary_data["normalized_url"]
        .isin(conflicting_urls)
        .sum()
    )

    binary_data = binary_data[
        ~binary_data["normalized_url"].isin(conflicting_urls)
    ].copy()

    print("Removing duplicate URLs...")

    before_duplicates = len(binary_data)

    binary_data = binary_data.drop_duplicates(
        subset="normalized_url",
        keep="first"
    ).copy()

    duplicate_rows_removed = (
        before_duplicates - len(binary_data)
    )

    print("Extracting URL features...")

    records = []

    for row in binary_data.itertuples(index=False):

        features = extract_features(row.prepared_url)

        record = {
            "url": row.url,
            "label": row.label,
        }

        for feature in FEATURE_ORDER:
            record[feature] = features[feature]

        records.append(record)

    final_data = pd.DataFrame(records)

    if final_data.empty:
        raise ValueError("No valid records remain after cleaning.")

    if final_data["label"].nunique() < 2:
        raise ValueError(
            "Both phishing and benign classes are required."
        )

    print("Splitting training and testing data...")

    train_data, test_data = train_test_split(
        final_data,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=final_data["label"]
    )

    # Save the two datasets.
    train_data.to_csv(TRAIN_FILE, index=False)
    test_data.to_csv(TEST_FILE, index=False)

    # Prepare cleaning report.
    summary = {
        "original_records": total_records,
        "missing_urls": missing_urls,
        "original_label_counts": label_counts(
            data["label"]
        ),
        "excluded_non_binary_records": excluded_non_binary,
        "unparseable_urls": unparseable_urls,
        "conflicting_url_groups": len(conflicting_urls),
        "conflicting_rows_removed": conflicting_rows,
        "duplicate_rows_removed": duplicate_rows_removed,
        "final_records": len(final_data),
        "final_label_counts": label_counts(
            final_data["label"]
        ),
        "training_records": len(train_data),
        "testing_records": len(test_data),
        "training_label_counts": label_counts(
            train_data["label"]
        ),
        "testing_label_counts": label_counts(
            test_data["label"]
        ),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "feature_order": FEATURE_ORDER,
    }

    with open(SUMMARY_FILE, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4)

    print("\nDATA CLEANING SUMMARY")
    print("=" * 45)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nFiles created:")
    print(TRAIN_FILE)
    print(TEST_FILE)
    print(SUMMARY_FILE)

    print("\nDataset preparation completed.")


if __name__ == "__main__":
    prepare_dataset()
