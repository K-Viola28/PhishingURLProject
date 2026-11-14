
import json
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from prepare_data import prepare_url
from analysis.features import FEATURE_ORDER


PROJECT_ROOT = Path(__file__).resolve().parent.parent

SOURCE_PATH = PROJECT_ROOT / "data" / "processed" / "train.csv"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "grouped"

RANDOM_STATE = 42


def extract_hostname(url):
    """Extract a lowercase hostname for grouping URLs."""

    prepared_url = prepare_url(url)
    hostname = urlsplit(prepared_url).hostname

    if not hostname:
        raise ValueError("URL has no hostname.")

    return hostname.lower()


def create_grouped_split():
    print("Loading processed dataset...")

    data = pd.read_csv(SOURCE_PATH)

    required_columns = ["url", "label"] + FEATURE_ORDER

    missing_columns = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    print("Extracting hostnames...")

    data["hostname"] = data["url"].apply(extract_hostname)

    X = data[FEATURE_ORDER]
    y = data["label"]
    groups = data["hostname"]

    # First split: approximately 80% development, 20% testing.
    outer_splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    development_indices, test_indices = next(
        outer_splitter.split(X, y, groups)
    )

    development = data.iloc[development_indices].copy()
    test = data.iloc[test_indices].copy()

    # Second split: approximately 80% training, 20% validation
    # within the development partition.
    inner_splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    train_indices, validation_indices = next(
        inner_splitter.split(
            development[FEATURE_ORDER],
            development["label"],
            development["hostname"],
        )
    )

    train = development.iloc[train_indices].copy()
    validation = development.iloc[validation_indices].copy()

    # Verify that no hostname crosses partitions.
    train_hosts = set(train["hostname"])
    validation_hosts = set(validation["hostname"])
    test_hosts = set(test["hostname"])

    assert train_hosts.isdisjoint(validation_hosts)
    assert train_hosts.isdisjoint(test_hosts)
    assert validation_hosts.isdisjoint(test_hosts)

    # Save partitions without the helper hostname column.
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for name, partition in [
        ("train", train),
        ("validation", validation),
        ("test", test),
    ]:
        partition.drop(columns=["hostname"]).to_csv(
            OUTPUT_DIR / f"{name}.csv",
            index=False,
        )

    summary = {
        "random_state": RANDOM_STATE,
        "split_method": "StratifiedGroupKFold",
        "grouping_column": "hostname",
        "feature_order": FEATURE_ORDER,
        "partitions": {},
        "hostname_overlap": {
            "train_validation": 0,
            "train_test": 0,
            "validation_test": 0,
        },
    }

    for name, partition in [
        ("train", train),
        ("validation", validation),
        ("test", test),
    ]:
        summary["partitions"][name] = {
            "records": len(partition),
            "percentage": round(
                len(partition) / len(data) * 100, 2
            ),
            "unique_hostnames": partition["hostname"].nunique(),
            "label_counts": {
                str(label): int(count)
                for label, count in
                partition["label"].value_counts().items()
            },
        }

    with open(
        OUTPUT_DIR / "split_summary.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(summary, file, indent=4)

    print("\nGROUPED SPLIT SUMMARY")
    print("=" * 45)

    for name, partition in [
        ("TRAIN", train),
        ("VALIDATION", validation),
        ("TEST", test),
    ]:
        print(f"\n{name}")
        print("Records:", len(partition))
        print("Unique hostnames:", partition["hostname"].nunique())
        print("Labels:")
        print(partition["label"].value_counts().to_dict())

    print("\nHostname overlap checks:")
    print("Train / Validation:", len(train_hosts & validation_hosts))
    print("Train / Test:", len(train_hosts & test_hosts))
    print("Validation / Test:", len(validation_hosts & test_hosts))

    print("\nGrouped datasets saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    create_grouped_split()
