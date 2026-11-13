
import csv
from pathlib import Path
from collections import Counter


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_DIR / "data" / "raw" / "malicious_phish.csv"


def inspect_dataset():

    if not DATASET_PATH.exists():
        raise FileNotFoundError(DATASET_PATH)

    total_rows = 0
    missing_urls = 0
    label_counts = Counter()
    sample_records = []

    print("Inspecting dataset...")
    print(f"File: {DATASET_PATH.name}")

    with open(
        DATASET_PATH,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        print("\nColumns:")
        print(reader.fieldnames)

        if not {"url", "type"}.issubset(reader.fieldnames or []):
            raise ValueError("Expected columns 'url' and 'type'.")

        for row in reader:

            total_rows += 1

            if len(sample_records) < 5:
                sample_records.append(row)

            url = (row.get("url") or "").strip()
            label = (row.get("type") or "").strip()

            if not url:
                missing_urls += 1

            label_counts[label] += 1

    print("\nSample records:")
    for record in sample_records:
        print(record)

    print("\nDataset inspection summary")
    print("-" * 40)
    print(f"Total records: {total_rows:,}")
    print(f"Missing URLs: {missing_urls:,}")

    print("\nLabel distribution:")
    for label, count in label_counts.items():
        print(f"{label}: {count:,}")

    print("\nOriginal dataset remains unchanged.")


if __name__ == "__main__":
    inspect_dataset()
