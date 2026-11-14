# Web-Based URL Phishing Detector for Small Business Traders

## 1. Project Overview

The Web-Based URL Phishing Detector for Small Business Traders is a web application designed to help small business traders assess potentially suspicious URLs.

The system uses machine learning to analyse submitted URLs and classify them as either phishing or benign. It extracts URL-based features and uses a trained Random Forest model to generate a prediction, an estimated phishing probability, a risk category and details of the extracted features.

The system is intended to provide an additional layer of awareness when traders encounter suspicious links. Its predictions are estimates and should not be treated as a guarantee that a URL is safe or malicious.

## 2. Project Scope

The system focuses exclusively on analysing URLs submitted by users through a web interface.

It includes:
- URL input and validation.
- URL feature extraction.
- Machine-learning-based phishing detection.
- Estimated phishing probability.
- Risk categorisation.
- Display of extracted URL features.

The system does not analyse email messages, SMS messages, website content, attachments or network traffic. It does not visit submitted URLs or guarantee protection against all phishing attacks.

## 3. Key Features

- URL submission through a web interface.
- URL format validation.
- Extraction of nine URL-based features.
- Phishing and benign classification using Random Forest.
- Estimated phishing probability.
- Low, Medium and High risk categorisation.
- Display of extracted URL features.

## 4. Technologies Used

- Python 3.14 – Main programming language.
- Django 6.1.3 – Web application framework.
- Pandas – Dataset preparation and manipulation.
- NumPy – Numerical operations.
- Scikit-learn – Machine-learning model development and evaluation.
- Joblib – Saving and loading the trained model.
- SQLite – Application database.
- HTML and CSS – User interface.

## 5. Project Structure

```text
PhishingURLProject/
│
├── analysis/                  # URL validation, feature extraction and prediction
├── config/                    # Django project configuration
├── data/                      # Original and processed datasets
├── ml/                        # Data preparation, model training and evaluation scripts
├── models/                    # Trained machine-learning model and metadata
├── results/                   # Model evaluation results
├── templates/                 # HTML templates
├── tests/                     # Automated tests
├── manage.py                  # Django management script
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```
## 6. Dataset and Data Cleaning

The project uses the `malicious_phish.csv` dataset obtained from Kaggle.

The original dataset contained 651,191 URL records across four categories: benign, phishing, defacement and malware.

For this project, the dataset was converted into a binary classification dataset by retaining only benign and phishing URLs. Defacement and malware records were excluded because they fall outside the project's classification scope.

The data cleaning process involved:
- Checking for missing and empty URLs.
- Normalising URL labels and formats.
- Identifying URLs with conflicting labels.
- Removing conflicting records.
- Removing duplicate URLs.
- Extracting the nine URL-based features.
- Preparing the cleaned data for model development.

After cleaning, the dataset contained 522,160 records:
- Benign: 428,074
- Phishing: 94,086

The cleaned dataset was then used for hostname-grouped training, validation and testing to reduce the risk of similar hostnames appearing across different data partitions.
## 7. Machine-Learning Methodology

The project uses supervised machine learning to classify URLs as either phishing or benign.

Nine URL-based features are extracted from each submitted URL and passed to the trained classification model.

The nine features extracted are:

1. `uses_https`
2. `hostname_is_ip`
3. `url_length`
4. `subdomain_count`
5. `suspicious_keyword_count`
6. `special_char_count`
7. `encoded_char_count`
8. `has_at_symbol`
9. `brand_misuse`

Two algorithms were evaluated:
- Logistic Regression, used as a baseline model.
- Random Forest, evaluated as an alternative classification model.

The models were compared using validation data. Random Forest was selected based on its validation performance.

The final model was evaluated using a separate test dataset that was not used during model training or model selection.

The data was divided using hostname-grouped splitting to reduce data leakage caused by URLs sharing the same hostname across training, validation and testing datasets.

The selected Random Forest model produces a phishing probability estimate, which is used to generate a prediction and assign a risk category.
## 8. Model Evaluation Results

The selected Random Forest model was evaluated using a separate test dataset containing 82,225 URL records.

The evaluation produced the following results:

| Metric | Result |
|---|---:|
| Accuracy | 75.15% |
| Precision | 38.03% |
| Recall | 66.72% |
| F1-score | 48.45% |
| False Positive Rate | 23.07% |

The results show that the model identified approximately 66.72% of the phishing URLs in the test dataset. However, the precision and false positive rate indicate that some benign URLs were incorrectly classified as phishing.

These results demonstrate that the system can assist with identifying potentially suspicious URLs, but its predictions should not be treated as definitive security decisions.
## 9. Installation and Setup

### Prerequisites

- Python 3.14
- Git
- A virtual environment

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/K-Viola28/PhishingURLProject.git
   ```

2. Navigate to the project directory:

   ```bash
   cd PhishingURLProject
   ```

3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Activate the virtual environment:

   **Windows:**
   ```bash
   .venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   source .venv/bin/activate
   ```

5. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

6. Create a `.env` file in the project root and configure the Django secret key:

   ```text
   DJANGO_SECRET_KEY=your-secret-key
   ```

7. Ensure the trained model and evaluation results are available:

   - `models/grouped/random_forest.joblib`
   - `results/grouped/evaluation_results.json`
## 10. Running the Application

1. Activate the virtual environment.

2. Apply database migrations:

   ```bash
   python manage.py migrate
   ```

3. Start the Django development server:

   ```bash
   python manage.py runserver
   ```

4. Open the application in your browser using the local development address:

   ```text
   http://127.0.0.1:8000/
   ```

5. Enter a URL into the input field and submit it for analysis.

6. Review the prediction, estimated phishing probability, risk category and extracted URL characteristics.
## 11. Limitations

- The system analyses URL characteristics and does not inspect website content.
- The model may incorrectly classify legitimate URLs as phishing (false positives).
- The model may fail to identify some phishing URLs (false negatives).
- The model's performance depends on the quality and coverage of the training dataset.
- The phishing probability is an estimate produced by the model and does not represent a guarantee that a URL is malicious or safe.
- The system does not replace other cybersecurity measures or professional security assessment.