try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

import re

# representative training dataset reflecting legitimate vs phishing text signals
TRAINING_CORPUS = [
    # Legitimate samples (label 0)
    ("The project meeting has been rescheduled to Thursday at 3 PM in conference room B.", 0),
    ("Please find attached the quarterly performance report for your review and feedback.", 0),
    ("Here is the updated documentation for the API endpoints we discussed yesterday.", 0),
    ("Thanks for sending the invoice. Our accounts team will process it in the next cycle.", 0),
    ("Reminder: Team lunch tomorrow at noon. Let us know your dietary preferences.", 0),
    ("Your package has been delivered to your front porch. Tracking number available in your account.", 0),
    ("Weekly sprint notes: all tickets completed on time. Code review scheduled for Monday.", 0),
    ("The security advisory has been published for repository dependencies. Review when convenient.", 0),

    # Phishing / Social engineering samples (label 1)
    ("URGENT: Your account has been suspended due to unauthorized access. Click here immediately to verify.", 1),
    ("Immediate action required: We detected unusual login attempts. Verify your identity within 24 hours.", 1),
    ("Your bank account is locked. Please confirm your password and credit card details to restore access.", 1),
    ("Security alert: Your mailbox is full. You will lose all incoming emails unless you validate credentials.", 1),
    ("Dear customer, your PayPal balance has been limited. Follow the link to update your billing details.", 1),
    ("Urgent wire transfer request: Wire 50000 dollars to the vendor account immediately per CEO instructions.", 1),
    ("You have won an exclusive lottery prize! Claim your reward now by providing your personal details.", 1),
    ("Payroll update: Your direct deposit failed. Log in now to re-enter your banking credentials immediately.", 1),
]

# high-signal heuristic trigger words with custom weights
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "unauthorized", "locked",
    "24 hours", "restricted", "verify your account", "confirm your password",
    "wire transfer", "freeze", "action required", "billing update"
]


class TextPhishingClassifier:
    def __init__(self):
        if SKLEARN_AVAILABLE:
            self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
            self.model = MultinomialNB()
            self._train()
        else:
            self.vectorizer = None
            self.model = None

    def _train(self):
        if not SKLEARN_AVAILABLE:
            return
        texts = [item[0] for item in TRAINING_CORPUS]
        labels = [item[1] for item in TRAINING_CORPUS]
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)

    def analyze_text(self, text):
        if not text or len(text.strip()) < 10:
            return {"phish_probability": 0, "triggers_found": [], "penalty": 0}

        cleaned_text = re.sub(r"\s+", " ", text).strip().lower()

        # 1. find urgency and panic keywords
        found_triggers = [kw for kw in URGENCY_KEYWORDS if kw in cleaned_text]

        # 2. predict using trained scikit-learn model if installed
        phish_prob = 0
        if SKLEARN_AVAILABLE and self.model:
            vec = self.vectorizer.transform([cleaned_text])
            probabilities = self.model.predict_proba(vec)[0]
            phish_prob = round(float(probabilities[1]) * 100, 2)

        # 3. compute penalty based on both ML probability and trigger word density
        penalty = 0
        if phish_prob > 60:
            penalty += 25
        elif phish_prob > 40:
            penalty += 15
        elif not SKLEARN_AVAILABLE and found_triggers:
            penalty += 15  # heuristic fallback penalty

        # additional penalty for urgency keywords (capped at 20)
        trigger_penalty = min(len(found_triggers) * 5, 20)
        total_penalty = min(penalty + trigger_penalty, 35)

        return {
            "phish_probability": phish_prob,
            "triggers_found": found_triggers,
            "penalty": total_penalty
        }
