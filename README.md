# 📩 SMS Spam Classifier with URL Safety Check

This project classifies SMS messages as **Spam** or **Ham** using an ensemble of `MultinomialNB`, `RandomForest`, and `ExtraTrees` classifiers. It also integrates **Google Safe Browsing API** to check if URLs in the message are **malicious or phishing**.

---

## 🚀 Features

- Spam detection using a trained model.
- URL scanning via Google Safe Browsing API.
- Built with **FastAPI** (backend) and **Streamlit** (frontend).
- FN = 0 target: zero False Negatives with reduced False Positives (FP).
- Ensemble model logic for high accuracy.

---

## 📂 Repository Structure
sms-spam-classifier/
├── app.py # Streamlit frontend
├── main.py # FastAPI backend
├── preprocessing/
│ └── 01_DataPreprocessing.ipynb
├── models/
│ ├── vectorizer.pkl
│ ├── mnb_model.pkl
│ ├── rf_model.pkl
│ └── et_model.pkl
├── requirements.txt
├── .gitignore
└── README.md

```bash
uvicorn main:app --reload
```

``` bash
streamlit run app.py
```