from fastapi import FastAPI
from pydantic import BaseModel
import pickle, numpy as np, requests, re

# Load models
with open('vectorizer.pkl','rb') as f: tfidf=pickle.load(f)
with open('model.pkl','rb') as f: mnb=pickle.load(f)
with open('rf.pkl','rb') as f: rf=pickle.load(f)
with open('et.pkl','rb') as f: et=pickle.load(f)

app=FastAPI()

strong_kw=['cashback','earn from home','free','click','offer','win','lottery','link','http','buy now','subscribe']
fixed_kw=['urgent','claim now','limited offer','congratulations','winner','100% free','get money']
API_KEY="AIzaSyCsv_Y6iZvFfJW80XpvyB4XYOn-GPII1k0"

class InText(BaseModel): text:str

@app.get("/")
def root(): return {"msg":"fastapi is working"}

def chk_safe(text):
  urls=[w for w in text.split() if w.startswith('http')]
  if not urls: return "no url"
  ep=f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
  pl={
    "client":{"clientId":"spam-detector","clientVersion":"1.0"},
    "threatInfo":{
      "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
      "platformTypes":["ANY_PLATFORM"],
      "threatEntryTypes":["URL"],
      "threatEntries":[{"url":u} for u in urls]
    }
  }
  r=requests.post(ep,json=pl)
  return "unsafe url found" if "matches" in r.json() else "all urls safe"

@app.post("/predict")
def pred(d:InText):
  t=d.text
  t_low=t.lower()

  for kw in fixed_kw:
    if re.search(rf'\b{re.escape(kw)}\b',t_low):
      return {
        "result":"spam (fixed kw)",
        "matched_kw":kw,
        "mnb_proba":None,
        "rf_pred":None,
        "et_pred":None,
        "thresh":None,
        "url_stat":chk_safe(t)
      }

  vec=tfidf.transform([t])
  mnb_p=mnb.predict_proba(vec)[0][1]
  rf_p=rf.predict(vec)[0]
  et_p=et.predict(vec)[0]
  th=0.15 if any(k in t_low for k in strong_kw) else 0.5
  is_spam=mnb_p>=th or rf_p or et_p

  return {
    "result":"spam" if is_spam else "ham",
    "mnb_proba":mnb_p,
    "rf_pred":int(rf_p),
    "et_pred":int(et_p),
    "thresh":th,
    "url_stat":chk_safe(t)
  }
