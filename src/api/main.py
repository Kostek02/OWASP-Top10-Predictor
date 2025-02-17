from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime
import pandas as pd

from src.data.collectors import OWASPHistoricalCollector, GitHubSecurityCollector, CVECollector
from src.models.predictor import VulnerabilityPredictor

app = FastAPI(title="OWASP Top 10 Predictor")

# Initialize collectors and predictor
historical_collector = OWASPHistoricalCollector()
github_collector = GitHubSecurityCollector()
cve_collector = CVECollector()
predictor = VulnerabilityPredictor()

class Prediction(BaseModel):
    rank: int
    vulnerability: str
    confidence: float
    prediction_date: str

@app.get("/predict/next-top10", response_model=List[Prediction])
async def predict_next_top10():
    try:
        # Collect data
        historical_data = historical_collector.collect()
        github_data = github_collector.collect()
        cve_data = cve_collector.collect()
        
        # Train model
        predictor.train(historical_data, cve_data, github_data)
        
        # Make predictions
        predictions = predictor.predict_top10(pd.concat([cve_data, github_data]))
        
        return predictions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/data/historical", response_model=List[Dict])
async def get_historical_data():
    try:
        data = historical_collector.collect()
        return data.to_dict('records')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()} 