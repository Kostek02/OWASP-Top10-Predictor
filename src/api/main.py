from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime
import pandas as pd

from src.data.collectors import OWASPHistoricalCollector, GitHubSecurityCollector, CVECollector
from src.models.predictor import VulnerabilityPredictor
from src.utils.report_generator import ReportGenerator

app = FastAPI(title="OWASP Top 10 Predictor")

# Initialize collectors and predictor
historical_collector = OWASPHistoricalCollector()
github_collector = GitHubSecurityCollector()
cve_collector = CVECollector()
predictor = VulnerabilityPredictor()
report_generator = ReportGenerator()

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

@app.get("/generate/report")
async def generate_prediction_report():
    try:
        # Collect all necessary data
        historical_data = historical_collector.collect()
        github_data = github_collector.collect()
        cve_data = cve_collector.collect()
        
        # Train model
        predictor.train(historical_data, cve_data, github_data)
        
        # Get predictions for both 2025 and 2029
        combined_data = pd.concat([cve_data, github_data])
        predictions_2025 = predictor.predict_top10(combined_data, target_year=2025)
        predictions_2029 = predictor.predict_top10(combined_data, target_year=2029)
        
        # Generate the report
        report_path = report_generator.generate_prediction_report(
            predictions_2025=predictions_2025,
            predictions_2029=predictions_2029,
            historical_data=historical_data,
            cve_trends=cve_data,
            github_trends=github_data
        )
        
        return {"status": "success", "report_path": report_path}
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