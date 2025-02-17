# OWASP Top 10 Predictor

An ML-powered tool to predict future OWASP Top 10 vulnerabilities using historical data and current security trends.

## Features

- Historical OWASP Top 10 data analysis
- CVE data integration
- GitHub security advisory analysis
- Real-time security news monitoring
- ML-based prediction model
- API for predictions and data access

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with required API keys:
```
GITHUB_TOKEN=your_token
NEWS_API_KEY=your_key
```

## Project Structure

- `src/data/` - Data collection and processing
- `src/models/` - ML models and predictions
- `src/api/` - FastAPI backend
- `src/utils/` - Helper functions
- `data/` - Stored datasets
- `notebooks/` - Analysis notebooks 