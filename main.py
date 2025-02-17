import os
import sys
import logging
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from src.data.collectors import OWASPHistoricalCollector, GitHubSecurityCollector, CVECollector
from src.models.predictor import VulnerabilityPredictor

def setup_environment():
    """Setup environment variables and required directories"""
    # Load environment variables
    env_file = Path('.env')
    if not env_file.exists():
        if Path('.env.example').exists():
            print("ERROR: .env file not found. Please copy .env.example to .env and configure your environment variables.")
        else:
            print("ERROR: Neither .env nor .env.example files found.")
        sys.exit(1)
    
    load_dotenv()
    
    # Create required directories
    directories = [
        'results',
        'data',
        'models',
        'logs',
        os.path.dirname(os.getenv('MODEL_SAVE_PATH', 'models/owasp_predictor.pkl')),
        os.path.dirname(os.getenv('VECTORIZER_SAVE_PATH', 'models/tfidf_vectorizer.pkl')),
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def setup_logging():
    """Setup logging configuration"""
    log_file = os.getenv('LOG_FILE', 'logs/predictor.log')
    log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper())
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    # Suppress unnecessary warnings
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)

def check_api_keys():
    """Check if required API keys are configured"""
    github_token = os.getenv('GITHUB_TOKEN')
    if not github_token:
        logging.error("GitHub token not found in environment variables. Please set GITHUB_TOKEN in your .env file.")
        sys.exit(1)
    
    nvd_api_key = os.getenv('NVD_API_KEY')
    if not nvd_api_key:
        logging.warning("NVD API key not found. Will use unauthenticated requests (rate limited).")

def plot_historical_trends(historical_data: pd.DataFrame):
    """Generate plot of vulnerability trends over time"""
    logging.info("Generating historical trends plot...")
    
    # Drop duplicates before pivoting
    historical_data = historical_data.drop_duplicates(subset=['year', 'vulnerability'], keep='first')
    
    # Ensure data is properly normalized before pivoting
    historical_data['year'] = historical_data['year'].astype(str)
    historical_data['vulnerability'] = historical_data['vulnerability'].astype(str)
    
    trend_data = historical_data.pivot(index='year', columns='vulnerability', values='rank')
    
    # Create line plot
    fig = go.Figure()
    for vuln in trend_data.columns:
        fig.add_trace(go.Scatter(
            x=trend_data.index,
            y=trend_data[vuln],
            name=vuln,
            mode='lines+markers'
        ))
    
    fig.update_layout(
        title='OWASP Top 10 Vulnerability Trends (2004-2021)',
        xaxis_title='Year',
        yaxis_title='Rank',
        yaxis_autorange='reversed'  # Reverse y-axis so rank 1 is at top
    )
    
    fig.write_html('results/historical_trends.html')

def analyze_vulnerability_persistence(historical_data: pd.DataFrame):
    """Analyze how long vulnerabilities persist in the Top 10"""
    logging.info("Analyzing vulnerability persistence...")
    
    # Remove duplicates before analysis
    historical_data = historical_data.drop_duplicates(subset=['year', 'vulnerability'], keep='first')
    
    persistence = historical_data.groupby('vulnerability')['year'].nunique().sort_values(ascending=False)
    
    fig = px.bar(
        persistence,
        title='Vulnerability Persistence in OWASP Top 10 (2004-2021)',
        labels={'vulnerability': 'Vulnerability', 'year': 'Years Present'}
    )
    
    fig.write_html('results/vulnerability_persistence.html')

def generate_prediction_report(predictions: list, historical_data: pd.DataFrame):
    """Generate a detailed prediction report"""
    logging.info("Generating prediction report...")
    
    report = ["# OWASP Top 10 2025 Predictions\n\n"]
    report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # Add predictions
    report.append("## Predicted Top 10\n\n")
    for pred in predictions:
        report.append(f"{pred['rank']}. {pred['vulnerability']} (Confidence: {pred['confidence']:.2%})\n")
    
    # Add historical context
    report.append("\n## Historical Context\n\n")
    latest_year = historical_data['year'].max()
    latest_top10 = historical_data[historical_data['year'] == latest_year].sort_values('rank')
    
    report.append(f"### Current Top 10 ({latest_year})\n\n")
    for _, row in latest_top10.iterrows():
        report.append(f"{row['rank']}. {row['vulnerability']}\n")
    
    # Add analysis
    report.append("\n## Analysis\n\n")
    
    # New entries
    current = set(latest_top10['vulnerability'])
    predicted = set(p['vulnerability'] for p in predictions)
    new_entries = predicted - current
    if new_entries:
        report.append("### New Vulnerabilities\n\n")
        for entry in new_entries:
            report.append(f"- {entry}\n")
    
    # Dropped entries
    dropped = current - predicted
    if dropped:
        report.append("\n### Dropped Vulnerabilities\n\n")
        for entry in dropped:
            report.append(f"- {entry}\n")
    
    with open('results/prediction_report.md', 'w') as f:
        f.write('\n'.join(report))

def main():
    try:
        print("Starting OWASP Top 10 2025 prediction analysis...")
        
        # Setup environment and logging
        setup_environment()
        setup_logging()
        check_api_keys()
        
        logging.info("Environment setup complete")
        
        # Collect data
        logging.info("Collecting historical OWASP data...")
        historical_collector = OWASPHistoricalCollector()
        historical_data = historical_collector.collect()
        
        logging.info("Collecting current security data...")
        github_collector = GitHubSecurityCollector()
        cve_collector = CVECollector()
        
        github_data = github_collector.collect()
        cve_data = cve_collector.collect()
        
        # Generate historical analysis
        logging.info("Generating historical analysis...")
        plot_historical_trends(historical_data)
        analyze_vulnerability_persistence(historical_data)
        
        # Train model and generate predictions
        logging.info("Training model and generating predictions...")
        predictor = VulnerabilityPredictor()
        predictor.train(historical_data, cve_data, github_data)
        predictions = predictor.predict_top10(pd.concat([cve_data, github_data]))
        
        # Generate prediction report
        generate_prediction_report(predictions, historical_data)
        
        logging.info("Analysis complete! Results are available in the 'results' directory:")
        print("\nResults available in:")
        print("- results/historical_trends.html")
        print("- results/vulnerability_persistence.html")
        print("- results/prediction_report.md")
        
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main() 