from typing import List, Dict
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from transformers import pipeline
import torch
from datetime import datetime
import logging
from sklearn.metrics.pairwise import cosine_similarity

class VulnerabilityPredictor:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = RandomForestClassifier(n_estimators=100)
        self.sentiment_analyzer = pipeline("sentiment-analysis")
        
    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Convert raw data into features for prediction"""
        # Handle different data source formats
        descriptions = []
        for _, row in data.iterrows():
            text = ""
            # Handle CVE data format
            if 'description' in row:
                text += str(row['description'])
            
            # Handle GitHub data format
            if 'advisory' in row and isinstance(row['advisory'], dict):
                if 'description' in row['advisory']:
                    text += " " + str(row['advisory']['description'])
                if 'summary' in row['advisory']:
                    text += " " + str(row['advisory']['summary'])
            
            descriptions.append(text.strip())
        
        # Convert to DataFrame for consistent processing
        text_features = pd.Series(descriptions).fillna('')
        
        # TF-IDF features
        tfidf_features = self.vectorizer.fit_transform(text_features)
        
        # Sentiment features
        sentiments = []
        for text in text_features:
            try:
                # Limit text length for sentiment analysis
                sentiment = self.sentiment_analyzer(text[:512])[0]
                sentiments.append(sentiment['score'])
            except Exception as e:
                logging.warning(f"Error in sentiment analysis: {str(e)}")
                sentiments.append(0.5)  # Neutral sentiment as fallback
        
        # Combine all features
        feature_matrix = np.hstack([
            tfidf_features.toarray(),
            np.array(sentiments).reshape(-1, 1)
        ])
        
        return feature_matrix
    
    def train(self, historical_data: pd.DataFrame, cve_data: pd.DataFrame, 
             github_data: pd.DataFrame):
        """Train the model on historical and current data"""
        # Create labels first to determine our target classes
        y = self._create_labels(historical_data)
        
        # Prepare features from historical data text
        historical_features = []
        for _, row in historical_data.iterrows():
            historical_features.append(row['vulnerability'])
        
        # Convert historical features to the same format as current data
        historical_df = pd.DataFrame({
            'description': historical_features
        })
        
        # Combine with current security data
        training_data = pd.concat([
            historical_df,
            pd.concat([cve_data, github_data])
        ]).reset_index(drop=True)
        
        # Prepare all features
        X = self.prepare_features(training_data)
        
        # Only use the first len(y) samples to match dimensions
        X = X[:len(y)]
        
        # Train classifier
        self.classifier.fit(X, y)
        
        # Store the classes for prediction
        self.classes_ = list(self.vuln_to_idx.keys())
    
    def predict_top10(self, new_data: pd.DataFrame) -> List[Dict]:
        """Predict the next OWASP Top 10"""
        X = self.prepare_features(new_data)
        
        # Handle empty feature matrix
        if len(X) == 0:
            X = np.zeros((1, self.classifier.n_features_in_))
        
        probas = self.classifier.predict_proba(X)
        
        # Map predictions back to vulnerability names
        predictions = []
        for i, proba in enumerate(probas.mean(axis=0), 1):
            vuln_name = list(self.vuln_to_idx.keys())[i % len(self.vuln_to_idx)]
            predictions.append({
                'rank': i,
                'vulnerability': vuln_name,
                'confidence': float(proba),
                'prediction_date': datetime.now().isoformat()
            })
        
        predictions.sort(key=lambda x: x['confidence'], reverse=True)
        return predictions[:10]
    
    def _create_labels(self, historical_data: pd.DataFrame) -> np.ndarray:
        """Create training labels from historical rankings"""
        # Get the most recent year's vulnerabilities as our target classes
        latest_year = historical_data['year'].max()
        latest_vulns = historical_data[historical_data['year'] == latest_year]['vulnerability'].tolist()
        
        # Create a mapping of vulnerability to index
        self.vuln_to_idx = {vuln: idx for idx, vuln in enumerate(latest_vulns)}
        
        # Create TF-IDF vectors for our vulnerability categories
        category_vectorizer = TfidfVectorizer()
        category_vectors = category_vectorizer.fit_transform(latest_vulns)
        
        # Function to find best matching vulnerability category
        def find_best_match(text: str) -> int:
            # Vectorize the input text
            text_vector = category_vectorizer.transform([text])
            # Calculate similarity with all categories
            similarities = cosine_similarity(text_vector, category_vectors)[0]
            # Return index of most similar category
            return similarities.argmax()
        
        # Create labels for each training example
        labels = []
        for _, row in historical_data.iterrows():
            if row['vulnerability'] in self.vuln_to_idx:
                # If it's an exact match, use that index
                labels.append(self.vuln_to_idx[row['vulnerability']])
            else:
                # Otherwise find the most similar category
                labels.append(find_best_match(row['vulnerability']))
        
        return np.array(labels) 