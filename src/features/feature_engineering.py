class FeatureEngineer:
    """Engineers features from CVE data for OWASP Top 10 prediction"""
    
    def __init__(self):
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.label_encoder = LabelEncoder()
    
    def engineer_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Engineer features from CVE data and split into X (features) and y (labels)"""
        logging.info("Engineering features from CVE data...")
        
        # Clean and preprocess text data
        df['description'] = df['description'].fillna('').apply(self._preprocess_text)
        
        # Extract text features
        description_features = self.text_vectorizer.fit_transform(df['description'])
        
        # Create temporal features
        df['published_date'] = pd.to_datetime(df['published_date'])
        df['year'] = df['published_date'].dt.year
        df['month'] = df['published_date'].dt.month
        df['day_of_week'] = df['published_date'].dt.dayofweek
        
        # Create source-based features
        source_dummies = pd.get_dummies(df['source'], prefix='source')
        
        # Create attack vector features
        attack_vector_dummies = pd.get_dummies(df['attack_vector'], prefix='attack_vector')
        
        # Create attack complexity features
        attack_complexity_dummies = pd.get_dummies(df['attack_complexity'], prefix='attack_complexity')
        
        # Normalize severity scores
        df['severity'] = df['severity'].fillna(0).clip(0, 10)
        
        # Create time-based trend features
        df = self._add_trend_features(df)
        
        # Combine all features
        feature_matrix = pd.concat([
            pd.DataFrame(description_features.toarray(), 
                        columns=[f'text_{i}' for i in range(description_features.shape[1])]),
            pd.DataFrame({
                'year': df['year'],
                'month': df['month'],
                'day_of_week': df['day_of_week'],
                'severity': df['severity']
            }),
            source_dummies,
            attack_vector_dummies,
            attack_complexity_dummies,
            pd.DataFrame(self._extract_custom_features(df))
        ], axis=1)
        
        # Encode labels (impact types)
        labels = self.label_encoder.fit_transform(df['impact_type'])
        
        logging.info(f"Engineered {feature_matrix.shape[1]} features")
        return feature_matrix, pd.DataFrame(labels, columns=['impact_type'])
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text data for feature extraction"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters and digits
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def _add_trend_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add time-based trend features"""
        # Calculate rolling averages of severity by source
        df['severity_30d_avg'] = df.groupby('source')['severity'].transform(
            lambda x: x.rolling('30D', on=df['published_date']).mean()
        )
        
        # Calculate vulnerability frequency by source
        df['vuln_freq_30d'] = df.groupby('source')['id'].transform(
            lambda x: x.rolling('30D', on=df['published_date']).count()
        )
        
        # Fill NaN values with global means
        df['severity_30d_avg'] = df['severity_30d_avg'].fillna(df['severity'].mean())
        df['vuln_freq_30d'] = df['vuln_freq_30d'].fillna(df.groupby('source')['id'].transform('count').mean())
        
        return df
    
    def _extract_custom_features(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """Extract custom features from the data"""
        features = {}
        
        # Extract CWE patterns from descriptions
        features['has_cwe'] = df['description'].str.contains('CWE-', case=False).astype(int)
        
        # Extract version patterns
        features['has_version'] = df['description'].str.contains(r'v\d+\.\d+|version \d+', case=False).astype(int)
        
        # Extract package manager patterns
        pkg_patterns = r'npm|pip|gem|maven|nuget|composer'
        features['has_package'] = df['description'].str.contains(pkg_patterns, case=False).astype(int)
        
        # Extract framework patterns
        framework_patterns = r'django|flask|spring|rails|angular|react|vue'
        features['has_framework'] = df['description'].str.contains(framework_patterns, case=False).astype(int)
        
        # Extract cloud service patterns
        cloud_patterns = r'aws|azure|gcp|cloud'
        features['has_cloud'] = df['description'].str.contains(cloud_patterns, case=False).astype(int)
        
        # Extract authentication patterns
        auth_patterns = r'auth|login|password|credential|session'
        features['has_auth'] = df['description'].str.contains(auth_patterns, case=False).astype(int)
        
        # Extract database patterns
        db_patterns = r'sql|nosql|database|mongodb|mysql|postgresql'
        features['has_database'] = df['description'].str.contains(db_patterns, case=False).astype(int)
        
        # Extract API patterns
        api_patterns = r'api|endpoint|rest|graphql|grpc'
        features['has_api'] = df['description'].str.contains(api_patterns, case=False).astype(int)
        
        # Extract encryption patterns
        crypto_patterns = r'encrypt|decrypt|cipher|crypto|tls|ssl'
        features['has_crypto'] = df['description'].str.contains(crypto_patterns, case=False).astype(int)
        
        # Extract file operation patterns
        file_patterns = r'file|directory|path|upload|download'
        features['has_file_ops'] = df['description'].str.contains(file_patterns, case=False).astype(int)
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return (
            [f'text_{i}' for i in range(len(self.text_vectorizer.get_feature_names_out()))] +
            ['year', 'month', 'day_of_week', 'severity'] +
            [f'source_{s}' for s in self.label_encoder.classes_] +
            [f'attack_vector_{av}' for av in ['network', 'local', 'physical', 'unknown']] +
            [f'attack_complexity_{ac}' for ac in ['high', 'low', 'unknown']] +
            ['has_cwe', 'has_version', 'has_package', 'has_framework',
             'has_cloud', 'has_auth', 'has_database', 'has_api',
             'has_crypto', 'has_file_ops']
        )
    
    def get_label_names(self) -> List[str]:
        """Get list of label names"""
        return list(self.label_encoder.classes_) 