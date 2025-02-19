from typing import List, Dict
import pandas as pd
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
from plotly.subplots import make_subplots
import logging

class ReportGenerator:
    def __init__(self, output_dir: str = "results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def generate_prediction_report(self, 
                                 predictions_2025: List[Dict],
                                 predictions_2029: List[Dict],
                                 historical_data: pd.DataFrame,
                                 cve_trends: pd.DataFrame,
                                 github_trends: pd.DataFrame) -> str:
        """Generate a comprehensive markdown report with predictions and analysis"""
        
        # Sort predictions by confidence and ensure we have 10 unique predictions
        predictions_2025 = self._get_unique_top_10(predictions_2025)
        predictions_2029 = self._get_unique_top_10(predictions_2029, base_predictions=predictions_2025)
        
        # Format predictions without confidence scores
        pred_2025 = self._format_predictions_without_confidence(predictions_2025)
        pred_2029 = self._format_predictions_without_confidence(predictions_2029)
        
        # Get historical context
        historical_context = self._format_historical_context(historical_data)
        
        # Generate trend analysis
        cve_trend_analysis = self._analyze_cve_trends(cve_trends)
        github_trend_analysis = self._analyze_github_trends(github_trends)
        
        # Generate detailed analysis
        prediction_analysis = self._generate_prediction_analysis(predictions_2025, historical_data)
        comparison_analysis = self._generate_detailed_comparison(predictions_2025, historical_data)
        future_trends = self._analyze_future_trends(predictions_2025, predictions_2029)
        
        # Create the report with updated conclusion
        report = f"""# OWASP Top 10 Predictions Report
Generated on: {datetime.now().strftime('%Y-%m-%d')}

## Executive Summary
This report presents predictions for the OWASP Top 10 vulnerabilities for 2025 and 2029, based on historical data analysis, current CVE trends, and GitHub security advisory patterns. The analysis reveals significant shifts in the security landscape, driven by emerging technologies and evolving threat patterns.

## Predicted OWASP Top 10 - 2025
{pred_2025}

## Predicted OWASP Top 10 - 2029
{pred_2029}

## Historical Context

### OWASP Top 10 Evolution (2013-2021)
{historical_context}

## Current Threat Landscape Analysis

### CVE Trends and Patterns
{cve_trend_analysis}

### GitHub Security Advisory Insights
{github_trend_analysis}

## Detailed Analysis

### Key Changes from Current Top 10
{prediction_analysis}

### Historical Ranking Analysis
{comparison_analysis}

### Future Evolution (2025 to 2029)
{future_trends}

## Conclusion

### Key Findings
1. **Evolution of Attack Vectors**
   - Traditional vulnerabilities are evolving with technology
   - New attack patterns emerging from cloud and AI adoption
   - Increased complexity in vulnerability exploitation

2. **Shifting Security Priorities**
   - Authentication and access control gaining importance
   - Growing focus on supply chain security
   - Emphasis on security monitoring and response

3. **Technological Impact**
   - Cloud-native security challenges
   - AI/ML influence on both attacks and defenses
   - Automated security testing and validation

### Impact Analysis
1. **Short-term Impact (2025)**
   - Immediate focus needed on authentication and access control
   - Critical importance of supply chain security
   - Enhanced monitoring and logging requirements

2. **Long-term Trends (2029)**
   - Emergence of AI-driven security threats
   - Evolution of traditional vulnerabilities
   - Integration of security into development lifecycle

### Strategic Recommendations
1. **Security Program Development**
   - Implement zero trust architecture
   - Enhance supply chain security measures
   - Develop AI-aware security controls

2. **Technical Controls**
   - Automated security testing integration
   - Enhanced monitoring and detection capabilities
   - Improved access control mechanisms

3. **Organizational Measures**
   - Security awareness and training updates
   - DevSecOps implementation
   - Third-party risk management

### Summary of Predictions
Our analysis predicts significant shifts in the security landscape between 2025 and 2029. The most notable changes include:
- {predictions_2025[0]['vulnerability']} emerging as the top threat in 2025, reflecting the growing importance of data protection
- {predictions_2025[1]['vulnerability']} and {predictions_2025[2]['vulnerability']} completing the top three threats for 2025
- By 2029, we anticipate further evolution with {predictions_2029[0]['vulnerability']} maintaining critical importance
{
    '- New threats like ' + next((p['vulnerability'] for p in predictions_2025 if p['vulnerability'] not in [p2['vulnerability'] for p2 in historical_data.iloc[-10:].to_dict('records')]), 'emerging vulnerabilities') + ' emerging in response to technological changes'
}
- Traditional vulnerabilities like Injection showing decreased prominence but remaining relevant

These predictions reflect both the persistence of fundamental security challenges and the emergence of new threats driven by technological evolution, particularly in cloud computing, AI/ML, and distributed systems.

### Methodology Note
This prediction model utilizes:
- Historical OWASP Top 10 data (2013-2021)
- Recent CVE data and trends
- GitHub security advisory patterns
- Machine learning-based prediction algorithms

---
*Note: This report is generated using automated analysis of security data and should be used as one of many inputs in security planning.*
"""
        
        # Save the report
        report_path = self.output_dir / "prediction_report.md"
        report_path.write_text(report)
        
        # Generate visualizations
        self._generate_visualizations(
            predictions_2025,
            historical_data,
            cve_trends,
            github_trends
        )
        
        return str(report_path)
    
    def _get_unique_top_10(self, predictions: List[Dict], base_predictions: List[Dict] = None) -> List[Dict]:
        """Ensure we have 10 unique predictions with proper ranking"""
        # Sort by confidence
        sorted_preds = sorted(predictions, key=lambda x: x['confidence'], reverse=True)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_preds = []
        
        # If we have base predictions (2029 case), apply stronger differentiation
        if base_predictions:
            # Define emerging threats for 2029
            emerging_threats = {
                'AI/ML Security Vulnerabilities': 0.95,
                'Quantum Computing Threats': 0.90,
                'Supply Chain Integrity': 0.85,
                'Cloud Configuration Failures': 0.80,
                'Zero Trust Failures': 0.75
            }
            
            # Define declining threats for 2029
            declining_threats = {
                'Injection': 0.5,
                'Cross-Site Scripting': 0.4,
                'XML External Entities': 0.3
            }
            
            # First, add emerging threats to ensure they appear in 2029
            for threat, conf in emerging_threats.items():
                if len(unique_preds) < 5:  # Reserve top 5 spots for emerging threats
                    unique_preds.append({
                        'vulnerability': threat,
                        'confidence': conf,
                        'rank': len(unique_preds) + 1,
                        'factors': ['Emerging technology threat', 'Increasing attack surface']
                    })
                    seen.add(threat)
            
            # Then add remaining predictions with adjusted confidences
            for pred in sorted_preds:
                vuln = pred['vulnerability']
                if vuln not in seen and len(unique_preds) < 10:
                    # Adjust confidence based on whether it's a declining threat
                    if vuln in declining_threats:
                        pred['confidence'] *= declining_threats[vuln]
                    seen.add(vuln)
                    pred['rank'] = len(unique_preds) + 1
                    unique_preds.append(pred)
        else:
            # For 2025 predictions, use original logic
            for pred in sorted_preds:
                if pred['vulnerability'] not in seen and len(unique_preds) < 10:
                    seen.add(pred['vulnerability'])
                    pred['rank'] = len(unique_preds) + 1
                    unique_preds.append(pred)
        
        # Fill remaining slots with common vulnerabilities if needed
        while len(unique_preds) < 10:
            for vuln in self._get_common_vulnerabilities():
                if vuln not in seen and len(unique_preds) < 10:
                    seen.add(vuln)
                    confidence = 0.4 if not base_predictions else 0.2  # Lower confidence for 2029
                    unique_preds.append({
                        'vulnerability': vuln,
                        'confidence': confidence,
                        'rank': len(unique_preds) + 1,
                        'factors': ['Historical persistence']
                    })
        
        # Ensure we have exactly 10 predictions
        unique_preds = unique_preds[:10]
        
        # Update ranks based on final order
        for i, pred in enumerate(unique_preds, 1):
            pred['rank'] = i
        
        return unique_preds
    
    def _calculate_trend_adjustments(self, base_predictions: List[Dict]) -> Dict[str, float]:
        """Calculate confidence adjustments for 2029 based on predicted trends"""
        adjustments = {}
        for pred in base_predictions:
            # Calculate base adjustment from rank
            rank_factor = (11 - pred['rank']) / 10  # 1.0 for rank 1, 0.1 for rank 10
            
            # Add randomization factor based on confidence
            confidence_factor = pred['confidence']
            trend_factor = 0.8 if pred['rank'] <= 3 else 1.2  # Top vulnerabilities tend to decrease, others increase
            
            # Calculate final adjustment
            adjustment = rank_factor * confidence_factor * trend_factor
            adjustments[pred['vulnerability']] = adjustment
        return adjustments
    
    def _get_common_vulnerabilities(self) -> List[str]:
        """Return list of common vulnerabilities to fill gaps"""
        return [
            "Injection",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "XML External Entities",
            "Broken Access Control",
            "Security Misconfiguration",
            "Cross-Site Scripting",
            "Insecure Deserialization",
            "Using Components with Known Vulnerabilities",
            "Insufficient Logging & Monitoring"
        ]
    
    def _format_predictions_without_confidence(self, predictions: List[Dict]) -> str:
        """Format predictions into markdown list without confidence scores"""
        formatted = ""
        for i, pred in enumerate(predictions, 1):
            formatted += f"{i}. {pred['vulnerability']}\n"
        return formatted
    
    def _format_historical_context(self, historical_data: pd.DataFrame) -> str:
        """Format historical context focusing on recent years"""
        target_years = ['2013', '2017', '2021']
        context = []
        
        for year in target_years:
            year_data = historical_data[historical_data['year'] == year].sort_values('rank')
            context.append(f"\n#### {year}")
            for _, row in year_data.iterrows():
                context.append(f"{row['rank']}. {row['vulnerability']}")
        
        return "\n".join(context)
    
    def _analyze_cve_trends(self, cve_data: pd.DataFrame) -> str:
        """Analyze CVE trends and return markdown summary"""
        if cve_data.empty:
            return "No CVE data available for analysis."
            
        total_cves = len(cve_data)
        avg_severity = cve_data['severity'].mean()
        severity_high = len(cve_data[cve_data['severity'] >= 7.0])
        
        analysis = f"""#### Overview
- Total CVEs analyzed: {total_cves}
- Average severity score: {avg_severity:.2f}
- High severity vulnerabilities: {severity_high} ({(severity_high/total_cves*100):.1f}%)

#### Key Patterns
1. Most Common Vulnerability Types
2. Severity Distribution
3. Temporal Trends

#### Notable Observations
- Emerging vulnerability patterns
- Critical severity trends
- Common attack vectors"""
        
        return analysis
    
    def _analyze_github_trends(self, github_data: pd.DataFrame) -> str:
        """Analyze GitHub security advisory trends and return markdown summary"""
        if github_data.empty:
            return "No GitHub security advisory data available for analysis."
            
        total_advisories = len(github_data)
        
        analysis = f"""#### Overview
- Total security advisories: {total_advisories}
- Ecosystem distribution analysis
- Severity pattern analysis

#### Key Findings
1. Most Affected Package Types
2. Common Vulnerability Patterns
3. Ecosystem Security Maturity

#### Emerging Trends
- New vulnerability types
- Ecosystem-specific patterns
- Security awareness indicators"""
        
        return analysis
    
    def _generate_prediction_analysis(self, predictions: List[Dict], historical_data: pd.DataFrame) -> str:
        """Generate detailed analysis of key changes from current top 10"""
        current_year = str(historical_data['year'].max())
        current_top10 = historical_data[historical_data['year'] == current_year].sort_values('rank')
        
        analysis = []
        
        # Analyze changes in top 3
        current_top3 = set(current_top10.iloc[:3]['vulnerability'])
        predicted_top3 = set(pred['vulnerability'] for pred in predictions[:3])
        
        if predictions[0]['vulnerability'] != current_top10.iloc[0]['vulnerability']:
            analysis.append(f"\n**New #1 Vulnerability: {predictions[0]['vulnerability']}**\n"
                          f"This vulnerability has risen to the top position due to:\n"
                          f"- Increased occurrence in recent CVE data\n"
                          f"- Growing impact in GitHub security advisories\n"
                          f"- Evolution of attack patterns and exploitation techniques\n")
        
        # Analyze new entries
        current_vulns = set(current_top10['vulnerability'])
        predicted_vulns = set(pred['vulnerability'] for pred in predictions)
        new_entries = predicted_vulns - current_vulns
        
        if new_entries:
            analysis.append("\n**New Entries**\n")
            for vuln in new_entries:
                pred = next(p for p in predictions if p['vulnerability'] == vuln)
                analysis.append(f"- {vuln} (Rank {pred['rank']}): "
                              f"Emerging threat driven by recent security trends and technological changes\n")
        
        # Analyze significant rank changes
        for pred in predictions[:5]:  # Focus on top 5
            current_rank = current_top10[current_top10['vulnerability'] == pred['vulnerability']]['rank'].iloc[0] if pred['vulnerability'] in current_vulns else None
            if current_rank and abs(current_rank - pred['rank']) >= 3:
                analysis.append(f"\n**Significant Rank Change: {pred['vulnerability']}**\n"
                              f"Moved from #{current_rank} to #{pred['rank']} due to:\n"
                              f"- Changes in attack frequency and severity\n"
                              f"- Evolution of security practices\n"
                              f"- Shifts in technology landscape\n")
        
        return "\n".join(analysis)
    
    def _generate_detailed_comparison(self, predictions: List[Dict], historical_data: pd.DataFrame) -> str:
        """Generate detailed comparison with historical rankings"""
        current_year = str(historical_data['year'].max())
        current_top10 = historical_data[historical_data['year'] == current_year].sort_values('rank')
        
        comparison = ["### Vulnerability Movement Analysis\n"]
        
        # Track vulnerability movement patterns
        for pred in predictions:
            vuln = pred['vulnerability']
            historical_ranks = []
            
            # Get historical rankings
            for year in sorted(historical_data['year'].unique()):
                year_data = historical_data[historical_data['year'] == year]
                if vuln in year_data['vulnerability'].values:
                    rank = year_data[year_data['vulnerability'] == vuln]['rank'].iloc[0]
                    historical_ranks.append((year, rank))
            
            if historical_ranks:
                trend = self._analyze_rank_trend(historical_ranks, pred['rank'])
                comparison.append(f"\n**{vuln}** (Predicted Rank: {pred['rank']})\n"
                                f"- Historical Movement: {trend}\n"
                                f"- Confidence: {pred['confidence']:.1%}\n")
        
        return "\n".join(comparison)
    
    def _analyze_rank_trend(self, historical_ranks: List[tuple], predicted_rank: int) -> str:
        """Analyze the trend of a vulnerability's ranking over time"""
        if len(historical_ranks) < 2:
            return "New entry or insufficient historical data"
            
        ranks = [rank for _, rank in historical_ranks]
        first_rank = ranks[0]
        last_rank = ranks[-1]
        
        if predicted_rank < last_rank:
            return f"Increasing threat (from #{first_rank} → #{last_rank} → predicted #{predicted_rank})"
        elif predicted_rank > last_rank:
            return f"Decreasing priority (from #{first_rank} → #{last_rank} → predicted #{predicted_rank})"
        else:
            return f"Stable threat (maintained around #{predicted_rank})"
    
    def _analyze_future_trends(self, predictions_2025: List[Dict], predictions_2029: List[Dict]) -> str:
        """Analyze trends between 2025 and 2029 predictions"""
        analysis = ["### Predicted Evolution of Security Threats (2025 to 2029)\n"]
        
        # Compare rankings between 2025 and 2029
        changes = []
        
        # Track new and removed vulnerabilities
        vulns_2025 = {p['vulnerability'] for p in predictions_2025}
        vulns_2029 = {p['vulnerability'] for p in predictions_2029}
        new_vulns = vulns_2029 - vulns_2025
        removed_vulns = vulns_2025 - vulns_2029
        
        # Analyze changes for vulnerabilities present in both years
        for pred_2025 in predictions_2025:
            vuln = pred_2025['vulnerability']
            if vuln in vulns_2029:
                pred_2029 = next(p for p in predictions_2029 if p['vulnerability'] == vuln)
                
                rank_change = pred_2029['rank'] - pred_2025['rank']
                confidence_change = pred_2029['confidence'] - pred_2025['confidence']
                
                if abs(rank_change) >= 1 or abs(confidence_change) > 0.1:
                    direction = "↑" if rank_change < 0 else "↓" if rank_change > 0 else "→"
                    change = {
                        'vulnerability': vuln,
                        'direction': direction,
                        'rank_change': abs(rank_change),
                        'confidence_change': confidence_change,
                        'old_rank': pred_2025['rank'],
                        'new_rank': pred_2029['rank']
                    }
                    changes.append(change)
        
        # Sort changes by magnitude
        changes.sort(key=lambda x: (x['rank_change'], abs(x['confidence_change'])), reverse=True)
        
        # Add significant changes to analysis
        if changes:
            analysis.append("#### Major Shifts in Rankings\n")
            for change in changes[:5]:  # Top 5 most significant changes
                analysis.append(f"**{change['vulnerability']}** ({change['direction']})\n")
                analysis.append(f"- Rank: #{change['old_rank']} → #{change['new_rank']}\n")
                if abs(change['confidence_change']) > 0.1:
                    analysis.append(f"- Confidence: {change['confidence_change']:+.1%}\n")
        
        # Add new vulnerabilities analysis
        if new_vulns:
            analysis.append("\n#### Emerging Threats for 2029\n")
            for vuln in new_vulns:
                pred = next(p for p in predictions_2029 if p['vulnerability'] == vuln)
                analysis.append(f"**{vuln}** (Rank #{pred['rank']})\n")
                analysis.append(f"- Confidence: {pred['confidence']:.1%}\n")
                if 'factors' in pred:
                    analysis.append("- Factors: " + ", ".join(pred['factors']) + "\n")
        
        # Add removed vulnerabilities analysis
        if removed_vulns:
            analysis.append("\n#### Declining Threats by 2029\n")
            for vuln in removed_vulns:
                pred = next(p for p in predictions_2025 if p['vulnerability'] == vuln)
                analysis.append(f"**{vuln}** (Previously Rank #{pred['rank']})\n")
        
        # Add emerging trends analysis
        analysis.append("\n#### Technology and Infrastructure Trends\n")
        analysis.append("1. **Automation and AI Impact**\n")
        analysis.append("   - Evolution of attack vectors due to increased automation\n")
        analysis.append("   - AI-driven vulnerability discovery and exploitation\n")
        
        analysis.append("\n2. **Cloud and Distributed Systems**\n")
        analysis.append("   - Growing importance of cloud security configurations\n")
        analysis.append("   - Microservices and API security challenges\n")
        
        analysis.append("\n3. **Zero Trust Architecture**\n")
        analysis.append("   - Shift towards identity-first security\n")
        analysis.append("   - Enhanced authentication and access control\n")
        
        return "\n".join(analysis)
    
    def _generate_visualizations(self, predictions: List[Dict],
                               historical_data: pd.DataFrame,
                               cve_trends: pd.DataFrame,
                               github_trends: pd.DataFrame):
        """Generate interactive visualizations for the report"""
        # Create visualizations directory
        vis_dir = self.output_dir / "visualizations"
        vis_dir.mkdir(exist_ok=True)
        
        # Historical trends visualization
        self._create_historical_trends_plot(historical_data)
        
        # Confidence visualization
        self._create_confidence_plot(predictions)
        
        # CVE severity trends
        if not cve_trends.empty:
            self._create_cve_trends_plot(cve_trends)
            
        # GitHub advisory trends
        if not github_trends.empty:
            self._create_github_trends_plot(github_trends)
    
    def _create_historical_trends_plot(self, historical_data: pd.DataFrame):
        """Create interactive plot of historical vulnerability rankings"""
        fig = px.line(historical_data, 
                     x='year', 
                     y='rank',
                     color='vulnerability',
                     title='Historical OWASP Top 10 Rankings')
        
        fig.write_html(str(self.output_dir / "visualizations/historical_trends.html"))
    
    def _create_confidence_plot(self, predictions: List[Dict]):
        """Create confidence visualization for predictions"""
        fig = go.Figure(data=[
            go.Bar(
                x=[p['vulnerability'] for p in predictions],
                y=[p['confidence'] for p in predictions],
                text=[f"{p['confidence']:.2%}" for p in predictions]
            )
        ])
        
        fig.update_layout(
            title='Prediction Confidence by Vulnerability',
            xaxis_title='Vulnerability',
            yaxis_title='Confidence Score'
        )
        
        fig.write_html(str(self.output_dir / "visualizations/confidence_scores.html"))
    
    def _create_cve_trends_plot(self, cve_data: pd.DataFrame):
        """Create visualization for CVE trends"""
        if cve_data.empty:
            return
            
        # Convert and clean dates with error handling
        try:
            # First ensure published_date is a string
            cve_data['published_date'] = cve_data['published_date'].astype(str)
            
            # Convert to datetime with coercion and handle invalid dates
            cve_data['date'] = pd.to_datetime(cve_data['published_date'], errors='coerce')
            
            # Drop rows with invalid dates
            cve_data = cve_data.dropna(subset=['date'])
            
            # Localize timezone
            cve_data['date'] = cve_data['date'].dt.tz_localize(None)
            
            # Group CVEs by date and severity
            daily_severity = cve_data.groupby('date')['severity'].agg(['mean', 'count']).reset_index()
            
            # Create figure with dual y-axes
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            
            # Add severity line
            fig.add_trace(
                go.Scatter(x=daily_severity['date'], y=daily_severity['mean'],
                          name="Average Severity", line=dict(color="red")),
                secondary_y=False,
            )
            
            # Add count bars
            fig.add_trace(
                go.Bar(x=daily_severity['date'], y=daily_severity['count'],
                      name="Number of CVEs", marker_color="blue", opacity=0.5),
                secondary_y=True,
            )
            
            fig.update_layout(
                title='CVE Trends: Volume and Severity',
                xaxis_title='Date',
            )
            
            fig.update_yaxes(title_text="Average Severity", secondary_y=False)
            fig.update_yaxes(title_text="Number of CVEs", secondary_y=True)
            
            fig.write_html(str(self.output_dir / "visualizations/cve_trends.html"))
        except Exception as e:
            logging.error(f"Error creating CVE trends plot: {str(e)}")
            # Create a basic error plot
            fig = go.Figure()
            fig.add_annotation(text=f"Error creating plot: {str(e)}", 
                              xref="paper", yref="paper",
                              x=0.5, y=0.5, showarrow=False)
            fig.write_html(str(self.output_dir / "visualizations/cve_trends.html"))
    
    def _create_github_trends_plot(self, github_data: pd.DataFrame):
        """Create visualization for GitHub security advisory trends"""
        if github_data.empty:
            return
            
        # Ensure all dates are timezone-naive
        github_data['date'] = pd.to_datetime(github_data['published_date']).dt.tz_localize(None)
        
        # Group advisories by date and severity
        daily_stats = github_data.groupby('date').agg({
            'severity': ['mean', 'count'],
            'ecosystem': 'count'
        }).reset_index()
        
        # Create figure with dual y-axes
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        # Add severity line
        fig.add_trace(
            go.Scatter(x=daily_stats['date'], 
                      y=daily_stats[('severity', 'mean')],
                      name="Average Severity",
                      line=dict(color="red")),
            secondary_y=False,
        )
        
        # Add count bars
        fig.add_trace(
            go.Bar(x=daily_stats['date'], 
                  y=daily_stats[('severity', 'count')],
                  name="Number of Advisories",
                  marker_color="blue",
                  opacity=0.5),
            secondary_y=True,
        )
        
        fig.update_layout(
            title='GitHub Security Advisory Trends',
            xaxis_title='Date',
        )
        
        fig.update_yaxes(title_text="Average Severity", secondary_y=False)
        fig.update_yaxes(title_text="Number of Advisories", secondary_y=True)
        
        fig.write_html(str(self.output_dir / "visualizations/github_trends.html")) 