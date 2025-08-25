import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from datetime import datetime, timedelta
import logging
from collections import defaultdict, Counter
import joblib
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

class AdvancedAnomalyDetector:
    def __init__(self):
        # Multiple anomaly detection models
        self.isolation_forest = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=200,
            max_samples='auto'
        )
        
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.1
        )
        
        self.dbscan = DBSCAN(
            eps=0.5,
            min_samples=5
        )
        
        # Scalers for different feature types
        self.standard_scaler = StandardScaler()
        self.minmax_scaler = MinMaxScaler()
        
        # PCA for dimensionality reduction
        self.pca = PCA(n_components=0.95)  # Keep 95% of variance
        
        # Model state
        self.models_trained = False
        self.feature_importance = {}
        
        # Anomaly thresholds
        self.anomaly_threshold = -0.1  # Isolation Forest threshold
        self.ensemble_threshold = 0.6  # Ensemble voting threshold
        
        # Pattern tracking
        self.behavioral_patterns = defaultdict(list)
        self.baseline_metrics = {}
        
    def extract_comprehensive_features(self, user_activities):
        """Extract comprehensive features for anomaly detection"""
        features_list = []
        
        for activity in user_activities:
            try:
                user_id = activity.get('user_id')
                timestamp = activity.get('timestamp', datetime.now())
                
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                # Temporal features
                hour = timestamp.hour
                day_of_week = timestamp.weekday()
                day_of_month = timestamp.day
                month = timestamp.month
                is_weekend = 1 if day_of_week >= 5 else 0
                is_business_hours = 1 if 9 <= hour <= 17 else 0
                
                # User behavior features
                recent_activities = self._get_user_recent_activities(user_id, days=30)
                
                # Login frequency patterns
                login_freq_1h = self._count_activities_in_window(recent_activities, hours=1)
                login_freq_6h = self._count_activities_in_window(recent_activities, hours=6)
                login_freq_24h = self._count_activities_in_window(recent_activities, hours=24)
                login_freq_7d = self._count_activities_in_window(recent_activities, days=7)
                
                # Geographic features
                current_country = activity.get('country', 'Unknown')
                current_city = activity.get('city', 'Unknown')
                
                unique_countries_7d = len(set([a.get('country', 'Unknown') for a in recent_activities]))
                unique_cities_7d = len(set([a.get('city', 'Unknown') for a in recent_activities]))
                
                # Calculate geographic velocity (impossible travel detection)
                geo_velocity = self._calculate_geographic_velocity(recent_activities)
                
                # Device and session features
                user_agent = activity.get('device_info', {}).get('user_agent', '')
                device_fingerprint = hash(user_agent) % 10000  # Simple device fingerprinting
                
                unique_devices_7d = len(set([
                    hash(a.get('device_info', {}).get('user_agent', '')) % 10000 
                    for a in recent_activities
                ]))
                
                # Session duration patterns
                avg_session_duration = np.mean([
                    a.get('session_duration', 30) for a in recent_activities
                ]) if recent_activities else 30
                
                session_duration_variance = np.var([
                    a.get('session_duration', 30) for a in recent_activities
                ]) if len(recent_activities) > 1 else 0
                
                # Failed attempt patterns
                failed_attempts_1h = len([
                    a for a in recent_activities 
                    if a.get('status') == 'failed' and 
                    (timestamp - a.get('timestamp', timestamp)).total_seconds() < 3600
                ])
                
                failed_attempts_24h = len([
                    a for a in recent_activities 
                    if a.get('status') == 'failed' and 
                    (timestamp - a.get('timestamp', timestamp)).days < 1
                ])
                
                # Time-based patterns
                time_since_last_login = self._get_time_since_last_activity(user_id, timestamp)
                avg_time_between_logins = self._calculate_avg_time_between_activities(recent_activities)
                
                # Risk escalation features
                previous_risk_scores = [a.get('risk_score', 0) for a in recent_activities[-10:]]
                avg_previous_risk = np.mean(previous_risk_scores) if previous_risk_scores else 0
                risk_trend = self._calculate_risk_trend(previous_risk_scores)
                
                # Network features
                ip_address = activity.get('ip_address', '')
                ip_reputation_score = self._get_ip_reputation_score(ip_address)
                
                # Behavioral consistency features
                consistency_score = self._calculate_behavioral_consistency(user_id, activity)
                
                feature_vector = [
                    # Temporal features
                    hour, day_of_week, day_of_month, month, is_weekend, is_business_hours,
                    
                    # Frequency features
                    login_freq_1h, login_freq_6h, login_freq_24h, login_freq_7d,
                    
                    # Geographic features
                    unique_countries_7d, unique_cities_7d, geo_velocity,
                    
                    # Device features
                    device_fingerprint, unique_devices_7d,
                    
                    # Session features
                    avg_session_duration, session_duration_variance,
                    
                    # Security features
                    failed_attempts_1h, failed_attempts_24h,
                    
                    # Temporal patterns
                    time_since_last_login, avg_time_between_logins,
                    
                    # Risk features
                    avg_previous_risk, risk_trend,
                    
                    # Network features
                    ip_reputation_score,
                    
                    # Behavioral features
                    consistency_score
                ]
                
                features_list.append({
                    'user_id': user_id,
                    'activity_id': activity.get('_id'),
                    'features': feature_vector,
                    'timestamp': timestamp,
                    'is_suspicious': activity.get('is_suspicious', False),
                    'feature_names': [
                        'hour', 'day_of_week', 'day_of_month', 'month', 'is_weekend', 'is_business_hours',
                        'login_freq_1h', 'login_freq_6h', 'login_freq_24h', 'login_freq_7d',
                        'unique_countries_7d', 'unique_cities_7d', 'geo_velocity',
                        'device_fingerprint', 'unique_devices_7d',
                        'avg_session_duration', 'session_duration_variance',
                        'failed_attempts_1h', 'failed_attempts_24h',
                        'time_since_last_login', 'avg_time_between_logins',
                        'avg_previous_risk', 'risk_trend',
                        'ip_reputation_score', 'consistency_score'
                    ]
                })
                
            except Exception as e:
                logging.error(f"Error extracting comprehensive features: {e}")
                continue
        
        return features_list
    
    def _get_user_recent_activities(self, user_id, days=30):
        """Get recent activities for a user"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            cutoff_date = datetime.now() - timedelta(days=days)
            recent = list(activities.find({
                'user_id': user_id,
                'timestamp': {'$gte': cutoff_date}
            }).sort('timestamp', -1))
            
            return recent
        except Exception as e:
            logging.error(f"Error getting recent activities: {e}")
            return []
    
    def _count_activities_in_window(self, activities, hours=None, days=None):
        """Count activities within a time window"""
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
        elif days:
            cutoff = datetime.now() - timedelta(days=days)
        else:
            return 0
        
        count = 0
        for activity in activities:
            activity_time = activity.get('timestamp', datetime.now())
            if isinstance(activity_time, str):
                activity_time = datetime.fromisoformat(activity_time.replace('Z', '+00:00'))
            if activity_time >= cutoff:
                count += 1
        
        return count
    
    def _calculate_geographic_velocity(self, activities):
        """Calculate impossible travel velocity"""
        if len(activities) < 2:
            return 0
        
        max_velocity = 0
        for i in range(len(activities) - 1):
            try:
                act1 = activities[i]
                act2 = activities[i + 1]
                
                # Get coordinates
                lat1, lon1 = act1.get('latitude', 0), act1.get('longitude', 0)
                lat2, lon2 = act2.get('latitude', 0), act2.get('longitude', 0)
                
                if lat1 == 0 or lon1 == 0 or lat2 == 0 or lon2 == 0:
                    continue
                
                # Calculate distance (simplified)
                distance = ((lat2 - lat1) ** 2 + (lon2 - lon1) ** 2) ** 0.5 * 111  # Rough km conversion
                
                # Calculate time difference
                time1 = act1.get('timestamp', datetime.now())
                time2 = act2.get('timestamp', datetime.now())
                
                if isinstance(time1, str):
                    time1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
                if isinstance(time2, str):
                    time2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
                
                time_diff_hours = abs((time2 - time1).total_seconds()) / 3600
                
                if time_diff_hours > 0:
                    velocity = distance / time_diff_hours
                    max_velocity = max(max_velocity, velocity)
                    
            except Exception as e:
                logging.error(f"Error calculating velocity: {e}")
                continue
        
        return min(max_velocity, 1000)  # Cap at 1000 km/h
    
    def _get_time_since_last_activity(self, user_id, current_time):
        """Get hours since last activity"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            last_activity = activities.find_one({
                'user_id': user_id,
                'timestamp': {'$lt': current_time}
            }, sort=[('timestamp', -1)])
            
            if last_activity:
                last_time = last_activity.get('timestamp', current_time)
                if isinstance(last_time, str):
                    last_time = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                return (current_time - last_time).total_seconds() / 3600
            return 168  # Default to 1 week
        except Exception as e:
            logging.error(f"Error getting last activity time: {e}")
            return 168
    
    def _calculate_avg_time_between_activities(self, activities):
        """Calculate average time between activities"""
        if len(activities) < 2:
            return 24  # Default 24 hours
        
        time_diffs = []
        for i in range(len(activities) - 1):
            try:
                time1 = activities[i].get('timestamp', datetime.now())
                time2 = activities[i + 1].get('timestamp', datetime.now())
                
                if isinstance(time1, str):
                    time1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
                if isinstance(time2, str):
                    time2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
                
                diff_hours = abs((time1 - time2).total_seconds()) / 3600
                time_diffs.append(diff_hours)
            except Exception as e:
                continue
        
        return np.mean(time_diffs) if time_diffs else 24
    
    def _calculate_risk_trend(self, risk_scores):
        """Calculate trend in risk scores"""
        if len(risk_scores) < 2:
            return 0
        
        # Simple linear trend calculation
        x = np.arange(len(risk_scores))
        y = np.array(risk_scores)
        
        if len(x) > 1:
            slope = np.polyfit(x, y, 1)[0]
            return slope
        return 0
    
    def _get_ip_reputation_score(self, ip_address):
        """Get IP reputation score (simplified)"""
        # In a real implementation, this would query threat intelligence APIs
        # For now, return a simple score based on IP characteristics
        
        if not ip_address or ip_address in ['127.0.0.1', 'localhost']:
            return 0  # Local/safe
        
        # Simple heuristic based on IP patterns
        ip_parts = ip_address.split('.')
        if len(ip_parts) == 4:
            try:
                # Check for common suspicious patterns
                first_octet = int(ip_parts[0])
                
                # Known safe ranges
                if first_octet in [10, 172, 192]:  # Private ranges
                    return 0
                elif first_octet in [1, 8, 4]:  # Common public DNS/CDN
                    return 10
                else:
                    return 30  # Unknown public IP
            except ValueError:
                return 50  # Invalid IP format
        
        return 50  # Unknown format
    
    def _calculate_behavioral_consistency(self, user_id, current_activity):
        """Calculate how consistent current activity is with user's behavior"""
        try:
            # Get user's historical patterns
            if user_id not in self.behavioral_patterns:
                self._build_user_behavioral_profile(user_id)
            
            user_profile = self.behavioral_patterns.get(user_id, {})
            
            consistency_score = 100  # Start with perfect consistency
            
            # Check time patterns
            current_hour = current_activity.get('timestamp', datetime.now()).hour
            typical_hours = user_profile.get('typical_hours', [])
            
            if typical_hours and current_hour not in typical_hours:
                consistency_score -= 20
            
            # Check location patterns
            current_country = current_activity.get('country', 'Unknown')
            typical_countries = user_profile.get('typical_countries', [])
            
            if typical_countries and current_country not in typical_countries:
                consistency_score -= 30
            
            # Check device patterns
            current_device = hash(current_activity.get('device_info', {}).get('user_agent', '')) % 10000
            typical_devices = user_profile.get('typical_devices', [])
            
            if typical_devices and current_device not in typical_devices:
                consistency_score -= 25
            
            return max(0, consistency_score)
            
        except Exception as e:
            logging.error(f"Error calculating behavioral consistency: {e}")
            return 50  # Neutral score
    
    def _build_user_behavioral_profile(self, user_id):
        """Build behavioral profile for a user"""
        try:
            recent_activities = self._get_user_recent_activities(user_id, days=90)
            
            if not recent_activities:
                return
            
            # Extract typical patterns
            hours = [a.get('timestamp', datetime.now()).hour for a in recent_activities]
            countries = [a.get('country', 'Unknown') for a in recent_activities]
            devices = [hash(a.get('device_info', {}).get('user_agent', '')) % 10000 for a in recent_activities]
            
            # Find most common patterns
            hour_counter = Counter(hours)
            country_counter = Counter(countries)
            device_counter = Counter(devices)
            
            self.behavioral_patterns[user_id] = {
                'typical_hours': [h for h, count in hour_counter.most_common(8)],  # Top 8 hours
                'typical_countries': [c for c, count in country_counter.most_common(3)],  # Top 3 countries
                'typical_devices': [d for d, count in device_counter.most_common(5)],  # Top 5 devices
                'profile_built_at': datetime.now()
            }
            
        except Exception as e:
            logging.error(f"Error building behavioral profile: {e}")
    
    def train_ensemble_models(self, training_data=None):
        """Train ensemble of anomaly detection models"""
        try:
            if training_data is None:
                training_data = self._collect_comprehensive_training_data()
            
            if len(training_data) < 50:
                logging.warning("Insufficient training data. Generating synthetic data.")
                training_data.extend(self._generate_comprehensive_synthetic_data())
            
            # Prepare feature matrix
            X = np.array([item['features'] for item in training_data])
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0, posinf=999, neginf=-999)
            
            # Scale features
            X_standard = self.standard_scaler.fit_transform(X)
            X_minmax = self.minmax_scaler.fit_transform(X)
            
            # Apply PCA for dimensionality reduction
            X_pca = self.pca.fit_transform(X_standard)
            
            # Train multiple models
            logging.info("Training Isolation Forest...")
            self.isolation_forest.fit(X_standard)
            
            logging.info("Training One-Class SVM...")
            self.one_class_svm.fit(X_minmax)
            
            logging.info("Training DBSCAN clustering...")
            cluster_labels = self.dbscan.fit_predict(X_pca)
            
            # Calculate feature importance (simplified)
            self._calculate_feature_importance(training_data)
            
            # Establish baseline metrics
            self._establish_baseline_metrics(training_data)
            
            self.models_trained = True
            self._save_anomaly_models()
            
            logging.info("Ensemble anomaly detection models trained successfully")
            
            return {
                'models_trained': True,
                'training_samples': len(training_data),
                'feature_dimensions': X.shape[1],
                'pca_components': X_pca.shape[1],
                'cluster_count': len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
            }
            
        except Exception as e:
            logging.error(f"Error training ensemble models: {e}")
            return {'models_trained': False, 'error': str(e)}
    
    def detect_anomalies(self, activity):
        """Detect anomalies using ensemble approach"""
        try:
            if not self.models_trained:
                self.train_ensemble_models()
            
            # Extract features
            features_data = self.extract_comprehensive_features([activity])
            if not features_data:
                return self._default_anomaly_result()
            
            X = np.array([features_data[0]['features']])
            X = np.nan_to_num(X, nan=0.0, posinf=999, neginf=-999)
            
            # Scale features
            X_standard = self.standard_scaler.transform(X)
            X_minmax = self.minmax_scaler.transform(X)
            X_pca = self.pca.transform(X_standard)
            
            # Get predictions from all models
            predictions = {}
            
            # Isolation Forest
            iso_score = self.isolation_forest.decision_function(X_standard)[0]
            iso_anomaly = self.isolation_forest.predict(X_standard)[0] == -1
            predictions['isolation_forest'] = {
                'score': float(iso_score),
                'is_anomaly': bool(iso_anomaly),
                'confidence': abs(float(iso_score))
            }
            
            # One-Class SVM
            svm_score = self.one_class_svm.decision_function(X_minmax)[0]
            svm_anomaly = self.one_class_svm.predict(X_minmax)[0] == -1
            predictions['one_class_svm'] = {
                'score': float(svm_score),
                'is_anomaly': bool(svm_anomaly),
                'confidence': abs(float(svm_score))
            }
            
            # DBSCAN clustering (check if point would be outlier)
            cluster_distances = []
            for label in set(self.dbscan.labels_):
                if label != -1:  # Not noise
                    cluster_center = np.mean(X_pca[self.dbscan.labels_ == label], axis=0)
                    distance = np.linalg.norm(X_pca[0] - cluster_center)
                    cluster_distances.append(distance)
            
            if cluster_distances:
                min_cluster_distance = min(cluster_distances)
                cluster_anomaly = min_cluster_distance > np.percentile(cluster_distances, 90)
            else:
                min_cluster_distance = 1.0
                cluster_anomaly = True
            
            predictions['clustering'] = {
                'score': float(min_cluster_distance),
                'is_anomaly': bool(cluster_anomaly),
                'confidence': float(min_cluster_distance)
            }
            
            # Ensemble decision
            anomaly_votes = sum([pred['is_anomaly'] for pred in predictions.values()])
            ensemble_anomaly = anomaly_votes >= 2  # Majority vote
            
            # Calculate ensemble confidence
            confidences = [pred['confidence'] for pred in predictions.values()]
            ensemble_confidence = np.mean(confidences)
            
            # Calculate composite anomaly score
            composite_score = (
                predictions['isolation_forest']['confidence'] * 0.4 +
                predictions['one_class_svm']['confidence'] * 0.4 +
                predictions['clustering']['confidence'] * 0.2
            )
            
            # Generate detailed analysis
            analysis = self._generate_anomaly_analysis(features_data[0], predictions)
            
            return {
                'is_anomaly': ensemble_anomaly,
                'anomaly_score': float(composite_score),
                'confidence': float(ensemble_confidence),
                'ensemble_votes': anomaly_votes,
                'model_predictions': predictions,
                'analysis': analysis,
                'feature_contributions': self._calculate_feature_contributions(features_data[0])
            }
            
        except Exception as e:
            logging.error(f"Error detecting anomalies: {e}")
            return self._default_anomaly_result()
    
    def _default_anomaly_result(self):
        """Return default anomaly detection result"""
        return {
            'is_anomaly': False,
            'anomaly_score': 0.0,
            'confidence': 0.0,
            'ensemble_votes': 0,
            'model_predictions': {},
            'analysis': {'insights': ['Unable to analyze activity']},
            'feature_contributions': {}
        }
    
    def _generate_anomaly_analysis(self, feature_data, predictions):
        """Generate human-readable anomaly analysis"""
        analysis = {
            'insights': [],
            'risk_factors': [],
            'model_agreement': len([p for p in predictions.values() if p['is_anomaly']]),
            'strongest_signal': max(predictions.keys(), key=lambda k: predictions[k]['confidence'])
        }
        
        features = feature_data['features']
        feature_names = feature_data['feature_names']
        
        # Analyze specific risk factors
        for i, (feature_name, value) in enumerate(zip(feature_names, features)):
            if feature_name == 'login_freq_1h' and value > 5:
                analysis['risk_factors'].append(f"High login frequency: {value} logins in 1 hour")
            elif feature_name == 'unique_countries_7d' and value > 3:
                analysis['risk_factors'].append(f"Multiple countries accessed: {value} countries in 7 days")
            elif feature_name == 'geo_velocity' and value > 500:
                analysis['risk_factors'].append(f"Impossible travel detected: {value:.0f} km/h")
            elif feature_name == 'failed_attempts_1h' and value > 3:
                analysis['risk_factors'].append(f"Multiple failed attempts: {value} in 1 hour")
            elif feature_name == 'consistency_score' and value < 50:
                analysis['risk_factors'].append(f"Unusual behavior pattern detected")
        
        # Generate insights based on model agreement
        if analysis['model_agreement'] == 3:
            analysis['insights'].append("All anomaly detection models agree - high confidence anomaly")
        elif analysis['model_agreement'] == 2:
            analysis['insights'].append("Majority of models detect anomaly - moderate confidence")
        elif analysis['model_agreement'] == 1:
            analysis['insights'].append("Single model detects anomaly - low confidence")
        else:
            analysis['insights'].append("No anomalies detected by ensemble models")
        
        return analysis
    
    def _calculate_feature_contributions(self, feature_data):
        """Calculate feature contributions to anomaly score"""
        contributions = {}
        
        if not hasattr(self, 'feature_importance') or not self.feature_importance:
            return contributions
        
        features = feature_data['features']
        feature_names = feature_data['feature_names']
        
        for i, (name, value) in enumerate(zip(feature_names, features)):
            importance = self.feature_importance.get(name, 0)
            contribution = abs(value) * importance
            contributions[name] = float(contribution)
        
        return contributions
    
    def _calculate_feature_importance(self, training_data):
        """Calculate feature importance (simplified approach)"""
        try:
            # This is a simplified feature importance calculation
            # In practice, you might use more sophisticated methods
            
            feature_names = training_data[0]['feature_names']
            X = np.array([item['features'] for item in training_data])
            y = np.array([1 if item['is_suspicious'] else 0 for item in training_data])
            
            # Calculate correlation with suspicious activity
            correlations = []
            for i in range(X.shape[1]):
                corr = np.corrcoef(X[:, i], y)[0, 1]
                correlations.append(abs(corr) if not np.isnan(corr) else 0)
            
            # Normalize to sum to 1
            total_importance = sum(correlations)
            if total_importance > 0:
                normalized_importance = [c / total_importance for c in correlations]
            else:
                normalized_importance = [1 / len(correlations)] * len(correlations)
            
            self.feature_importance = dict(zip(feature_names, normalized_importance))
            
        except Exception as e:
            logging.error(f"Error calculating feature importance: {e}")
            self.feature_importance = {}
    
    def _establish_baseline_metrics(self, training_data):
        """Establish baseline metrics for comparison"""
        try:
            X = np.array([item['features'] for item in training_data])
            feature_names = training_data[0]['feature_names']
            
            self.baseline_metrics = {}
            for i, name in enumerate(feature_names):
                self.baseline_metrics[name] = {
                    'mean': float(np.mean(X[:, i])),
                    'std': float(np.std(X[:, i])),
                    'min': float(np.min(X[:, i])),
                    'max': float(np.max(X[:, i])),
                    'percentile_95': float(np.percentile(X[:, i], 95))
                }
                
        except Exception as e:
            logging.error(f"Error establishing baseline metrics: {e}")
            self.baseline_metrics = {}
    
    def _collect_comprehensive_training_data(self):
        """Collect comprehensive training data"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            # Get recent activities for training
            cutoff_date = datetime.now() - timedelta(days=60)
            recent_activities = list(activities.find({
                'timestamp': {'$gte': cutoff_date}
            }).limit(2000))
            
            return self.extract_comprehensive_features(recent_activities)
        except Exception as e:
            logging.error(f"Error collecting comprehensive training data: {e}")
            return []
    
    def _generate_comprehensive_synthetic_data(self):
        """Generate comprehensive synthetic training data"""
        synthetic_data = []
        np.random.seed(42)
        
        feature_names = [
            'hour', 'day_of_week', 'day_of_month', 'month', 'is_weekend', 'is_business_hours',
            'login_freq_1h', 'login_freq_6h', 'login_freq_24h', 'login_freq_7d',
            'unique_countries_7d', 'unique_cities_7d', 'geo_velocity',
            'device_fingerprint', 'unique_devices_7d',
            'avg_session_duration', 'session_duration_variance',
            'failed_attempts_1h', 'failed_attempts_24h',
            'time_since_last_login', 'avg_time_between_logins',
            'avg_previous_risk', 'risk_trend',
            'ip_reputation_score', 'consistency_score'
        ]
        
        for i in range(500):
            # 80% normal, 20% anomalous
            is_anomalous = i >= 400
            
            if not is_anomalous:
                # Normal behavior
                features = [
                    np.random.randint(8, 18),  # Normal hours
                    np.random.randint(0, 7),   # Any day
                    np.random.randint(1, 31),  # Any day of month
                    np.random.randint(1, 13),  # Any month
                    np.random.choice([0, 1], p=[0.7, 0.3]),  # Mostly weekdays
                    np.random.choice([0, 1], p=[0.3, 0.7]),  # Mostly business hours
                    np.random.randint(0, 2),   # Low frequency
                    np.random.randint(0, 3),   # Low frequency
                    np.random.randint(1, 5),   # Normal daily frequency
                    np.random.randint(5, 20),  # Normal weekly frequency
                    np.random.randint(1, 3),   # Few countries
                    np.random.randint(1, 5),   # Few cities
                    np.random.uniform(0, 50),  # Normal travel speed
                    np.random.randint(1000, 9999),  # Device fingerprint
                    np.random.randint(1, 3),   # Few devices
                    np.random.normal(45, 15),  # Normal session duration
                    np.random.uniform(0, 100), # Session variance
                    np.random.randint(0, 1),   # Few failed attempts
                    np.random.randint(0, 2),   # Few failed attempts
                    np.random.exponential(12), # Time since last login
                    np.random.normal(24, 12),  # Average time between logins
                    np.random.uniform(0, 30),  # Low previous risk
                    np.random.uniform(-5, 5),  # Neutral risk trend
                    np.random.uniform(0, 20),  # Low IP reputation risk
                    np.random.uniform(70, 100) # High consistency
                ]
            else:
                # Anomalous behavior
                features = [
                    np.random.choice([2, 3, 23, 24]),  # Unusual hours
                    np.random.randint(0, 7),
                    np.random.randint(1, 31),
                    np.random.randint(1, 13),
                    np.random.choice([0, 1]),
                    np.random.choice([0, 1], p=[0.8, 0.2]),  # Mostly non-business hours
                    np.random.randint(5, 15),  # High frequency
                    np.random.randint(10, 25), # High frequency
                    np.random.randint(15, 30), # High daily frequency
                    np.random.randint(50, 100), # High weekly frequency
                    np.random.randint(5, 15),  # Many countries
                    np.random.randint(10, 25), # Many cities
                    np.random.uniform(500, 2000), # Impossible travel
                    np.random.randint(1000, 9999),
                    np.random.randint(5, 15),  # Many devices
                    np.random.normal(15, 5),   # Short sessions
                    np.random.uniform(200, 500), # High variance
                    np.random.randint(3, 10),  # Many failed attempts
                    np.random.randint(5, 20),  # Many failed attempts
                    np.random.exponential(2),  # Very recent login
                    np.random.normal(2, 1),    # Rapid logins
                    np.random.uniform(50, 100), # High previous risk
                    np.random.uniform(10, 30), # Increasing risk trend
                    np.random.uniform(50, 100), # High IP risk
                    np.random.uniform(0, 40)   # Low consistency
                ]
            
            synthetic_data.append({
                'user_id': f'synthetic_user_{i}',
                'features': features,
                'feature_names': feature_names,
                'is_suspicious': is_anomalous,
                'timestamp': datetime.now()
            })
        
        return synthetic_data
    
    def _save_anomaly_models(self):
        """Save trained anomaly detection models"""
        try:
            models_dir = 'models'
            os.makedirs(models_dir, exist_ok=True)
            
            joblib.dump(self.isolation_forest, f'{models_dir}/isolation_forest_advanced.pkl')
            joblib.dump(self.one_class_svm, f'{models_dir}/one_class_svm.pkl')
            joblib.dump(self.standard_scaler, f'{models_dir}/standard_scaler_advanced.pkl')
            joblib.dump(self.minmax_scaler, f'{models_dir}/minmax_scaler.pkl')
            joblib.dump(self.pca, f'{models_dir}/pca_advanced.pkl')
            joblib.dump(self.feature_importance, f'{models_dir}/feature_importance.pkl')
            joblib.dump(self.baseline_metrics, f'{models_dir}/baseline_metrics.pkl')
            
            logging.info("Advanced anomaly detection models saved successfully")
        except Exception as e:
            logging.error(f"Error saving anomaly models: {e}")
    
    def load_anomaly_models(self):
        """Load trained anomaly detection models"""
        try:
            models_dir = 'models'
            
            if os.path.exists(f'{models_dir}/isolation_forest_advanced.pkl'):
                self.isolation_forest = joblib.load(f'{models_dir}/isolation_forest_advanced.pkl')
                self.one_class_svm = joblib.load(f'{models_dir}/one_class_svm.pkl')
                self.standard_scaler = joblib.load(f'{models_dir}/standard_scaler_advanced.pkl')
                self.minmax_scaler = joblib.load(f'{models_dir}/minmax_scaler.pkl')
                self.pca = joblib.load(f'{models_dir}/pca_advanced.pkl')
                self.feature_importance = joblib.load(f'{models_dir}/feature_importance.pkl')
                self.baseline_metrics = joblib.load(f'{models_dir}/baseline_metrics.pkl')
                self.models_trained = True
                logging.info("Advanced anomaly detection models loaded successfully")
            else:
                logging.info("No saved anomaly models found, will train on first use")
        except Exception as e:
            logging.error(f"Error loading anomaly models: {e}")

# Initialize global advanced anomaly detector
advanced_anomaly_detector = AdvancedAnomalyDetector()
