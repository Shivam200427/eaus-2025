import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve
from datetime import datetime, timedelta
import logging
import joblib
import os
from collections import defaultdict
from pymongo import MongoClient
from dotenv import load_dotenv
from anomaly_detector import advanced_anomaly_detector

load_dotenv()

class MLRiskScorer:
    def __init__(self):
        # Multiple risk scoring models
        self.risk_classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )
        
        self.gradient_booster = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        
        self.logistic_model = LogisticRegression(
            random_state=42,
            class_weight='balanced',
            max_iter=1000
        )
        
        # Scalers
        self.standard_scaler = StandardScaler()
        self.robust_scaler = RobustScaler()
        
        # Model state
        self.models_trained = False
        self.feature_importance = {}
        self.risk_thresholds = {
            'low': 30,
            'medium': 60,
            'high': 80,
            'critical': 95
        }
        
        # Risk categories and weights
        self.risk_categories = {
            'temporal': 0.15,      # Time-based patterns
            'geographic': 0.25,    # Location-based risks
            'behavioral': 0.20,    # User behavior patterns
            'technical': 0.15,     # Device/IP risks
            'frequency': 0.15,     # Login frequency patterns
            'historical': 0.10     # Historical risk patterns
        }
        
        # Dynamic risk adjustment factors
        self.risk_multipliers = {
            'first_time_country': 1.5,
            'impossible_travel': 2.0,
            'multiple_failed_attempts': 1.3,
            'unusual_hours': 1.2,
            'new_device': 1.4,
            'high_frequency': 1.6,
            'suspicious_ip': 1.8,
            'behavioral_anomaly': 1.7
        }
        
    def extract_risk_features(self, user_activity, user_history=None):
        """Extract comprehensive risk features for ML scoring"""
        try:
            user_id = user_activity.get('user_id')
            timestamp = user_activity.get('timestamp', datetime.now())
            
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Get user history if not provided
            if user_history is None:
                user_history = self._get_user_comprehensive_history(user_id)
            
            # Temporal risk features
            temporal_features = self._extract_temporal_risk_features(timestamp, user_history)
            
            # Geographic risk features
            geographic_features = self._extract_geographic_risk_features(user_activity, user_history)
            
            # Behavioral risk features
            behavioral_features = self._extract_behavioral_risk_features(user_activity, user_history)
            
            # Technical risk features
            technical_features = self._extract_technical_risk_features(user_activity, user_history)
            
            # Frequency risk features
            frequency_features = self._extract_frequency_risk_features(user_activity, user_history)
            
            # Historical risk features
            historical_features = self._extract_historical_risk_features(user_history)
            
            # Combine all features
            all_features = {
                **temporal_features,
                **geographic_features,
                **behavioral_features,
                **technical_features,
                **frequency_features,
                **historical_features
            }
            
            # Convert to feature vector
            feature_vector = list(all_features.values())
            feature_names = list(all_features.keys())
            
            return {
                'features': feature_vector,
                'feature_names': feature_names,
                'feature_categories': self._categorize_features(feature_names),
                'raw_features': all_features
            }
            
        except Exception as e:
            logging.error(f"Error extracting risk features: {e}")
            return self._get_default_risk_features()
    
    def _extract_temporal_risk_features(self, timestamp, user_history):
        """Extract time-based risk features"""
        features = {}
        
        # Current time features
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = 1 if day_of_week >= 5 else 0
        is_night = 1 if hour < 6 or hour > 22 else 0
        is_business_hours = 1 if 9 <= hour <= 17 and not is_weekend else 0
        
        # Historical time patterns
        if user_history:
            historical_hours = [h.get('timestamp', timestamp).hour for h in user_history]
            hour_variance = np.var(historical_hours) if len(historical_hours) > 1 else 0
            
            # Check if current hour is unusual for this user
            hour_frequency = historical_hours.count(hour) / len(historical_hours) if historical_hours else 0
            unusual_hour_score = 1 - hour_frequency
        else:
            hour_variance = 0
            unusual_hour_score = 0.5
        
        # Time since last activity
        time_since_last = self._calculate_time_since_last_activity(user_history, timestamp)
        
        features.update({
            'hour_of_day': hour / 24.0,  # Normalized
            'day_of_week': day_of_week / 7.0,
            'is_weekend': is_weekend,
            'is_night_time': is_night,
            'is_business_hours': is_business_hours,
            'hour_variance': min(hour_variance / 144.0, 1.0),  # Normalized
            'unusual_hour_score': unusual_hour_score,
            'time_since_last_hours': min(time_since_last / 168.0, 1.0)  # Normalized to week
        })
        
        return features
    
    def _extract_geographic_risk_features(self, activity, user_history):
        """Extract location-based risk features"""
        features = {}
        
        current_country = activity.get('country', 'Unknown')
        current_city = activity.get('city', 'Unknown')
        current_lat = activity.get('latitude', 0)
        current_lon = activity.get('longitude', 0)
        
        if user_history:
            # Historical locations
            historical_countries = [h.get('country', 'Unknown') for h in user_history]
            historical_cities = [h.get('city', 'Unknown') for h in user_history]
            
            # Country analysis
            unique_countries = len(set(historical_countries))
            country_frequency = historical_countries.count(current_country) / len(historical_countries)
            is_new_country = 1 if current_country not in historical_countries else 0
            
            # City analysis
            unique_cities = len(set(historical_cities))
            city_frequency = historical_cities.count(current_city) / len(historical_cities)
            is_new_city = 1 if current_city not in historical_cities else 0
            
            # Geographic velocity (impossible travel detection)
            geo_velocity = self._calculate_geographic_velocity(user_history, activity)
            
            # Distance from usual locations
            avg_distance = self._calculate_average_distance_from_usual_locations(
                current_lat, current_lon, user_history
            )
            
        else:
            unique_countries = 1
            country_frequency = 0
            is_new_country = 1
            unique_cities = 1
            city_frequency = 0
            is_new_city = 1
            geo_velocity = 0
            avg_distance = 0
        
        features.update({
            'unique_countries_30d': min(unique_countries / 10.0, 1.0),  # Normalized
            'country_frequency': country_frequency,
            'is_new_country': is_new_country,
            'unique_cities_30d': min(unique_cities / 20.0, 1.0),
            'city_frequency': city_frequency,
            'is_new_city': is_new_city,
            'geographic_velocity': min(geo_velocity / 1000.0, 1.0),  # Normalized to 1000 km/h
            'avg_distance_from_usual': min(avg_distance / 10000.0, 1.0)  # Normalized to 10000 km
        })
        
        return features
    
    def _extract_behavioral_risk_features(self, activity, user_history):
        """Extract behavioral pattern risk features"""
        features = {}
        
        user_agent = activity.get('device_info', {}).get('user_agent', '')
        session_duration = activity.get('session_duration', 30)
        
        if user_history:
            # Device patterns
            historical_agents = [h.get('device_info', {}).get('user_agent', '') for h in user_history]
            unique_devices = len(set(historical_agents))
            device_frequency = historical_agents.count(user_agent) / len(historical_agents)
            is_new_device = 1 if user_agent not in historical_agents else 0
            
            # Session duration patterns
            historical_durations = [h.get('session_duration', 30) for h in user_history]
            avg_session_duration = np.mean(historical_durations)
            session_duration_variance = np.var(historical_durations)
            
            # Behavioral consistency score
            consistency_score = self._calculate_behavioral_consistency_score(activity, user_history)
            
            # Activity pattern regularity
            activity_regularity = self._calculate_activity_regularity(user_history)
            
        else:
            unique_devices = 1
            device_frequency = 0
            is_new_device = 1
            avg_session_duration = 30
            session_duration_variance = 0
            consistency_score = 0.5
            activity_regularity = 0.5
        
        # Session duration anomaly
        session_anomaly = abs(session_duration - avg_session_duration) / max(avg_session_duration, 1)
        
        features.update({
            'unique_devices_30d': min(unique_devices / 10.0, 1.0),
            'device_frequency': device_frequency,
            'is_new_device': is_new_device,
            'avg_session_duration': min(avg_session_duration / 180.0, 1.0),  # Normalized to 3 hours
            'session_duration_variance': min(session_duration_variance / 3600.0, 1.0),
            'session_duration_anomaly': min(session_anomaly, 1.0),
            'behavioral_consistency': consistency_score,
            'activity_regularity': activity_regularity
        })
        
        return features
    
    def _extract_technical_risk_features(self, activity, user_history):
        """Extract technical/security risk features"""
        features = {}
        
        ip_address = activity.get('ip_address', '')
        
        # IP reputation and analysis
        ip_reputation_score = self._get_enhanced_ip_reputation(ip_address)
        is_tor_ip = self._check_tor_ip(ip_address)
        is_vpn_ip = self._check_vpn_ip(ip_address)
        
        if user_history:
            # IP address patterns
            historical_ips = [h.get('ip_address', '') for h in user_history]
            unique_ips = len(set(historical_ips))
            ip_frequency = historical_ips.count(ip_address) / len(historical_ips)
            is_new_ip = 1 if ip_address not in historical_ips else 0
            
            # Failed attempt patterns
            recent_failures = self._count_recent_failed_attempts(user_history)
            
        else:
            unique_ips = 1
            ip_frequency = 0
            is_new_ip = 1
            recent_failures = 0
        
        features.update({
            'ip_reputation_score': ip_reputation_score / 100.0,  # Normalized
            'is_tor_ip': is_tor_ip,
            'is_vpn_ip': is_vpn_ip,
            'unique_ips_30d': min(unique_ips / 20.0, 1.0),
            'ip_frequency': ip_frequency,
            'is_new_ip': is_new_ip,
            'recent_failed_attempts': min(recent_failures / 10.0, 1.0)
        })
        
        return features
    
    def _extract_frequency_risk_features(self, activity, user_history):
        """Extract login frequency risk features"""
        features = {}
        
        timestamp = activity.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        if user_history:
            # Calculate login frequencies for different time windows
            login_freq_1h = self._count_logins_in_window(user_history, timestamp, hours=1)
            login_freq_6h = self._count_logins_in_window(user_history, timestamp, hours=6)
            login_freq_24h = self._count_logins_in_window(user_history, timestamp, hours=24)
            login_freq_7d = self._count_logins_in_window(user_history, timestamp, days=7)
            
            # Calculate average frequencies
            avg_daily_logins = self._calculate_average_daily_logins(user_history)
            
            # Frequency anomaly scores
            freq_anomaly_1h = min(login_freq_1h / 5.0, 1.0)  # Normalized to 5 logins/hour
            freq_anomaly_24h = login_freq_24h / max(avg_daily_logins, 1) if avg_daily_logins > 0 else 0
            
        else:
            login_freq_1h = 1
            login_freq_6h = 1
            login_freq_24h = 1
            login_freq_7d = 1
            avg_daily_logins = 1
            freq_anomaly_1h = 0.2
            freq_anomaly_24h = 1.0
        
        features.update({
            'login_freq_1h': min(login_freq_1h / 10.0, 1.0),
            'login_freq_6h': min(login_freq_6h / 20.0, 1.0),
            'login_freq_24h': min(login_freq_24h / 50.0, 1.0),
            'login_freq_7d': min(login_freq_7d / 200.0, 1.0),
            'avg_daily_logins': min(avg_daily_logins / 20.0, 1.0),
            'freq_anomaly_1h': freq_anomaly_1h,
            'freq_anomaly_24h': min(freq_anomaly_24h, 1.0)
        })
        
        return features
    
    def _extract_historical_risk_features(self, user_history):
        """Extract historical risk pattern features"""
        features = {}
        
        if user_history:
            # Historical risk scores
            historical_risks = [h.get('risk_score', 0) for h in user_history]
            avg_historical_risk = np.mean(historical_risks)
            max_historical_risk = max(historical_risks)
            risk_trend = self._calculate_risk_trend(historical_risks)
            
            # Suspicious activity history
            suspicious_count = len([h for h in user_history if h.get('is_suspicious', False)])
            suspicious_ratio = suspicious_count / len(user_history)
            
            # Account age and activity
            account_age_days = self._calculate_account_age(user_history)
            total_activities = len(user_history)
            
        else:
            avg_historical_risk = 0
            max_historical_risk = 0
            risk_trend = 0
            suspicious_count = 0
            suspicious_ratio = 0
            account_age_days = 0
            total_activities = 0
        
        features.update({
            'avg_historical_risk': avg_historical_risk / 100.0,
            'max_historical_risk': max_historical_risk / 100.0,
            'risk_trend': max(-1, min(risk_trend / 50.0, 1)),  # Normalized trend
            'suspicious_activity_ratio': suspicious_ratio,
            'account_age_days': min(account_age_days / 365.0, 1.0),  # Normalized to 1 year
            'total_activities': min(total_activities / 1000.0, 1.0)
        })
        
        return features
    
    def calculate_ml_risk_score(self, user_activity, user_history=None):
        """Calculate comprehensive ML-based risk score"""
        try:
            if not self.models_trained:
                self.train_risk_models()
            
            # Extract features
            feature_data = self.extract_risk_features(user_activity, user_history)
            X = np.array([feature_data['features']])
            X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            
            # Scale features
            X_scaled = self.standard_scaler.transform(X)
            X_robust = self.robust_scaler.transform(X)
            
            # Get predictions from all models
            rf_prob = self.risk_classifier.predict_proba(X_scaled)[0][1]
            gb_prob = self.gradient_booster.predict_proba(X_scaled)[0][1]
            lr_prob = self.logistic_model.predict_proba(X_robust)[0][1]
            
            # Ensemble prediction (weighted average)
            ensemble_prob = (rf_prob * 0.4 + gb_prob * 0.4 + lr_prob * 0.2)
            
            # Convert to risk score (0-100)
            base_risk_score = ensemble_prob * 100
            
            # Apply dynamic risk adjustments
            adjusted_risk_score = self._apply_dynamic_risk_adjustments(
                base_risk_score, user_activity, feature_data['raw_features']
            )
            
            # Get anomaly detection input
            anomaly_result = advanced_anomaly_detector.detect_anomalies(user_activity)
            
            # Combine ML risk score with anomaly detection
            final_risk_score = self._combine_risk_and_anomaly_scores(
                adjusted_risk_score, anomaly_result
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(final_risk_score)
            
            # Generate risk explanation
            risk_explanation = self._generate_risk_explanation(
                feature_data, final_risk_score, anomaly_result
            )
            
            return {
                'risk_score': min(100, max(0, final_risk_score)),
                'risk_level': risk_level,
                'confidence': self._calculate_prediction_confidence([rf_prob, gb_prob, lr_prob]),
                'model_scores': {
                    'random_forest': rf_prob * 100,
                    'gradient_boosting': gb_prob * 100,
                    'logistic_regression': lr_prob * 100,
                    'ensemble': ensemble_prob * 100
                },
                'anomaly_score': anomaly_result.get('anomaly_score', 0),
                'risk_factors': risk_explanation['risk_factors'],
                'protective_factors': risk_explanation['protective_factors'],
                'recommendations': risk_explanation['recommendations'],
                'feature_contributions': self._calculate_feature_risk_contributions(feature_data, X_scaled)
            }
            
        except Exception as e:
            logging.error(f"Error calculating ML risk score: {e}")
            return self._get_default_risk_result()
    
    def _apply_dynamic_risk_adjustments(self, base_score, activity, raw_features):
        """Apply dynamic risk adjustments based on specific conditions"""
        adjusted_score = base_score
        
        # Geographic risk adjustments
        if raw_features.get('is_new_country', 0) == 1:
            adjusted_score *= self.risk_multipliers['first_time_country']
        
        if raw_features.get('geographic_velocity', 0) > 0.5:  # > 500 km/h
            adjusted_score *= self.risk_multipliers['impossible_travel']
        
        # Behavioral risk adjustments
        if raw_features.get('is_new_device', 0) == 1:
            adjusted_score *= self.risk_multipliers['new_device']
        
        if raw_features.get('behavioral_consistency', 1) < 0.3:
            adjusted_score *= self.risk_multipliers['behavioral_anomaly']
        
        # Temporal risk adjustments
        if raw_features.get('is_night_time', 0) == 1:
            adjusted_score *= self.risk_multipliers['unusual_hours']
        
        # Frequency risk adjustments
        if raw_features.get('login_freq_1h', 0) > 0.5:  # > 5 logins/hour
            adjusted_score *= self.risk_multipliers['high_frequency']
        
        # Technical risk adjustments
        if raw_features.get('ip_reputation_score', 0) > 0.5:
            adjusted_score *= self.risk_multipliers['suspicious_ip']
        
        if raw_features.get('recent_failed_attempts', 0) > 0.3:
            adjusted_score *= self.risk_multipliers['multiple_failed_attempts']
        
        return adjusted_score
    
    def _combine_risk_and_anomaly_scores(self, risk_score, anomaly_result):
        """Combine ML risk score with anomaly detection results"""
        anomaly_score = abs(anomaly_result.get('anomaly_score', 0)) * 100
        anomaly_confidence = anomaly_result.get('confidence', 0)
        
        # Weight the combination based on confidence
        if anomaly_confidence > 0.7:
            # High confidence anomaly detection
            combined_score = risk_score * 0.6 + anomaly_score * 0.4
        elif anomaly_confidence > 0.4:
            # Medium confidence anomaly detection
            combined_score = risk_score * 0.7 + anomaly_score * 0.3
        else:
            # Low confidence anomaly detection
            combined_score = risk_score * 0.8 + anomaly_score * 0.2
        
        # Boost score if anomaly is detected
        if anomaly_result.get('is_anomaly', False):
            combined_score = min(100, combined_score * 1.2)
        
        return combined_score
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= self.risk_thresholds['critical']:
            return 'critical'
        elif risk_score >= self.risk_thresholds['high']:
            return 'high'
        elif risk_score >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _generate_risk_explanation(self, feature_data, risk_score, anomaly_result):
        """Generate human-readable risk explanation"""
        risk_factors = []
        protective_factors = []
        recommendations = []
        
        raw_features = feature_data['raw_features']
        
        # Analyze risk factors
        if raw_features.get('is_new_country', 0) == 1:
            risk_factors.append("Login from a new country")
        
        if raw_features.get('geographic_velocity', 0) > 0.5:
            risk_factors.append("Impossible travel speed detected")
        
        if raw_features.get('is_new_device', 0) == 1:
            risk_factors.append("Login from a new device")
        
        if raw_features.get('is_night_time', 0) == 1:
            risk_factors.append("Login during unusual hours")
        
        if raw_features.get('login_freq_1h', 0) > 0.5:
            risk_factors.append("High login frequency")
        
        if raw_features.get('recent_failed_attempts', 0) > 0.3:
            risk_factors.append("Recent failed login attempts")
        
        if raw_features.get('behavioral_consistency', 1) < 0.3:
            risk_factors.append("Unusual behavioral pattern")
        
        # Analyze protective factors
        if raw_features.get('account_age_days', 0) > 0.5:
            protective_factors.append("Established account with history")
        
        if raw_features.get('device_frequency', 0) > 0.7:
            protective_factors.append("Login from frequently used device")
        
        if raw_features.get('country_frequency', 0) > 0.8:
            protective_factors.append("Login from usual location")
        
        if raw_features.get('is_business_hours', 0) == 1:
            protective_factors.append("Login during business hours")
        
        # Generate recommendations
        if risk_score >= 80:
            recommendations.extend([
                "Require additional authentication factors",
                "Monitor session closely for suspicious activity",
                "Consider temporary account restrictions"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "Request additional verification",
                "Monitor user activity patterns",
                "Send security notification to user"
            ])
        elif risk_score >= 30:
            recommendations.extend([
                "Log activity for review",
                "Monitor for pattern changes"
            ])
        
        return {
            'risk_factors': risk_factors,
            'protective_factors': protective_factors,
            'recommendations': recommendations
        }
    
    def train_risk_models(self, training_data=None):
        """Train ML risk scoring models"""
        try:
            if training_data is None:
                training_data = self._collect_risk_training_data()
            
            if len(training_data) < 100:
                logging.warning("Insufficient training data. Generating synthetic data.")
                training_data.extend(self._generate_risk_synthetic_data())
            
            # Prepare training data
            X = np.array([item['features'] for item in training_data])
            y = np.array([1 if item['is_high_risk'] else 0 for item in training_data])
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.standard_scaler.fit_transform(X_train)
            X_test_scaled = self.standard_scaler.transform(X_test)
            
            X_train_robust = self.robust_scaler.fit_transform(X_train)
            X_test_robust = self.robust_scaler.transform(X_test)
            
            # Train models
            logging.info("Training Random Forest risk model...")
            self.risk_classifier.fit(X_train_scaled, y_train)
            
            logging.info("Training Gradient Boosting risk model...")
            self.gradient_booster.fit(X_train_scaled, y_train)
            
            logging.info("Training Logistic Regression risk model...")
            self.logistic_model.fit(X_train_robust, y_train)
            
            # Evaluate models
            rf_score = roc_auc_score(y_test, self.risk_classifier.predict_proba(X_test_scaled)[:, 1])
            gb_score = roc_auc_score(y_test, self.gradient_booster.predict_proba(X_test_scaled)[:, 1])
            lr_score = roc_auc_score(y_test, self.logistic_model.predict_proba(X_test_robust)[:, 1])
            
            logging.info(f"Model performance - RF: {rf_score:.3f}, GB: {gb_score:.3f}, LR: {lr_score:.3f}")
            
            # Calculate feature importance
            self._calculate_risk_feature_importance(training_data[0]['feature_names'])
            
            self.models_trained = True
            self._save_risk_models()
            
            return {
                'models_trained': True,
                'training_samples': len(training_data),
                'model_scores': {
                    'random_forest_auc': rf_score,
                    'gradient_boosting_auc': gb_score,
                    'logistic_regression_auc': lr_score
                }
            }
            
        except Exception as e:
            logging.error(f"Error training risk models: {e}")
            return {'models_trained': False, 'error': str(e)}
    
    # Helper methods (continuing with the remaining implementation)
    def _get_user_comprehensive_history(self, user_id, days=30):
        """Get comprehensive user history"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            cutoff_date = datetime.now() - timedelta(days=days)
            history = list(activities.find({
                'user_id': user_id,
                'timestamp': {'$gte': cutoff_date}
            }).sort('timestamp', -1))
            
            return history
        except Exception as e:
            logging.error(f"Error getting user history: {e}")
            return []
    
    def _get_default_risk_features(self):
        """Return default risk features"""
        feature_names = [
            'hour_of_day', 'day_of_week', 'is_weekend', 'is_night_time', 'is_business_hours',
            'hour_variance', 'unusual_hour_score', 'time_since_last_hours',
            'unique_countries_30d', 'country_frequency', 'is_new_country',
            'unique_cities_30d', 'city_frequency', 'is_new_city',
            'geographic_velocity', 'avg_distance_from_usual',
            'unique_devices_30d', 'device_frequency', 'is_new_device',
            'avg_session_duration', 'session_duration_variance', 'session_duration_anomaly',
            'behavioral_consistency', 'activity_regularity',
            'ip_reputation_score', 'is_tor_ip', 'is_vpn_ip',
            'unique_ips_30d', 'ip_frequency', 'is_new_ip', 'recent_failed_attempts',
            'login_freq_1h', 'login_freq_6h', 'login_freq_24h', 'login_freq_7d',
            'avg_daily_logins', 'freq_anomaly_1h', 'freq_anomaly_24h',
            'avg_historical_risk', 'max_historical_risk', 'risk_trend',
            'suspicious_activity_ratio', 'account_age_days', 'total_activities'
        ]
        
        return {
            'features': [0.5] * len(feature_names),  # Neutral values
            'feature_names': feature_names,
            'feature_categories': self._categorize_features(feature_names),
            'raw_features': {name: 0.5 for name in feature_names}
        }
    
    def _get_default_risk_result(self):
        """Return default risk result"""
        return {
            'risk_score': 50,
            'risk_level': 'medium',
            'confidence': 0.5,
            'model_scores': {
                'random_forest': 50,
                'gradient_boosting': 50,
                'logistic_regression': 50,
                'ensemble': 50
            },
            'anomaly_score': 0,
            'risk_factors': ['Unable to analyze risk factors'],
            'protective_factors': [],
            'recommendations': ['Monitor activity patterns'],
            'feature_contributions': {}
        }
    
    def _categorize_features(self, feature_names):
        """Categorize features by risk category"""
        categories = {}
        
        temporal_features = ['hour_of_day', 'day_of_week', 'is_weekend', 'is_night_time', 
                           'is_business_hours', 'hour_variance', 'unusual_hour_score', 
                           'time_since_last_hours']
        
        geographic_features = ['unique_countries_30d', 'country_frequency', 'is_new_country',
                             'unique_cities_30d', 'city_frequency', 'is_new_city',
                             'geographic_velocity', 'avg_distance_from_usual']
        
        behavioral_features = ['unique_devices_30d', 'device_frequency', 'is_new_device',
                             'avg_session_duration', 'session_duration_variance', 
                             'session_duration_anomaly', 'behavioral_consistency', 
                             'activity_regularity']
        
        technical_features = ['ip_reputation_score', 'is_tor_ip', 'is_vpn_ip',
                            'unique_ips_30d', 'ip_frequency', 'is_new_ip', 
                            'recent_failed_attempts']
        
        frequency_features = ['login_freq_1h', 'login_freq_6h', 'login_freq_24h', 
                            'login_freq_7d', 'avg_daily_logins', 'freq_anomaly_1h', 
                            'freq_anomaly_24h']
        
        historical_features = ['avg_historical_risk', 'max_historical_risk', 'risk_trend',
                             'suspicious_activity_ratio', 'account_age_days', 
                             'total_activities']
        
        for feature in feature_names:
            if feature in temporal_features:
                categories[feature] = 'temporal'
            elif feature in geographic_features:
                categories[feature] = 'geographic'
            elif feature in behavioral_features:
                categories[feature] = 'behavioral'
            elif feature in technical_features:
                categories[feature] = 'technical'
            elif feature in frequency_features:
                categories[feature] = 'frequency'
            elif feature in historical_features:
                categories[feature] = 'historical'
            else:
                categories[feature] = 'other'
        
        return categories
    
    def _save_risk_models(self):
        """Save trained risk models"""
        try:
            models_dir = 'models'
            os.makedirs(models_dir, exist_ok=True)
            
            joblib.dump(self.risk_classifier, f'{models_dir}/risk_classifier.pkl')
            joblib.dump(self.gradient_booster, f'{models_dir}/gradient_booster.pkl')
            joblib.dump(self.logistic_model, f'{models_dir}/logistic_model.pkl')
            joblib.dump(self.standard_scaler, f'{models_dir}/risk_standard_scaler.pkl')
            joblib.dump(self.robust_scaler, f'{models_dir}/risk_robust_scaler.pkl')
            joblib.dump(self.feature_importance, f'{models_dir}/risk_feature_importance.pkl')
            
            logging.info("Risk scoring models saved successfully")
        except Exception as e:
            logging.error(f"Error saving risk models: {e}")
    
    def load_risk_models(self):
        """Load trained risk models"""
        try:
            models_dir = 'models'
            
            if os.path.exists(f'{models_dir}/risk_classifier.pkl'):
                self.risk_classifier = joblib.load(f'{models_dir}/risk_classifier.pkl')
                self.gradient_booster = joblib.load(f'{models_dir}/gradient_booster.pkl')
                self.logistic_model = joblib.load(f'{models_dir}/logistic_model.pkl')
                self.standard_scaler = joblib.load(f'{models_dir}/risk_standard_scaler.pkl')
                self.robust_scaler = joblib.load(f'{models_dir}/risk_robust_scaler.pkl')
                self.feature_importance = joblib.load(f'{models_dir}/risk_feature_importance.pkl')
                self.models_trained = True
                logging.info("Risk scoring models loaded successfully")
            else:
                logging.info("No saved risk models found, will train on first use")
        except Exception as e:
            logging.error(f"Error loading risk models: {e}")

# Initialize global ML risk scorer
ml_risk_scorer = MLRiskScorer()
