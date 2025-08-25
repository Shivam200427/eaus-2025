"use client"

import { useState, useEffect } from "react"
import axios from "axios"
import {
  Brain,
  TrendingUp,
  Shield,
  AlertTriangle,
  Users,
  Globe,
  Clock,
  Cpu,
  BarChart3,
  Activity,
  Target,
  Zap,
} from "lucide-react"

interface MLDashboardData {
  model_performance: {
    anomaly_detection: {
      models_trained: boolean
      total_activities_analyzed: number
      anomalies_detected: number
      anomaly_rate: number
    }
    risk_scoring: {
      models_trained: boolean
      average_risk_score: number
      high_risk_activities: number
      risk_distribution: {
        low: number
        medium: number
        high: number
        critical: number
      }
    }
  }
  user_risk_profiles: Array<{
    user_id: string
    average_risk_score: number
    total_activities: number
    suspicious_activities: number
    risk_level: string
  }>
  geographic_analysis: {
    high_risk_countries: Array<[string, any]>
    high_risk_cities: Array<[string, any]>
  }
  temporal_patterns: {
    hourly_risk_pattern: number[]
    daily_risk_pattern: number[]
    peak_risk_hours: number[]
    peak_risk_days: number[]
  }
  technical_analysis: {
    high_risk_ips: Array<{
      ip: string
      avg_risk: number
      total_activities: number
      unique_users: number
    }>
    total_unique_ips: number
    total_unique_devices: number
  }
  feature_importance: any
  threat_summary: {
    total_threats_detected: number
    threat_trend: string
    most_common_threat_types: string[]
    threat_sources: any
  }
  predictive_insights: {
    predicted_threat_increase: string
    high_risk_time_windows: string[]
    emerging_risk_patterns: string[]
    recommended_actions: string[]
  }
}

interface MLInsightsDashboardProps {
  className?: string
}

export default function MLInsightsDashboard({ className = "" }: MLInsightsDashboardProps) {
  const [mlData, setMlData] = useState<MLDashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<"overview" | "models" | "threats" | "predictions">("overview")

  useEffect(() => {
    fetchMLDashboardData()
  }, [])

  const fetchMLDashboardData = async () => {
    try {
      setLoading(true)
      const response = await axios.get("/api/analytics/ml-dashboard")
      setMlData(response.data)
      setError(null)
    } catch (err) {
      console.error("Failed to fetch ML dashboard data:", err)
      setError("Failed to load ML insights")
    } finally {
      setLoading(false)
    }
  }

  const triggerModelTraining = async (modelType = "all") => {
    try {
      await axios.post("/api/analytics/ml-model-training", { model_type: modelType })
      // Refresh data after training
      await fetchMLDashboardData()
    } catch (err) {
      console.error("Failed to trigger model training:", err)
    }
  }

  if (loading) {
    return (
      <div className={`bg-white rounded-lg shadow-lg p-6 ${className}`}>
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading ML insights...</span>
        </div>
      </div>
    )
  }

  if (error || !mlData) {
    return (
      <div className={`bg-white rounded-lg shadow-lg p-6 ${className}`}>
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <p className="text-gray-600">{error || "No ML data available"}</p>
          <button
            onClick={fetchMLDashboardData}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className={`bg-white rounded-lg shadow-lg ${className}`}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Brain className="h-6 w-6 text-purple-600 mr-3" />
            <h2 className="text-xl font-semibold text-gray-900">ML Security Analytics</h2>
          </div>
          <button
            onClick={() => triggerModelTraining()}
            className="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 flex items-center"
          >
            <Zap className="h-4 w-4 mr-2" />
            Retrain Models
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="px-6 py-3 border-b border-gray-200">
        <nav className="flex space-x-8">
          {[
            { id: "overview", label: "Overview", icon: BarChart3 },
            { id: "models", label: "Model Performance", icon: Cpu },
            { id: "threats", label: "Threat Analysis", icon: Shield },
            { id: "predictions", label: "Predictions", icon: TrendingUp },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as any)}
              className={`flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                activeTab === id ? "bg-purple-100 text-purple-700" : "text-gray-500 hover:text-gray-700"
              }`}
            >
              <Icon className="h-4 w-4 mr-2" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="p-6">
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* Model Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-gradient-to-r from-blue-50 to-blue-100 rounded-lg p-4">
                <div className="flex items-center">
                  <Activity className="h-8 w-8 text-blue-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-blue-900">Activities Analyzed</p>
                    <p className="text-2xl font-bold text-blue-700">
                      {mlData.model_performance.anomaly_detection.total_activities_analyzed.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-r from-red-50 to-red-100 rounded-lg p-4">
                <div className="flex items-center">
                  <AlertTriangle className="h-8 w-8 text-red-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-red-900">Anomalies Detected</p>
                    <p className="text-2xl font-bold text-red-700">
                      {mlData.model_performance.anomaly_detection.anomalies_detected}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-r from-yellow-50 to-yellow-100 rounded-lg p-4">
                <div className="flex items-center">
                  <Target className="h-8 w-8 text-yellow-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-yellow-900">Avg Risk Score</p>
                    <p className="text-2xl font-bold text-yellow-700">
                      {mlData.model_performance.risk_scoring.average_risk_score.toFixed(1)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-r from-green-50 to-green-100 rounded-lg p-4">
                <div className="flex items-center">
                  <Shield className="h-8 w-8 text-green-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-green-900">Detection Rate</p>
                    <p className="text-2xl font-bold text-green-700">
                      {mlData.model_performance.anomaly_detection.anomaly_rate.toFixed(1)}%
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Risk Distribution Chart */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Risk Distribution</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {Object.entries(mlData.model_performance.risk_scoring.risk_distribution).map(([level, count]) => (
                  <div key={level} className="text-center">
                    <div
                      className={`w-16 h-16 mx-auto rounded-full flex items-center justify-center text-white font-bold text-lg ${
                        level === "low"
                          ? "bg-green-500"
                          : level === "medium"
                            ? "bg-yellow-500"
                            : level === "high"
                              ? "bg-orange-500"
                              : "bg-red-500"
                      }`}
                    >
                      {count}
                    </div>
                    <p className="mt-2 text-sm font-medium text-gray-700 capitalize">{level}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* High Risk Users */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">High Risk Users</h3>
              <div className="space-y-3">
                {mlData.user_risk_profiles.slice(0, 5).map((profile, index) => (
                  <div key={profile.user_id} className="flex items-center justify-between bg-white rounded-lg p-3">
                    <div className="flex items-center">
                      <div
                        className={`w-3 h-3 rounded-full mr-3 ${
                          profile.risk_level === "high"
                            ? "bg-red-500"
                            : profile.risk_level === "medium"
                              ? "bg-yellow-500"
                              : "bg-green-500"
                        }`}
                      ></div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">User {profile.user_id.slice(-8)}</p>
                        <p className="text-xs text-gray-500">{profile.total_activities} activities</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-bold text-gray-900">{profile.average_risk_score.toFixed(1)}</p>
                      <p className="text-xs text-gray-500">Risk Score</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === "models" && (
          <div className="space-y-6">
            {/* Model Status */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-blue-50 rounded-lg p-6">
                <div className="flex items-center mb-4">
                  <Brain className="h-6 w-6 text-blue-600 mr-3" />
                  <h3 className="text-lg font-semibold text-blue-900">Anomaly Detection</h3>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-blue-700">Status:</span>
                    <span
                      className={`text-sm font-medium ${
                        mlData.model_performance.anomaly_detection.models_trained ? "text-green-600" : "text-red-600"
                      }`}
                    >
                      {mlData.model_performance.anomaly_detection.models_trained ? "Trained" : "Not Trained"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-blue-700">Activities Analyzed:</span>
                    <span className="text-sm font-medium text-blue-900">
                      {mlData.model_performance.anomaly_detection.total_activities_analyzed.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-blue-700">Detection Rate:</span>
                    <span className="text-sm font-medium text-blue-900">
                      {mlData.model_performance.anomaly_detection.anomaly_rate.toFixed(2)}%
                    </span>
                  </div>
                </div>
              </div>

              <div className="bg-purple-50 rounded-lg p-6">
                <div className="flex items-center mb-4">
                  <Target className="h-6 w-6 text-purple-600 mr-3" />
                  <h3 className="text-lg font-semibold text-purple-900">Risk Scoring</h3>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-purple-700">Status:</span>
                    <span
                      className={`text-sm font-medium ${
                        mlData.model_performance.risk_scoring.models_trained ? "text-green-600" : "text-red-600"
                      }`}
                    >
                      {mlData.model_performance.risk_scoring.models_trained ? "Trained" : "Not Trained"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-purple-700">Avg Risk Score:</span>
                    <span className="text-sm font-medium text-purple-900">
                      {mlData.model_performance.risk_scoring.average_risk_score.toFixed(1)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-purple-700">High Risk Activities:</span>
                    <span className="text-sm font-medium text-purple-900">
                      {mlData.model_performance.risk_scoring.high_risk_activities}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Geographic Analysis */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Geographic Risk Analysis</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-md font-medium text-gray-700 mb-3">High Risk Countries</h4>
                  <div className="space-y-2">
                    {mlData.geographic_analysis.high_risk_countries.slice(0, 5).map(([country, data]) => (
                      <div key={country} className="flex items-center justify-between bg-white rounded p-2">
                        <div className="flex items-center">
                          <Globe className="h-4 w-4 text-gray-500 mr-2" />
                          <span className="text-sm text-gray-900">{country}</span>
                        </div>
                        <span className="text-sm font-medium text-red-600">{data.avg_risk.toFixed(1)}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="text-md font-medium text-gray-700 mb-3">High Risk Cities</h4>
                  <div className="space-y-2">
                    {mlData.geographic_analysis.high_risk_cities.slice(0, 5).map(([city, data]) => (
                      <div key={city} className="flex items-center justify-between bg-white rounded p-2">
                        <div className="flex items-center">
                          <Globe className="h-4 w-4 text-gray-500 mr-2" />
                          <span className="text-sm text-gray-900">{city}</span>
                        </div>
                        <span className="text-sm font-medium text-red-600">{data.avg_risk.toFixed(1)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Temporal Patterns */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Temporal Risk Patterns</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-md font-medium text-gray-700 mb-3">Peak Risk Hours</h4>
                  <div className="flex flex-wrap gap-2">
                    {mlData.temporal_patterns.peak_risk_hours.map((hour) => (
                      <span key={hour} className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm">
                        {hour}:00
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="text-md font-medium text-gray-700 mb-3">Peak Risk Days</h4>
                  <div className="flex flex-wrap gap-2">
                    {mlData.temporal_patterns.peak_risk_days.map((day) => (
                      <span key={day} className="px-3 py-1 bg-orange-100 text-orange-800 rounded-full text-sm">
                        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][day]}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "threats" && (
          <div className="space-y-6">
            {/* Threat Summary */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-red-50 rounded-lg p-4">
                <div className="flex items-center">
                  <AlertTriangle className="h-8 w-8 text-red-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-red-900">Total Threats</p>
                    <p className="text-2xl font-bold text-red-700">{mlData.threat_summary.total_threats_detected}</p>
                  </div>
                </div>
              </div>
              <div className="bg-yellow-50 rounded-lg p-4">
                <div className="flex items-center">
                  <TrendingUp className="h-8 w-8 text-yellow-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-yellow-900">Threat Trend</p>
                    <p className="text-lg font-bold text-yellow-700 capitalize">{mlData.threat_summary.threat_trend}</p>
                  </div>
                </div>
              </div>
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="flex items-center">
                  <Users className="h-8 w-8 text-blue-600" />
                  <div className="ml-3">
                    <p className="text-sm font-medium text-blue-900">Unique IPs</p>
                    <p className="text-2xl font-bold text-blue-700">{mlData.technical_analysis.total_unique_ips}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Common Threat Types */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Most Common Threat Types</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {mlData.threat_summary.most_common_threat_types.map((threat, index) => (
                  <div key={index} className="bg-white rounded-lg p-4 border-l-4 border-red-500">
                    <div className="flex items-center">
                      <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                      <span className="text-sm font-medium text-gray-900">{threat}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* High Risk IPs */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">High Risk IP Addresses</h3>
              <div className="space-y-3">
                {mlData.technical_analysis.high_risk_ips.slice(0, 10).map((ip, index) => (
                  <div key={index} className="flex items-center justify-between bg-white rounded-lg p-3">
                    <div className="flex items-center">
                      <div className="w-3 h-3 bg-red-500 rounded-full mr-3"></div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{ip.ip}</p>
                        <p className="text-xs text-gray-500">
                          {ip.unique_users} users, {ip.total_activities} activities
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-bold text-red-600">{ip.avg_risk.toFixed(1)}</p>
                      <p className="text-xs text-gray-500">Risk Score</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === "predictions" && (
          <div className="space-y-6">
            {/* Predictive Insights */}
            <div className="bg-gradient-to-r from-purple-50 to-blue-50 rounded-lg p-6">
              <div className="flex items-center mb-4">
                <TrendingUp className="h-6 w-6 text-purple-600 mr-3" />
                <h3 className="text-lg font-semibold text-gray-900">Threat Predictions</h3>
              </div>
              <div className="bg-white rounded-lg p-4 mb-4">
                <p className="text-lg font-medium text-gray-900 mb-2">Predicted Threat Increase</p>
                <p className="text-2xl font-bold text-red-600">
                  {mlData.predictive_insights.predicted_threat_increase}
                </p>
              </div>
            </div>

            {/* High Risk Time Windows */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">High Risk Time Windows</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {mlData.predictive_insights.high_risk_time_windows.map((window, index) => (
                  <div key={index} className="bg-white rounded-lg p-4 border-l-4 border-yellow-500">
                    <div className="flex items-center">
                      <Clock className="h-5 w-5 text-yellow-500 mr-2" />
                      <span className="text-sm font-medium text-gray-900">{window}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Emerging Risk Patterns */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Emerging Risk Patterns</h3>
              <div className="space-y-3">
                {mlData.predictive_insights.emerging_risk_patterns.map((pattern, index) => (
                  <div key={index} className="bg-white rounded-lg p-4 border-l-4 border-orange-500">
                    <div className="flex items-center">
                      <TrendingUp className="h-5 w-5 text-orange-500 mr-2" />
                      <span className="text-sm text-gray-900">{pattern}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="bg-gray-50 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recommended Actions</h3>
              <div className="space-y-3">
                {mlData.predictive_insights.recommended_actions.map((action, index) => (
                  <div key={index} className="bg-white rounded-lg p-4 border-l-4 border-green-500">
                    <div className="flex items-center">
                      <Shield className="h-5 w-5 text-green-500 mr-2" />
                      <span className="text-sm text-gray-900">{action}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
