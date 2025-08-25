"use client"

import { useAuth } from "@/contexts/AuthContext"
import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"
import axios from "axios"
import { LogOut, Shield, Users, Activity, AlertTriangle, MapPin } from "lucide-react"
import SecurityMap from "@/components/SecurityMap"
import MLInsightsDashboard from "@/components/MLInsightsDashboard"

interface DashboardData {
  stats: {
    total_users: number
    total_logins: number
    suspicious_activities: number
    active_sessions: number
  }
  login_locations: Array<{
    lat: number
    lng: number
    country: string
    city: string
    risk_score: number
    timestamp: string
    is_suspicious: boolean
  }>
  country_stats: Record<string, { count: number; suspicious: number }>
  recent_activities: Array<{
    id: string
    user_id: string
    ip_address: string
    location: {
      country: string
      city: string
    }
    timestamp: string
    is_suspicious: boolean
    risk_score: number
  }>
}

export default function AdminDashboard() {
  const { user, logout, loading } = useAuth()
  const router = useRouter()
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null)
  const [loadingData, setLoadingData] = useState(true)
  const [activeView, setActiveView] = useState<"traditional" | "ml">("traditional")

  useEffect(() => {
    if (!loading && (!user || user.role !== "admin")) {
      router.push("/")
    } else if (user && user.role === "admin") {
      fetchDashboardData()
    }
  }, [user, loading, router])

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get("/api/analytics/dashboard")
      setDashboardData(response.data)
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error)
    } finally {
      setLoadingData(false)
    }
  }

  if (loading || !user || user.role !== "admin") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-xl font-semibold text-gray-900">Security Analytics Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex bg-gray-100 rounded-lg p-1">
                <button
                  onClick={() => setActiveView("traditional")}
                  className={`px-3 py-1 text-sm font-medium rounded-md transition-colors ${
                    activeView === "traditional"
                      ? "bg-white text-blue-600 shadow-sm"
                      : "text-gray-600 hover:text-gray-900"
                  }`}
                >
                  Traditional
                </button>
                <button
                  onClick={() => setActiveView("ml")}
                  className={`px-3 py-1 text-sm font-medium rounded-md transition-colors ${
                    activeView === "ml" ? "bg-white text-purple-600 shadow-sm" : "text-gray-600 hover:text-gray-900"
                  }`}
                >
                  ML Analytics
                </button>
              </div>
              <span className="text-sm text-gray-700">Admin: {user.name || user.email}</span>
              <button onClick={() => router.push("/dashboard")} className="text-blue-600 hover:text-blue-800 text-sm">
                User View
              </button>
              <button onClick={logout} className="flex items-center text-gray-700 hover:text-gray-900">
                <LogOut className="h-4 w-4 mr-1" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {activeView === "ml" ? (
            <MLInsightsDashboard />
          ) : (
            <>
              {loadingData ? (
                <div className="flex items-center justify-center py-12">
                  <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
                </div>
              ) : dashboardData ? (
                <>
                  {/* Stats Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div className="bg-white overflow-hidden shadow rounded-lg">
                      <div className="p-5">
                        <div className="flex items-center">
                          <div className="flex-shrink-0">
                            <Users className="h-6 w-6 text-blue-600" />
                          </div>
                          <div className="ml-5 w-0 flex-1">
                            <dl>
                              <dt className="text-sm font-medium text-gray-500 truncate">Total Users</dt>
                              <dd className="text-lg font-medium text-gray-900">{dashboardData.stats.total_users}</dd>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white overflow-hidden shadow rounded-lg">
                      <div className="p-5">
                        <div className="flex items-center">
                          <div className="flex-shrink-0">
                            <Activity className="h-6 w-6 text-green-600" />
                          </div>
                          <div className="ml-5 w-0 flex-1">
                            <dl>
                              <dt className="text-sm font-medium text-gray-500 truncate">Total Logins</dt>
                              <dd className="text-lg font-medium text-gray-900">{dashboardData.stats.total_logins}</dd>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white overflow-hidden shadow rounded-lg">
                      <div className="p-5">
                        <div className="flex items-center">
                          <div className="flex-shrink-0">
                            <AlertTriangle className="h-6 w-6 text-red-600" />
                          </div>
                          <div className="ml-5 w-0 flex-1">
                            <dl>
                              <dt className="text-sm font-medium text-gray-500 truncate">Suspicious Activities</dt>
                              <dd className="text-lg font-medium text-gray-900">
                                {dashboardData.stats.suspicious_activities}
                              </dd>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white overflow-hidden shadow rounded-lg">
                      <div className="p-5">
                        <div className="flex items-center">
                          <div className="flex-shrink-0">
                            <MapPin className="h-6 w-6 text-purple-600" />
                          </div>
                          <div className="ml-5 w-0 flex-1">
                            <dl>
                              <dt className="text-sm font-medium text-gray-500 truncate">Countries</dt>
                              <dd className="text-lg font-medium text-gray-900">
                                {Object.keys(dashboardData.country_stats).length}
                              </dd>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Security Map */}
                  <div className="bg-white shadow rounded-lg mb-8">
                    <div className="px-4 py-5 sm:px-6">
                      <h3 className="text-lg leading-6 font-medium text-gray-900">Global Login Activity</h3>
                      <p className="mt-1 max-w-2xl text-sm text-gray-500">
                        Interactive map showing login locations and risk assessment.
                      </p>
                    </div>
                    <div className="px-4 pb-5">
                      <SecurityMap locations={dashboardData.login_locations} />
                    </div>
                  </div>

                  {/* Recent Activities */}
                  <div className="bg-white shadow overflow-hidden sm:rounded-md">
                    <div className="px-4 py-5 sm:px-6">
                      <h3 className="text-lg leading-6 font-medium text-gray-900">Recent Login Activities</h3>
                      <p className="mt-1 max-w-2xl text-sm text-gray-500">
                        Latest user login sessions across the platform.
                      </p>
                    </div>
                    <ul className="divide-y divide-gray-200">
                      {dashboardData.recent_activities.map((activity) => (
                        <li key={activity.id} className="px-4 py-4">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center">
                              <div
                                className={`flex-shrink-0 h-3 w-3 rounded-full ${
                                  activity.is_suspicious ? "bg-red-400" : "bg-green-400"
                                }`}
                              ></div>
                              <div className="ml-4">
                                <div className="text-sm font-medium text-gray-900">
                                  User ID: {activity.user_id.slice(-8)}
                                </div>
                                <div className="text-sm text-gray-500">
                                  {activity.location?.city}, {activity.location?.country} • IP: {activity.ip_address} •
                                  Risk: {activity.risk_score}
                                </div>
                              </div>
                            </div>
                            <div className="text-sm text-gray-500">{new Date(activity.timestamp).toLocaleString()}</div>
                          </div>
                          {activity.is_suspicious && (
                            <div className="mt-2 ml-7">
                              <div className="bg-red-50 border border-red-200 rounded-md p-3">
                                <div className="flex">
                                  <AlertTriangle className="h-5 w-5 text-red-400" />
                                  <div className="ml-3">
                                    <h4 className="text-sm font-medium text-red-800">High Risk Activity</h4>
                                    <p className="text-sm text-red-700 mt-1">
                                      This login session triggered multiple security alerts.
                                    </p>
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                </>
              ) : (
                <div className="text-center py-12">
                  <p className="text-gray-500">Failed to load dashboard data.</p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
