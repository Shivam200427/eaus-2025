"use client"

import type React from "react"
import { createContext, useContext, useState, useEffect } from "react"
import axios from "axios"
import Cookies from "js-cookie"

interface User {
  id: string
  email: string
  name: string
  role: string
}

interface AuthContextType {
  user: User | null
  login: (email: string, password: string) => Promise<{ success: boolean; message: string; securityAlert?: boolean }>
  register: (email: string, password: string, name: string) => Promise<{ success: boolean; message: string }>
  logout: () => void
  loading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const API_URL = process.env.NEXT_PUBLIC_API_URL

  // Configure axios defaults
  axios.defaults.baseURL = API_URL

  useEffect(() => {
    const token = Cookies.get("auth_token")
    if (token) {
      axios.defaults.headers.common["Authorization"] = `Bearer ${token}`
      fetchProfile()
    } else {
      setLoading(false)
    }
  }, [])

  const fetchProfile = async () => {
    try {
      const response = await axios.get("/api/auth/profile")
      setUser(response.data.user)
    } catch (error) {
      console.error("Failed to fetch profile:", error)
      Cookies.remove("auth_token")
      delete axios.defaults.headers.common["Authorization"]
    } finally {
      setLoading(false)
    }
  }

  const login = async (email: string, password: string) => {
    try {
      const response = await axios.post("/api/auth/login", { email, password })
      const { access_token, user: userData, security_alert } = response.data

      Cookies.set("auth_token", access_token, { expires: 1 })
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
      setUser(userData)

      return {
        success: true,
        message: "Login successful",
        securityAlert: security_alert,
      }
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.error || "Login failed",
      }
    }
  }

  const register = async (email: string, password: string, name: string) => {
    try {
      const response = await axios.post("/api/auth/register", { email, password, name })
      const { access_token, user: userData } = response.data

      Cookies.set("auth_token", access_token, { expires: 1 })
      axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
      setUser(userData)

      return { success: true, message: "Registration successful" }
    } catch (error: any) {
      return {
        success: false,
        message: error.response?.data?.error || "Registration failed",
      }
    }
  }

  const logout = () => {
    Cookies.remove("auth_token")
    delete axios.defaults.headers.common["Authorization"]
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, login, register, logout, loading }}>{children}</AuthContext.Provider>
}
