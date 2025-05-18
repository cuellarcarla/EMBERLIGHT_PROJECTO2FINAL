import { createContext, useContext, useState, useEffect } from "react";
import { getCookie } from "../utils/cookies";

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = async () => {
    try {
      const res = await fetch("http://localhost:8000/auth/me/", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          'X-CSRFToken': getCookie('csrftoken'),
        },
        credentials: "include",
      });
      
      if (res.ok) {
        const userData = await res.json();
        setUser({
          id: userData.id,
          username: userData.username,
          email: userData.email,
        });
        return true;
      }
      setUser(null);
      return false;
    } catch (err) {
      setUser(null);
      return false;
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  const login = async ({ username, password }) => {
    const response = await fetch("http://localhost:8000/auth/login/", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        'X-CSRFToken': getCookie('csrftoken'),
      },
      credentials: "include",
      body: JSON.stringify({ username, password }),
      
    });

    console.log('Login response status:', response.status);

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Login failed:', errorData);
      throw new Error(errorData.error || "Invalid username or password.");
    }

    // After successful login, verify the session
    console.log('Login successful, verifying session...');
    const success = await fetchUser();
    console.log('Session verification result:', success);
    if (!success) throw new Error("Session verification failed");
  };

  const logout = async () => {
    await fetch("http://localhost:8000/auth/logout/", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        'X-CSRFToken': getCookie('csrftoken'),
      },
      credentials: "include",
    });
    setUser(null);
  };

  const register = async ({ username, email, password }) => {
    const response = await fetch("http://localhost:8000/auth/register/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCookie("csrftoken"),
      },
      credentials: "include",
      body: JSON.stringify({ username, email, password }),
    });

    const responseData = await response.json();
  
    if (!response.ok) {
      const error = new Error(responseData.errors ? "Validation error" : "Registration failed");
      error.response = { data: responseData };
      throw error;
    }
    
    return responseData;
  };

  const updateUser = async ({ username, email }) => {
    try {
      const response = await fetch(`http://localhost:8000/auth/users/${user.id}/update/`, {
        method: 'PUT',
        headers: { 
          "Content-Type": "application/json",
          'X-CSRFToken': getCookie('csrftoken'),
        },
        credentials: "include",
        body: JSON.stringify({ username, email }),
      });

      const responseData = await response.json();

      if (!response.ok) {
        const errorMsg = responseData.errors 
          ? Object.values(responseData.errors).join('\n')
          : responseData.error || "Update failed";
        throw new Error(errorMsg);
      }

      setUser(prev => ({ ...prev, ...responseData }));
      return true;
    } catch (error) {
      console.error('Update error:', error);
      throw error;
    }
  };

  const deleteUserData = async () => {
    try {
      const response = await fetch(`http://localhost:8000/auth/users/delete-data/`, {
        method: 'POST',
        headers: { 
          "Content-Type": "application/json",
          'X-CSRFToken': getCookie('csrftoken'),
        },
        credentials: "include",
      });

      if (!response.ok) {
        throw new Error('Failed to delete user data');
      }
      return true;
    } catch (error) {
      console.error('Data deletion error:', error);
      throw error;
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, register, updateUser, deleteUserData, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);