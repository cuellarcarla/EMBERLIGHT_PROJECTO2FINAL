import { BrowserRouter as Router, Route, Routes, useLocation, Navigate  } from "react-router-dom";
import MainNavbar from "./components/MainNavbar";
import AppNavbar from "./components/AppNavbar";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Profile from "./pages/Profile";
import NotFound from "./pages/NotFound";
import MainPage from "./pages/MainPage";
import JournalPage from "./pages/JournalPage";
import ChatPage from "./pages/ChatPage";
import { useAuth } from "./contexts/AuthContext";

const Layout = ({ children }) => {
  const location = useLocation();
  const { user, logout } = useAuth();
  const showMainNavbar = ["/", "/login", "/register"].includes(location.pathname);

  return (
    <>
      {showMainNavbar ? <MainNavbar /> : <AppNavbar username={user?.username} onLogout={logout} />}
      {children}
    </>
  );
};

function App() {
  const { user, loading } = useAuth();
  if (loading) {
    return <div>Cargando...</div>;
  }

  return (
    <Router>
      <Layout>
        <Routes>
          {/* No login accessible pages */}
          <Route path="/" element={user ? <Navigate to="/journal" replace /> : <MainPage />} />
          <Route path="/login" element={user ? <Navigate to="/journal" replace /> : <Login />} />
          <Route path="/register" element={user ? <Navigate to="/journal" replace /> : <Register />} />

          {/* Login-only accessible pages */}
          <Route 
            path="/chat" 
            element={user ? <ChatPage /> : <Navigate to="/login" replace />} 
          />
          <Route 
            path="/journal" 
            element={user ? <JournalPage /> : <Navigate to="/login" replace />} 
          />
          <Route 
            path="/profile" 
            element={user ? <Profile /> : <Navigate to="/login" replace />} 
          />

          {/* Not found page, not necessary to check sessions */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;