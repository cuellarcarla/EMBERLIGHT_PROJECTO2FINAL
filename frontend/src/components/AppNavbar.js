import { Link, useNavigate } from "react-router-dom";
import { FaUser } from "react-icons/fa";
import { IconContext } from "react-icons";
import "./AppNavbar.css";
import { useAuth } from "../contexts/AuthContext";
import { useState } from "react";

const AppNavbar = () => {
  const { user, logout } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const navigate = useNavigate();

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  const handleLogout = () => {
    logout();
    setDropdownOpen(false)
    navigate("/login");
  };

  const profileRedirect = () => {
    setDropdownOpen(false)
    navigate("/profile");
  }

  return (
    <nav className="navbar">
      <div className="nav-left">
        <Link to="/journal" className="logo-link">
          <img src="/logoEmberLight.jpg" alt="Logo" className="logo"></img>
        </Link>
        <Link to="/journal" className="nav-link">DIARIO</Link>
        <Link to="/chat" className="nav-link">CHAT</Link>
      </div>
      <div className="nav-right">
      {user && <span className="user">Bienvenido, {user.username}!</span>}
        <IconContext.Provider
          value={{ className: "nav-icon" }}
        >
          <div className="user-icon" onClick={toggleDropdown}>
            <FaUser />
          </div>
        </IconContext.Provider>
        {dropdownOpen && (
          <div className="dropdown">
            <div className="profile-option" onClick={profileRedirect}>Perfil</div>
            <div className="logout-option" onClick={handleLogout}>Logout</div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default AppNavbar;
