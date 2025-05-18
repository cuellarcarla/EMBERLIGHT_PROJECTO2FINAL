import { Link, useLocation } from "react-router-dom";
import "./MainNavbar.css";

const MainNavbar = () => {
  const location = useLocation();

  return (
    <nav className="main-navbar">
      <div className="nav-left">
        <Link to="/" className="logo-link">
          <img src="/logoEmberLight.jpg" alt="Logo" className="logo"></img>
        </Link>
        <span className="logo-text">EmberLight</span>
      </div>
      <div className="nav-right">
        <Link to="/about">Sobre nosotros</Link>
        <Link to="/functionality">Funcionalidades</Link>
        <Link to="/contact">Contacto</Link>
        <Link to="/login" className={location.pathname === "/login" ? "disabled" : ""}>Login</Link>
        <Link to="/register">Regístrate</Link>
      </div>
    </nav>
  );
};

export default MainNavbar;