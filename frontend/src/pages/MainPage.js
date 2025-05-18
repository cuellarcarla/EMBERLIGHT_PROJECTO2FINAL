import { Link } from "react-router-dom";
import './MainPage.css';

const MainPage = () => {
  return (
    <div className="main-container">
      <div className="content-box">
        <h1>Ilumina tus emociones con <span className="bold-text">Emberlight</span></h1>
        <p>Describe tus emociones en un diario digital y recibe apoyo personalizado de nuestra IA de Emberlight</p>
        <Link to="/register" className="get-started-btn">Comienza Ahora</Link>
      </div>
    </div>
  );
};

export default MainPage;