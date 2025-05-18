import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import "./Register.css";

function Register() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errors, setErrors] = useState("");
  const navigate = useNavigate();
  const { register } = useAuth();

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{6,}$/;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrors("");

    if (password !== confirmPassword) {
      setErrors("Las contraseñas no coinciden.");
      return;
    }

    if (!passwordRegex.test(password)) {
      setErrors("La contraseña debe tener por lo menos 1 mayúscula, 1 minúscula, 1 número, y 1 carácter especial.");
      return;
    }

    try {
      await register({ username, email, password });
      navigate("/login");
    } catch (err) {
      if (err.response?.data?.errors) {
        const backendErrors = err.response.data.errors;
        const errorMessages = Object.values(backendErrors).join('\n');
        setErrors(errorMessages);
      } else {
        setErrors("Registration failed");
      }
    }
  };

  return (
    <div className="register-wrapper">
      <div className="register-container">
        <h2>Registro</h2>
        {errors && <p style={{ color: "red" }}>{errors}</p>}
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="Confirm Password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          <button type="submit">Registrarse</button>
        </form>
      </div>
    </div>
  );
}

export default Register;
