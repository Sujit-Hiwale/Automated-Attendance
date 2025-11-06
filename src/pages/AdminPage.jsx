import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";


export default function AdminPage() {
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [animate, setAnimate] = useState(false); // for animation
  const navigate = useNavigate();

  // ✅ Redirect if already logged in
  useEffect(() => {
    const authData = JSON.parse(localStorage.getItem("adminAuthData") || "null");
    const now = new Date().getTime();
    if (authData?.authenticated && now - authData.timestamp <= 10 * 60 * 1000) {
      navigate("/dashboard");
    } else {
      setAnimate(true); // start animation after mount
    }
  }, [navigate]);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await fetch("https://automated-attendance-6rl6.onrender.com/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem(
          "adminAuthData",
          JSON.stringify({ authenticated: true, timestamp: new Date().getTime() })
        );
        navigate("/dashboard");
      } else {
        alert("Invalid password!");
      }
    } catch (err) {
      console.error(err);
      alert("Error connecting to server.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.fullPage}>
      <div
        style={{
          ...styles.loginBox,
          transform: animate ? "translateY(0)" : "translateY(-50px)",
          opacity: animate ? 1 : 0,
          transition: "all 0.6s cubic-bezier(0.25, 0.8, 0.25, 1)",
        }}
      >
        <h2 style={styles.title}>Admin Login</h2>
        <form onSubmit={handleSubmit} style={styles.form}>
          <input
            type="password"
            placeholder="Enter Admin Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
            required
          />
          <button type="submit" style={styles.button} disabled={loading}>
            {loading ? "Verifying..." : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}

// ✅ Styles
const styles = {
  fullPage: {
    width: "100vw",
    height: "100vh",
    margin: 0,
    padding: 0,
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    background: "linear-gradient(135deg, #0f172a, #1e293b, #111827)",
    boxSizing: "border-box",
    overflow: "hidden",
  },
  loginBox: {
    width: "90%",
    maxWidth: "400px",
    background: "rgba(255, 255, 255, 0.05)",
    padding: "40px 30px",
    borderRadius: "12px",
    textAlign: "center",
    boxShadow: "0 0 25px rgba(0, 0, 0, 0.5)",
  },
  title: {
    fontSize: "2rem",
    color: "#38bdf8",
    fontWeight: "bold",
    marginBottom: "1rem",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "15px",
  },
  input: {
    width: "90%",
    padding: "12px 15px",
    borderRadius: "8px",
    border: "1px solid #334155",
    backgroundColor: "#1e293b",
    color: "white",
    fontSize: "1rem",
    outline: "none",
  },
  button: {
    backgroundColor: "#38bdf8",
    border: "none",
    borderRadius: "8px",
    padding: "12px 15px",
    fontSize: "1rem",
    fontWeight: "600",
    cursor: "pointer",
    color: "white",
    transition: "all 0.3s ease",
  },
};
