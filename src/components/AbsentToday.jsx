// TodayAbsent.jsx
import { useEffect, useState } from "react";
import { FiAlertTriangle } from "react-icons/fi"; // exclamation icon

export default function TodayAbsent() {
  const [count, setCount] = useState(null);
  const [displayCount, setDisplayCount] = useState(0); // count-up animation
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchAbsentCount = async () => {
      try {
        const res = await fetch("https://automated-attendance-6rl6.onrender.com/api/students-absent-today");
        const data = await res.json();
        setCount(data.count);
      } catch (err) {
        console.error("Error fetching absent employees:", err);
        setError("Failed to load data");
      } finally {
        setLoading(false);
      }
    };

    fetchAbsentCount();
    const interval = setInterval(fetchAbsentCount, 60000);
    return () => clearInterval(interval);
  }, []);

  // Count-up effect
  useEffect(() => {
    if (count === null) return;
    let start = 0;
    const end = count;
    const duration = 1000;
    const stepTime = Math.max(Math.floor(duration / end), 1);
    const timer = setInterval(() => {
      start += 1;
      setDisplayCount(start);
      if (start >= end) clearInterval(timer);
    }, stepTime);
  }, [count]);

  return (
    <div
      className="today-absent-card"
      style={{
        width: "300px",
        height: "200px",
        padding: "25px",
        background: "linear-gradient(135deg, #ff416c, #ff4b2b)",
        color: "#fff", 
        borderRadius: "16px",
        boxShadow: "0 8px 20px rgba(0,0,0,0.4)",
        textAlign: "center",
        transform: "scale(0)",
        animation: "fadeInScale 0.8s forwards",
        cursor: "pointer",
        transition: "transform 0.3s, box-shadow 0.3s",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
        gap: "10px"
      }}
      onMouseEnter={e => {
        e.currentTarget.style.transform = "scale(1.05)";
        e.currentTarget.style.boxShadow = "0 12px 30px rgba(0,0,0,0.4)";
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = "scale(1)";
        e.currentTarget.style.boxShadow = "0 8px 20px rgba(0,0,0,0.2)";
      }}
    >
      <FiAlertTriangle size={36} color="#fff" />
      <h3 style={{ margin: 0, fontSize: "1.5rem", color: "#fff" }}>
        Absent Today
      </h3>
      {loading ? (
        <p style={{ color: "#e0f7e0", margin: 0 }}>Loading...</p>
      ) : error ? (
        <p style={{ color: "#e0f7e0", margin: 0 }}>{error}</p>
      ) : (
        <span style={{ fontSize: "3rem", fontWeight: "bold", color: "#fff" }}>
          {displayCount}
        </span>
      )}

      <style>
        {`
          @keyframes fadeInScale {
            0% { opacity: 0; transform: scale(0.8); }
            100% { opacity: 1; transform: scale(1); }
          }
        `}
      </style>
    </div>
  );
}
