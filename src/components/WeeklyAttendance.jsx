import { useEffect, useState } from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import { FaCircleChevronLeft, FaCircleChevronRight } from "react-icons/fa6";

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export default function WeeklyAttendance() {
  const [weekOffset, setWeekOffset] = useState(0);
  const [labels, setLabels] = useState([]);
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [windowWidth, setWindowWidth] = useState(window.innerWidth);

  // Handle window resize
  useEffect(() => {
    const handleResize = () => setWindowWidth(window.innerWidth);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const fetchWeekData = async () => {
    setLoading(true);
    try {
      const res = await fetch(`https://automated-attendance-6rl6.onrender.com/api/weekly-attendance?offset=${weekOffset}`);
      const result = await res.json();
      setLabels(result.dates || []); // fallback if empty
      setData(result.counts || []);
    } catch (err) {
      console.error("Error fetching weekly attendance:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWeekData();
  }, [weekOffset]);

  // Responsive chart height
  const chartHeight = windowWidth < 400 ? 180 : windowWidth < 768 ? 250 : 350;

  const chartData = {
    labels,
    datasets: [
      {
        label: "Students Present",
        data,
        backgroundColor: (context) => {
          const chart = context.chart;
          const { ctx, chartArea } = chart;
          if (!chartArea) return null;
          const gradient = ctx.createLinearGradient(0, chartArea.bottom, 0, chartArea.top);
          gradient.addColorStop(0, "rgba(255, 99, 132, 0.8)");
          gradient.addColorStop(1, "rgba(255, 180, 100, 0.9)");
          return gradient;
        },
        borderRadius: 6,
        barThickness: "flex",
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: { label: (ctx) => `Present: ${ctx.raw}` },
        backgroundColor: "#222",
        titleColor: "#fff",
        bodyColor: "#fff",
      },
      title: {
        display: true,
        text: "Weekly Attendance",
        color: "#fff",
        font: { size: windowWidth < 480 ? 16 : 20, weight: "600" },
      },
    },
    scales: {
      x: {
        ticks: {
          color: "#fff",
          font: { size: windowWidth < 480 ? 10 : 12 },
        },
        grid: { display: false },
      },
      y: {
        ticks: {
          color: "#fff",
          stepSize: 1,
          font: { size: windowWidth < 480 ? 10 : 12 },
        },
        grid: { color: "rgba(255,255,255,0.2)" },
      },
    },
  };

  return (
    <div
      style={{
        width: "95%",
        maxWidth: "950px",
        margin: "30px auto",
        padding: windowWidth < 500 ? "15px" : "25px",
        borderRadius: "16px",
        background: "linear-gradient(135deg, #11998e, #38ef7d)",
        boxShadow: "0 8px 25px rgba(0,0,0,0.4)",
        color: "#fff",
        transition: "all 0.3s",
        position: "relative", // Needed for absolutely positioned icons
        minHeight: `${chartHeight + 60}px`, // enough height for chart + arrows
      }}
    >
      {/* Chevron Buttons */}
      <FaCircleChevronLeft
        size={windowWidth < 480 ? 28 : 36}
        style={{
          position: "absolute",
          top: "20px",
          left: "20px",
          cursor: "pointer",
          color: "#fff",
          zIndex: 2,
          transition: "0.3s",
        }}
        onClick={() => setWeekOffset((prev) => prev - 1)}
        onMouseEnter={(e) => (e.currentTarget.style.color = "#ffe600")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "#fff")}
      />

      <FaCircleChevronRight
        size={windowWidth < 480 ? 28 : 36}
        style={{
          position: "absolute",
          top: "20px",
          right: "20px",
          cursor: "pointer",
          color: "#fff",
          zIndex: 2,
          transition: "0.3s",
        }}
        onClick={() => setWeekOffset((prev) => prev + 1)}
        onMouseEnter={(e) => (e.currentTarget.style.color = "#ffe600")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "#fff")}
      />

      {/* Chart */}
      <div
        style={{
          position: "relative",
          width: "100%",
          height: `${chartHeight}px`,
        }}
      >
        {loading ? (
          <p style={{ textAlign: "center", marginTop: "100px", fontSize: "1rem" }}>
            Loading Weekly Data...
          </p>
        ) : (
          <Bar data={chartData} options={options} />
        )}
      </div>

      <style>{`
        canvas {
          width: 100% !important;
          height: 100% !important;
        }
      `}</style>
    </div>
  );
}
