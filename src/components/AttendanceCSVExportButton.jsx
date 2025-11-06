import React from "react";
import axios from "axios";

export default function AttendanceCSVExportButton() {
  const handleExport = async () => {
    try {
      // 1️⃣ Fetch all attendance records from Flask
      const res = await axios.get("https://automated-attendance-6rl6.onrender.com/api/attendance-all", {
        withCredentials: false,
      });

      const records = res.data.records;

      if (!records || records.length === 0) {
        alert("No attendance records found!");
        return;
      }

      // 2️⃣ Convert to CSV format
      const headers = ["Name", "Date", "In Time", "Out Time"];
      const rows = records.map(
        (r) => `${r.student},${r.date},${r.intime},${r.outtime}`
      );

      const csvContent = [headers.join(","), ...rows].join("\n");

      // 3️⃣ Create a downloadable file
      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "attendance_records.csv");
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      alert("✅ Attendance exported successfully!");
    } catch (err) {
      console.error("Error exporting CSV:", err);
      alert("❌ Failed to export CSV.");
    }
  };

  return (
    <button
      onClick={handleExport}
      style={{
        background: "linear-gradient(90deg, #2563eb, #1e3a8a)",
        color: "white",
        padding: "12px 24px",
        borderRadius: "10px",
        border: "none",
        fontSize: "1rem",
        fontWeight: "600",
        cursor: "pointer",
        transition: "0.3s",
      }}
      onMouseOver={(e) => (e.target.style.background = "#1d4ed8")}
      onMouseOut={(e) =>
        (e.target.style.background = "linear-gradient(90deg, #2563eb, #1e3a8a)")
      }
    >
      📄 Export Attendance CSV
    </button>
  );
}
