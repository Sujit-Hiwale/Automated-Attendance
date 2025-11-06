import { useEffect, useRef, useState } from "react";
import axios from "axios";

export default function HomePage() {
  const videoRef = useRef(null);
  const [detectedName, setDetectedName] = useState("");
  const [showNotification, setShowNotification] = useState(false);
  const isProcessingRef = useRef(false);
  const cooldownRef = useRef({});

  // Start webcam
  useEffect(() => {
    navigator.mediaDevices.getUserMedia({ video: true }).then(stream => {
      if (videoRef.current) videoRef.current.srcObject = stream;
      videoRef.current.play();
    });
  }, []);

  // Recognition loop
  useEffect(() => {
    const loop = async () => {
      if (!videoRef.current || videoRef.current.readyState !== 4) {
        requestAnimationFrame(loop);
        return;
      }

      if (showNotification || isProcessingRef.current) {
        requestAnimationFrame(loop);
        return;
      }

      isProcessingRef.current = true;

      const canvas = document.createElement("canvas");
      canvas.width = videoRef.current.videoWidth;
      canvas.height = videoRef.current.videoHeight;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);
      const imageData = canvas.toDataURL("image/jpeg");

      try {
        const res = await axios.post("https://automated-attendance-6rl6.onrender.com/recognize", { image: imageData });
        const faces = res.data.faces;

        if (faces.length > 0) {
          faces.forEach(face => {
            const name = face.name;
            if (name === "Unknown") return;

            const now = Date.now();
            const lastTime = cooldownRef.current[name] || 0;

            if (now - lastTime >= 2000) {
              cooldownRef.current[name] = now;

              videoRef.current.pause();
              setDetectedName(name);
              setShowNotification(true);

              setTimeout(() => {
                setShowNotification(false);
                videoRef.current.play();
              }, 1000);
            }
          });
        }
      } catch (err) {
        console.log("Recognition error:", err);
      }

      isProcessingRef.current = false;
      requestAnimationFrame(loop);
    };

    requestAnimationFrame(loop);
  }, [showNotification]);

  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        background: "linear-gradient(90deg, #0f172a, #1e3a8a, #312e81)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        overflow: "hidden",
        position: "relative",
      }}
    >
      <video
        ref={videoRef}
        autoPlay
        playsInline
        style={{
          width: "100%",
          height: "100%",
          objectFit: "contain",
          filter: "brightness(1.05) contrast(1.1)",
        }}
      />

      {showNotification && (
        <div
          style={{
            position: "absolute",
            top: "20%",
            left: "50%",
            transform: "translateX(-50%)",
            background: "rgba(0, 30, 0, 0.8)",
            color: "#39FF14",
            padding: "20px 50px",
            borderRadius: "16px",
            fontSize: "2.2rem",
            fontWeight: "bold",
            textShadow: "0 0 10px #39FF14, 0 0 20px #00FF66",
            boxShadow: "0 0 20px #00FF66",
            display: "flex",
            alignItems: "center",
            gap: "12px",
            animation: "fadeInOut 1s ease-in-out",
            border: "1px solid #00FF66",
          }}
        >
          <span>{detectedName}</span>
          <span>✔️</span>
        </div>
      )}

      <style>
        {`
          @keyframes fadeInOut {
            0% { opacity: 0; transform: translate(-50%, -20px); }
            15% { opacity: 1; transform: translate(-50%, 0); }
            85% { opacity: 1; transform: translate(-50%, 0); }
            100% { opacity: 0; transform: translate(-50%, -20px); }
          }
        `}
      </style>
    </div>
  );
}
