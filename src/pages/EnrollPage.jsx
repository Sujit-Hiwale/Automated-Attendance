import { useEffect, useRef, useState } from "react";
import axios from "axios";
import "./EnrollPage.css";

export default function EnrollPage() {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const [capturedImage, setCapturedImage] = useState(null);
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [mobile, setMobile] = useState("");
  const [email, setEmail] = useState("");
  const [faces, setFaces] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    // Start webcam
    navigator.mediaDevices.getUserMedia({ video: true }).then((stream) => {
      if (videoRef.current) videoRef.current.srcObject = stream;
    });
  }, []);

  useEffect(() => {
    let isProcessing = false;

    const processFrame = async () => {
      if (!videoRef.current || videoRef.current.readyState !== 4 || isProcessing) {
        requestAnimationFrame(processFrame);
        return;
      }

      isProcessing = true;
      const canvas = canvasRef.current;
      const ctx = canvas.getContext("2d");
      canvas.width = videoRef.current.videoWidth;
      canvas.height = videoRef.current.videoHeight;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);

      const imageData = canvas.toDataURL("image/jpeg");

      try {
        const res = await axios.post("https://automated-attendance-6rl6.onrender.com/recognize", { image: imageData });
        setFaces(res.data.faces);

        ctx.lineWidth = 3;
        ctx.font = "18px Arial";
        ctx.textBaseline = "top";

        res.data.faces.forEach((face, index) => {
          const [x, y, w, h] = face.bbox;
          const color = `hsl(${(Date.now() / 10 + index * 60) % 360}, 100%, 50%)`;
          ctx.strokeStyle = color;
          ctx.strokeRect(x, y, w, h);
          ctx.fillStyle = "#fff";
          ctx.shadowColor = color;
          ctx.shadowBlur = 10;
          ctx.fillText(face.name, x, y - 22 < 0 ? y + 5 : y - 22);
        });
      } catch (err) {
        console.log("Recognition error:", err);
      }

      isProcessing = false;
      requestAnimationFrame(processFrame);
    };

    requestAnimationFrame(processFrame);

    return () => {
      isProcessing = true; // stop processing when component unmounts
    };
  }, []);

  const capturePhoto = () => {
    const canvas = document.createElement("canvas");
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(videoRef.current, 0, 0, canvas.width, canvas.height);
    setCapturedImage(canvas.toDataURL("image/jpeg"));
    setStep(1);
  };

  const retakePhoto = () => {
    setCapturedImage(null);
    setStep(0);
    setName("");
    setMobile("");
    setEmail("");
    setError("");
  };

  const submitEnrollment = async () => {
    try {
      const res = await axios.post("https://automated-attendance-6rl6.onrender.com/enroll", {
        name,
        mobile: mobile || null,
        email: email || null,
        image: capturedImage,
      });

      if (res.data.student_exists) {
        setError(res.data.message);
      } else {
        alert(res.data.message);
        retakePhoto();
      }
    } catch (err) {
      console.log(err);
      setError(err.response?.data?.error || "Enrollment failed");
    }
  };

  return (
    <div className="enroll-container">
      {!capturedImage && (
        <>
          <div className="feeds-wrapper">
            <div className="camera-feed">
              <video ref={videoRef} autoPlay playsInline className="camera-video" />
              <canvas ref={canvasRef} className="camera-overlay-canvas" />
              <p className="feed-label">Camera Feed</p>
            </div>

            <div className="camera-feed">
              <canvas ref={canvasRef} className="camera-canvas" />
              <p className="feed-label">Processed Feed</p>
            </div>
          </div>

          <button className="capture-btn" onClick={capturePhoto}></button>
        </>
      )}

      {capturedImage && step === 1 && (
        <div className="capture-preview">
          <img src={capturedImage} alt="captured" className="preview-image" />
          <input
            type="text"
            placeholder="Enter Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="input-field"
          />
          <div className="btn-group">
            <button className="btn retake" onClick={retakePhoto}>Retake</button>
            <button className="btn next" onClick={() => setStep(2)} disabled={!name.trim()}>Next</button>
          </div>
        </div>
      )}

      {capturedImage && step === 2 && (
        <div className="capture-preview">
          <img src={capturedImage} alt="captured" className="preview-image" />
          <input
            type="text"
            placeholder="Mobile (optional)"
            value={mobile}
            onChange={(e) => setMobile(e.target.value)}
            className="input-field"
          />
          <input
            type="email"
            placeholder="Email (optional)"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input-field"
          />
          {error && <p className="error-msg">{error}</p>}
          <div className="btn-group">
            <button className="btn retake" onClick={retakePhoto}>Retake</button>
            <button className="btn confirm" onClick={submitEnrollment} disabled={!name.trim()}>Confirm</button>
          </div>
        </div>
      )}
    </div>
  );
}
