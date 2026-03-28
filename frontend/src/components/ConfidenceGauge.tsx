import { useEffect, useState } from "react";
import { motion } from "motion/react";

interface ConfidenceGaugeProps {
  score: number;
}

function getScoreColor(score: number) {
  if (score <= 30) return { color: "var(--safe)", label: "Low Risk" };
  if (score <= 60) return { color: "var(--warning)", label: "Suspicious" };
  return { color: "var(--danger)", label: "High Risk" };
}

export default function ConfidenceGauge({ score }: ConfidenceGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);
  const { color, label } = getScoreColor(score);

  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset =
    circumference - (animatedScore / 100) * circumference * 0.75; // 270-degree arc

  useEffect(() => {
    const duration = 1200;
    const startTime = performance.now();
    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(score * eased));
      if (progress < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);
  }, [score]);

  return (
    <motion.div
      className="flex flex-col items-center"
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5, delay: 0.2 }}
    >
      <div className="relative w-52 h-52">
        <svg
          viewBox="0 0 200 200"
          className="w-full h-full -rotate-[135deg]"
        >
          {/* Background arc */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="currentColor"
            className="text-secondary"
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * 0.25}
            strokeLinecap="round"
          />
          {/* Score arc */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 8px ${color})`,
              transition: "stroke-dashoffset 0.1s linear",
            }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-heading text-5xl font-bold tabular-nums"
            style={{ color }}
          >
            {animatedScore}
          </span>
          <span className="text-muted-foreground text-xs font-mono mt-1">
            / 100
          </span>
        </div>
        {/* Glow effect */}
        <div
          className="absolute inset-4 rounded-full blur-3xl opacity-15 -z-10"
          style={{ backgroundColor: color }}
        />
      </div>
      <div className="mt-2 text-center">
        <p
          className="font-heading text-sm font-bold tracking-wider uppercase"
          style={{ color }}
        >
          {label}
        </p>
        <p className="text-muted-foreground text-xs mt-1">
          Phishing Likelihood
        </p>
      </div>
    </motion.div>
  );
}
