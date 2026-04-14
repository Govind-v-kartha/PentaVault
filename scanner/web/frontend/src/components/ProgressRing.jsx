import './ProgressRing.css';

export default function ProgressRing({ progress = 0, size = 160, strokeWidth = 10 }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (progress / 100) * circumference;
  const center = size / 2;

  return (
    <div className="progress-ring-wrap" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="progress-ring-svg">
        <defs>
          <linearGradient id="ringGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--pv-cyan)" />
            <stop offset="100%" stopColor="var(--pv-green)" />
          </linearGradient>
          <filter id="ringGlow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Track */}
        <circle
          cx={center} cy={center} r={radius}
          fill="none" stroke="rgba(26,37,54,0.5)"
          strokeWidth={strokeWidth}
        />
        {/* Progress */}
        <circle
          cx={center} cy={center} r={radius}
          fill="none" stroke="url(#ringGrad)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="progress-ring-value"
          filter="url(#ringGlow)"
          transform={`rotate(-90 ${center} ${center})`}
        />
      </svg>
      <div className="progress-ring-label">
        <span className="progress-ring-pct">{Math.round(progress)}</span>
        <span className="progress-ring-unit">%</span>
      </div>
    </div>
  );
}
