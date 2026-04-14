import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const SEVERITY_COLORS = {
  Critical: '#ff1a4a',
  High: '#ff6a30',
  Medium: '#f5a623',
  Low: '#00e87b',
  Info: '#4fa5ff',
  None: '#4fa5ff',
};

const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export default function SeverityDonut({ findings = [] }) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach(f => {
    const sev = f?.severity || 'Info';
    if (counts[sev] != null) counts[sev]++;
    else counts.Info++;
  });

  const data = SEVERITY_ORDER
    .map(name => ({ name, value: counts[name] }))
    .filter(d => d.value > 0);

  if (!data.length) {
    return <div className="empty-state"><span className="empty-icon">🛡️</span><p>No findings</p></div>;
  }

  const total = findings.length;

  return (
    <div style={{ width: '100%', height: 240, position: 'relative' }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            cx="50%" cy="50%"
            innerRadius="55%"
            outerRadius="80%"
            paddingAngle={3}
            dataKey="value"
            animationBegin={0}
            animationDuration={800}
          >
            {data.map((d) => (
              <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} fillOpacity={0.9} stroke="none" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: 'rgba(10,15,26,0.95)',
              border: '1px solid rgba(26,37,54,0.8)',
              borderRadius: 10,
              color: '#c5d8f0',
              fontSize: 13,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        pointerEvents: 'none',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: '#e8f0fa' }}>
          {total}
        </span>
        <span style={{ fontSize: '0.7rem', color: '#7e95b0' }}>findings</span>
      </div>
    </div>
  );
}
