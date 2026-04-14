import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const SEVERITY_COLORS = {
  Critical: '#ff1a4a', High: '#ff6a30', Medium: '#f5a623', Low: '#00e87b', Info: '#4fa5ff', None: '#4fa5ff',
};

function severityRank(s) {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1, None: 0 }[s] || 0;
}

export default function OwaspBarChart({ findings = [] }) {
  const groups = {};
  findings.forEach(f => {
    const cat = f?.owasp_category || 'Uncategorized';
    if (!groups[cat]) groups[cat] = { category: cat, count: 0, maxSev: 'None' };
    groups[cat].count++;
    if (severityRank(f?.severity) > severityRank(groups[cat].maxSev)) {
      groups[cat].maxSev = f?.severity || 'None';
    }
  });

  const data = Object.values(groups)
    .sort((a, b) => b.count - a.count)
    .map(d => ({
      name: d.category.length > 28 ? d.category.slice(0, 25) + '…' : d.category,
      fullName: d.category,
      value: d.count,
      color: SEVERITY_COLORS[d.maxSev] || '#4fa5ff',
    }));

  if (!data.length) {
    return <div className="empty-state"><span className="empty-icon">📊</span><p>No OWASP data</p></div>;
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 36 + 40)}>
      <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 10, bottom: 10 }}>
        <XAxis type="number" hide />
        <YAxis
          type="category" dataKey="name" width={180}
          tick={{ fill: '#7e95b0', fontSize: 11, fontFamily: 'var(--font-mono)' }}
          axisLine={false} tickLine={false}
        />
        <Tooltip
          contentStyle={{
            background: 'rgba(10,15,26,0.95)',
            border: '1px solid rgba(26,37,54,0.8)',
            borderRadius: 10,
            color: '#c5d8f0',
            fontSize: 13,
          }}
          formatter={(value, name, props) => [`${value} findings`, props.payload.fullName]}
        />
        <Bar dataKey="value" radius={[0, 6, 6, 0]} animationDuration={600}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.color} fillOpacity={0.8} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
