import './MitreHeatmap.css';

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Dev' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Esc' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Move' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command & Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

export default function MitreHeatmap({ coverage = {} }) {
  const tactics = Array.isArray(coverage.tactics) ? coverage.tactics : [];
  const tacticMap = {};
  tactics.forEach(t => { tacticMap[t.tactic_id || t.tactic] = t; });

  return (
    <div className="mitre-heatmap">
      <div className="heatmap-summary">
        <span className="hm-stat">{coverage.tactics_with_hits || 0}/{coverage.total_tactics || 14} tactics</span>
        <span className="hm-stat">{coverage.total_technique_hits || 0} technique hits</span>
        <span className="hm-stat">{coverage.overall_coverage_pct || 0}% coverage</span>
      </div>
      <div className="heatmap-grid">
        {TACTICS.map(tactic => {
          const data = tacticMap[tactic.id] || tacticMap[tactic.name];
          const pct = data?.coverage_pct || 0;
          const detected = data?.detected_techniques || 0;
          const total = data?.total_techniques || 0;
          const heat = pct > 50 ? 'heat-high' : pct > 0 ? 'heat-med' : 'heat-none';

          return (
            <div key={tactic.id} className={`heatmap-cell ${heat}`} title={`${tactic.name}: ${detected}/${total} techniques`}>
              <div className="hm-cell-name">{tactic.name}</div>
              <div className="hm-cell-id">{tactic.id}</div>
              <div className="hm-cell-stat">{detected}/{total}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
