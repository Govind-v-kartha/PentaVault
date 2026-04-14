import { useCallback, useEffect, useRef, useState } from 'react';
import { getScan, subscribeScanProgress } from '../api/client';

/**
 * Hook for real-time scan progress via SSE with polling fallback.
 * Returns scanData + connection status.
 */
export function useScanStream(scanId) {
  const [scanData, setScanData] = useState(null);
  const [connected, setConnected] = useState(false);
  const [liveFindings, setLiveFindings] = useState([]);
  const cleanupRef = useRef(null);
  const pollRef = useRef(null);

  const stopAll = useCallback(() => {
    cleanupRef.current?.();
    cleanupRef.current = null;
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => {
    if (!scanId) { setScanData(null); setLiveFindings([]); return; }

    // Try SSE first, fall back to polling
    let sseWorking = false;

    const unsub = subscribeScanProgress(scanId, {
      onProgress: (d) => {
        sseWorking = true;
        setConnected(true);
        setScanData(prev => ({
          ...prev,
          ...d,
          scan_id: scanId,
        }));
      },
      onStageComplete: (d) => {
        setScanData(prev => {
          const stages = [...(prev?.stages || [])];
          if (d.stage) stages.push(d.stage);
          return { ...prev, stages };
        });
      },
      onFinding: (d) => {
        if (d.finding) {
          setLiveFindings(prev => [...prev, d.finding]);
        }
      },
      onComplete: (d) => {
        setConnected(false);
        // Final fetch to get complete data
        getScan(scanId).then(full => setScanData(full)).catch(() => {});
      },
      onError: () => {
        setConnected(false);
        // SSE failed, start polling
        if (!sseWorking && !pollRef.current) {
          pollRef.current = setInterval(async () => {
            try {
              const data = await getScan(scanId);
              setScanData(data);
              if (data.findings) setLiveFindings(data.findings);
              if (data.status !== 'running') {
                clearInterval(pollRef.current);
                pollRef.current = null;
              }
            } catch (e) { /* retry */ }
          }, 1200);
        }
      },
    });

    cleanupRef.current = unsub;

    // Also do an initial fetch
    getScan(scanId).then(d => setScanData(d)).catch(() => {});

    return () => { stopAll(); };
  }, [scanId, stopAll]);

  return { scanData, connected, liveFindings };
}
