import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import ScanPage from './pages/ScanPage';
import LiveScanPage from './pages/LiveScanPage';
import ResultsPage from './pages/ResultsPage';
import HistoryPage from './pages/HistoryPage';
import MitrePage from './pages/MitrePage';
import OwaspPage from './pages/OwaspPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="scan" element={<ScanPage />} />
          <Route path="scan/:id/live" element={<LiveScanPage />} />
          <Route path="scan/:id/results" element={<ResultsPage />} />
          <Route path="history" element={<HistoryPage />} />
          <Route path="mitre" element={<MitrePage />} />
          <Route path="owasp" element={<OwaspPage />} />
          {/* Fallback */}
          <Route path="*" element={<DashboardPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
