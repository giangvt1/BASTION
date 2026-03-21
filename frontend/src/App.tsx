import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Orchestrator from './pages/Orchestrator';
import SOCDashboard from './pages/SOCDashboard';
import Pipeline from './pages/Pipeline';
import Architecture from './pages/Architecture';
import Metrics from './pages/Metrics';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<SOCDashboard />} />
        <Route path="/orchestrator" element={<Orchestrator />} />
        <Route path="/pipeline" element={<Pipeline />} />
        <Route path="/architecture" element={<Architecture />} />
        <Route path="/metrics" element={<Metrics />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;