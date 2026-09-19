import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertOctagon, RefreshCw } from 'lucide-react';
import Navbar from '../components/Navbar.jsx';
import Sidebar from '../components/Sidebar.jsx';
import AgentHierarchyTree from '../components/AgentHierarchyTree.jsx';
import AuditLogTable from '../components/AuditLogTable.jsx';
import ApiKeyModal from '../components/ApiKeyModal.jsx';
import DelegationChainViewer from '../components/DelegationChainViewer.jsx';
import McpProxyLog from '../components/McpProxyLog.jsx';
import { apiService } from '../services/api.js';

const TOKEN_KEY = 'aiiam_operator_token';

export default function DashboardPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('agents');
  const [agents, setAgents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [mcpSessions, setMcpSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgentForModal, setSelectedAgentForModal] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState(null);
  const [operator, setOperator] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  // No mock fallback (Slice 16) — a failed fetch surfaces here instead
  // of silently rendering fabricated agents/audit rows. This is the
  // one thing an operator using this dashboard must never be misled
  // about: whether it's actually looking at real backend state.
  const [loadError, setLoadError] = useState(null);

  // Real logged-in operator identity (frontend overhaul) — replaces
  // the old hardcoded "admin@acmecorp.ai" Navbar text. Fetched once on
  // mount, independent of the per-tab data fetch below.
  useEffect(() => {
    apiService.getCurrentUser()
      .then(setOperator)
      .catch((err) => console.error('Failed to load operator identity:', err));
  }, []);

  // Dashboard reskin: same light console surface as the landing/login
  // pages, toggled the same way (see LandingPage.jsx/LoginPage.jsx).
  useEffect(() => {
    document.body.classList.add('on-light-surface');
    return () => document.body.classList.remove('on-light-surface');
  }, []);

  // Initial Data Fetch
  useEffect(() => {
    fetchDashboardData();
  }, [activeTab]);

  const fetchDashboardData = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      if (activeTab === 'agents' || activeTab === 'delegation') {
        const agentList = await apiService.getAgents();
        setAgents(agentList);
      }
      if (activeTab === 'audit') {
        const logs = await apiService.getAuditLogs();
        setAuditLogs(logs);
      }
      if (activeTab === 'mcp') {
        const sessions = await apiService.getMcpSessions();
        setMcpSessions(sessions);
      }
    } catch (err) {
      console.error('Failed to load data:', err);
      setLoadError(err.message || 'Failed to reach the AI-IAM backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenKeyModal = (agent) => {
    setSelectedAgentForModal(agent);
    setIsModalOpen(true);
  };

  const handleVerifyAuditChain = async () => {
    try {
      const report = await apiService.verifyAuditChain();
      setVerificationStatus(report);
    } catch (err) {
      console.error('Verification error:', err);
      setVerificationStatus(null);
      setLoadError(err.message || 'Failed to verify the audit chain.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem(TOKEN_KEY);
    navigate('/login', { replace: true });
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSidebarOpen(false); // close the mobile drawer on navigation
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Navbar
        onVerify={handleVerifyAuditChain}
        verificationStatus={verificationStatus}
        operator={operator}
        onLogout={handleLogout}
        onToggleSidebar={() => setSidebarOpen((v) => !v)}
      />

      <div className="flex flex-1 relative">
        <Sidebar
          activeTab={activeTab}
          onTabChange={handleTabChange}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        <main className="flex-1 p-4 md:p-8 max-w-[1400px] mx-auto w-full">
          {loading ? (
            <div className="flex justify-center items-center h-[60vh]">
              <div className="animate-pulse-glow text-xl text-brand-red">
                ⚡ Synchronizing with AI-IAM Governance Cluster...
              </div>
            </div>
          ) : loadError ? (
            <div
              className="glass-panel flex flex-col items-center gap-4 p-12 mt-8 border border-rose-300"
              role="alert"
            >
              <AlertOctagon size={40} className="text-rose-600" />
              <div className="text-lg font-semibold text-center" style={{ color: '#be123c' }}>
                Backend unreachable
              </div>
              <div className="font-mono text-sm text-text-muted text-center max-w-[48ch]">
                {loadError}
              </div>
              <button onClick={fetchDashboardData} className="btn-secondary flex items-center gap-2">
                <RefreshCw size={16} />
                <span>Retry</span>
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'agents' && (
                <AgentHierarchyTree
                  agents={agents}
                  onRefresh={fetchDashboardData}
                  onOpenKeyModal={handleOpenKeyModal}
                />
              )}

              {activeTab === 'delegation' && (
                <DelegationChainViewer agents={agents} />
              )}

              {activeTab === 'audit' && (
                <AuditLogTable logs={auditLogs} onRefresh={fetchDashboardData} />
              )}

              {activeTab === 'mcp' && (
                <McpProxyLog sessions={mcpSessions} onRefresh={fetchDashboardData} />
              )}
            </>
          )}
        </main>
      </div>

      {isModalOpen && selectedAgentForModal && (
        <ApiKeyModal
          agent={selectedAgentForModal}
          onClose={() => setIsModalOpen(false)}
        />
      )}
    </div>
  );
}
