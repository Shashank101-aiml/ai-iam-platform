import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar.jsx';
import Sidebar from './components/Sidebar.jsx';
import AgentHierarchyTree from './components/AgentHierarchyTree.jsx';
import AuditLogTable from './components/AuditLogTable.jsx';
import ApiKeyModal from './components/ApiKeyModal.jsx';
import DelegationChainViewer from './components/DelegationChainViewer.jsx';
import McpProxyLog from './components/McpProxyLog.jsx';
import { apiService } from './services/api.js';

export default function App() {
  const [activeTab, setActiveTab] = useState('agents');
  const [agents, setAgents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [mcpSessions, setMcpSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgentForModal, setSelectedAgentForModal] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState(null);

  // Initial Data Fetch
  useEffect(() => {
    fetchDashboardData();
  }, [activeTab]);

  const fetchDashboardData = async () => {
    setLoading(true);
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
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Navbar onVerify={handleVerifyAuditChain} verificationStatus={verificationStatus} />
      
      <div style={{ display: 'flex', flex: 1 }}>
        <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

        <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', margin: '0 auto' }}>
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
              <div className="animate-pulse-glow" style={{ fontSize: '1.25rem', color: '#00f5ff' }}>
                ⚡ Synchronizing with AI-IAM Governance Cluster...
              </div>
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
