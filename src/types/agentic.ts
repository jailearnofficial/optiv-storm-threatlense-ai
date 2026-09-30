export interface AgentStep {
  step: number;
  agent: string;
  agentRole: string;
  phase: 'Decomposition' | 'Detonation' | 'Infrastructure Pivoting' | 'Adversary Mapping' | 'Containment Synthesis';
  thought: string;
  toolCall: {
    name: string;
    arguments: Record<string, any>;
  };
  observation: string;
  durationMs: number;
  timestamp: string;
}

export interface ContainmentAction {
  id: string;
  platform: 'Palo Alto Cortex XSOAR' | 'Microsoft Sentinel' | 'Splunk SOAR' | 'ServiceNow SIR';
  title: string;
  action: string;
  target: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  requiresAdmin: boolean;
  status: 'pending_approval' | 'executed' | 'rejected';
  payload: Record<string, any>;
}

export interface AgenticMissionResult {
  missionId: string;
  indicator: string;
  targetType: string;
  scenarioTitle: string;
  verdict: 'Malicious C2' | 'Ransomware Dropper' | 'Phishing Campaign' | 'Suspicious Anomaly';
  riskScore: number;
  confidence: number;
  threatActor?: string;
  malwareFamily?: string;
  summary: string;
  agents: Array<{
    name: string;
    role: string;
    avatar: string;
    status: 'idle' | 'active' | 'completed';
    actionsCount: number;
  }>;
  steps: AgentStep[];
  mitreMatrix: Array<{
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    evidence: string;
  }>;
  synthesizedRules: {
    sigmaRule: string;
    yaraRule: string;
  };
  containmentActions: ContainmentAction[];
  generatedAt: string;
}
