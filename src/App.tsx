import React, { useState, useEffect } from 'react';
import { GoogleGenAI, Type, Schema } from '@google/genai';
import { 
  ShieldAlert, ShieldCheck, Activity, Terminal, AlertTriangle, 
  Info, CheckCircle, Crosshair, FileText, ChevronRight, Play, Loader2,
  LayoutDashboard, PieChart as PieChartIcon,
  Globe, Plus, Trash2, Search, Filter, Clock,
  Bell, Settings, Mail, Smartphone, X, Users, UserCheck,
  Network, Flame, History, Volume2, FileDown
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend 
} from 'recharts';
import { motion, AnimatePresence } from 'motion/react';

// Initialize Gemini API
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// System Instruction based on user's prompt
const SOC_SYSTEM_INSTRUCTION = `
You are "AI SOC Analyst", an advanced Autonomous Security Operations Center (SOC) AI system.

Your role is to continuously analyze cybersecurity logs in real-time and detect potential security threats, anomalies, and attacks. You act like a senior SOC analyst combined with a machine learning detection engine and a security explanation assistant.

🧠 CORE OBJECTIVE

You must:
Analyze incoming logs from: Server logs, Firewall logs, API request logs, Authentication/login logs, Network traffic events
Detect security threats such as: Brute force login attacks, DDoS, Phishing attempts, Unauthorized access, Suspicious IP behavior, API abuse, Intrusion attempts.
Classify each event into: NORMAL, LOW RISK, MEDIUM RISK, HIGH RISK, CRITICAL ATTACK

🧪 DETECTION INTELLIGENCE RULES
Apply reasoning similar to anomaly detection systems:
- Repeated login attempts from same IP → brute force suspicion
- High request rate in short time → DDoS / bot attack
- Login from unusual country/IP → suspicious access
- Failed login spikes → credential stuffing attack
- Multiple endpoint scanning → intrusion attempt
- API key misuse or repeated 401/403 → abuse detection
- UBA Deviation → If a user deviates from their established baseline (e.g., active during off-hours, accessing unusual endpoints, logging in from unusual locations), flag as potential compromised account or insider threat.

🧾 OUTPUT FORMAT
You must return your response strictly matching the requested JSON schema. Do not include markdown formatting or extra text outside the JSON.

🧑‍🏫 EXPLANATION LAYER (VERY IMPORTANT)
1. Simple Explanation: Human Friendly, use plain English OR Roman Urdu (e.g. "Ye IP bar bar login try kar raha hai, ye brute force attack ho sakta hai")
2. Technical Explanation: Explain like a SOC engineer mentioning patterns, thresholds, anomaly signals.
`;

const RESPONSE_SCHEMA: Schema = {
  type: Type.OBJECT,
  properties: {
    event_summary: { type: Type.STRING, description: "One sentence summary of the event" },
    risk_level: { type: Type.STRING, enum: ["NORMAL", "LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL ATTACK"], description: "Assigned risk level string" },
    attack_type: { type: Type.STRING, description: "Type of attack or 'None'" },
    detected_indicators: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Specific IOCs or anomalies detected" },
    evidence: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Lines or data points from the log that serve as evidence" },
    explanation_simple: { type: Type.STRING, description: "Explanation in plain English or Roman Urdu for laymen" },
    explanation_technical: { type: Type.STRING, description: "Deep technical explanation for SOC engineers" },
    recommended_actions: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Actionable steps to mitigate or investigate" },
    confidence_score: { type: Type.NUMBER, description: "Confidence in the assessment from 0.0 to 1.0" }
  },
  required: ["event_summary", "risk_level", "attack_type", "detected_indicators", "evidence", "explanation_simple", "explanation_technical", "recommended_actions", "confidence_score"]
};

// Correlation Engine Prompt
const CORRELATION_SYSTEM_INSTRUCTION = `
You are an AI SOC Correlation Engine.
Your objective is to analyze a chronological sequence of security events and identify complex, multi-stage attack campaigns. 
Individual events might seem low or medium risk, but when correlated (e.g., failed logins followed by a successful login from the same IP, then access to unusual endpoints), they represent a critical incident.

Analyze the provided JSON list of events. Group related events into incidents. If no events are correlated to form a multi-stage attack, return an empty incidents list.
`;

const CORRELATION_SCHEMA: Schema = {
  type: Type.OBJECT,
  properties: {
    incidents: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          incident_summary: { type: Type.STRING, description: "Short summary of the multi-stage incident" },
          severity: { type: Type.STRING, enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], description: "Overall incident severity" },
          attack_campaign: { type: Type.STRING, description: "Name/Type of the attack campaign (e.g., 'Compromised Account via Brute Force')" },
          correlated_event_ids: { type: Type.ARRAY, items: { type: Type.STRING }, description: "IDs of the events forming this incident" },
          explanation: { type: Type.STRING, description: "Detailed narrative explaining the attack timeline and logic" },
          recommended_actions: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Mitigation steps" }
        },
        required: ["incident_summary", "severity", "attack_campaign", "correlated_event_ids", "explanation", "recommended_actions"]
      }
    }
  },
  required: ["incidents"]
};

type AnalysisResult = {
  event_summary: string;
  risk_level: "NORMAL" | "LOW RISK" | "MEDIUM RISK" | "HIGH RISK" | "CRITICAL ATTACK";
  attack_type: string;
  detected_indicators: string[];
  evidence: string[];
  explanation_simple: string;
  explanation_technical: string;
  recommended_actions: string[];
  confidence_score: number;
};

type HistoryItem = AnalysisResult & {
  id: string;
  timestamp: number;
};

type ToastData = {
  id: string;
  title: string;
  message: string;
  type: 'critical' | 'info';
};

const PRESET_LOGS = [
  {
    label: "Failed Logins (Brute Force)",
    content: "IP: 192.168.1.10\nEvent: login_failed\nCount: 45 attempts in 2 minutes\nLocation: unknown\nUser: admin\nTimestamp: 2023-11-01T23:45:12Z"
  },
  {
    label: "High Traffic (DDoS)",
    content: "Timestamp: 2023-10-27T10:00:00Z\nEndpoint: /api/v1/data\nSource IP: Multiple (200+ unique IPs)\nRequest Rate: 5000 req/sec\nResponse: 503 Service Unavailable\nUser-Agent: Unknown/Bot"
  },
  {
    label: "Normal Access",
    content: "Timestamp: 2023-10-27T10:05:00Z\nEvent: user_login\nSource IP: 10.0.0.5\nUser: j.doe\nStatus: Success\nDevice: Mac OS Chrome"
  },
  {
    label: "Directory Traversal",
    content: "10.0.0.21 - - [14/May/2024:13:55:36 -0700] \"GET /../../../../etc/passwd HTTP/1.1\" 403 232 \"-\" \"curl/7.68.0\""
  },
  {
    label: "UBA Anomaly",
    content: "Timestamp: 2023-11-20T03:15:00Z\nEvent: user_login\nSource IP: 203.0.113.50\nLocation: RU\nUser: j.doe\nEndpoint: /admin/config"
  }
];

export default function App() {
  const [logInput, setLogInput] = useState(PRESET_LOGS[0].content);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [view, setView] = useState<'analyzer' | 'dashboard' | 'threat-intel' | 'settings' | 'uba' | 'correlation'>('analyzer');
  
  const injectSimulatedAttack = () => {
    const time = Date.now();
    const newEvents: HistoryItem[] = [
      {
        id: `ms-3`,
        timestamp: time,
        event_summary: "Data Exfiltration Attempt to unusual IP",
        risk_level: "HIGH RISK",
        attack_type: "Exfiltration",
        detected_indicators: ["Large outbound transfer to unknown IP from db-server"],
        evidence: ["492MB transferred to 203.0.113.100"], explanation_simple: "Kafi data unknown IP par transfer hua hai", explanation_technical: "High volume outbound traffic detected from internal server to external unverified IP address.", recommended_actions: ["Block IP immediately", "Check for data leak"], confidence_score: 0.95
      },
       {
        id: `ms-2`,
        timestamp: time - 60000,
        event_summary: "Successful Admin Login from unusual location",
        risk_level: "MEDIUM RISK",
        attack_type: "Anomalous Login",
        detected_indicators: ["Login success from RU for user 'admin'"],
        evidence: ["User admin logged in from RU"], explanation_simple: "Admin pass theek diya gaya, lekin location ajeeb hai.", explanation_technical: "Successful authentication for privileged account from an IP geolocated in an unusual region.", recommended_actions: ["Force password reset", "Require 2FA"], confidence_score: 0.88
      },
      {
        id: `ms-1`,
        timestamp: time - 300000,
        event_summary: "Multiple failed login attempts",
        risk_level: "LOW RISK",
        attack_type: "Brute Force",
        detected_indicators: ["50 failed logins from 203.0.113.100"],
        evidence: ["Failed password for admin from 203.0.113.100"], explanation_simple: "Bohat se login fail hue hain.", explanation_technical: "Brute force attack detected against admin account from external IP.", recommended_actions: ["Implement rate limiting", "Block IP"], confidence_score: 0.90
      }
    ];
    setHistory(prev => [...newEvents, ...prev]);
    addToast({ title: 'Simulated Attack Injected', message: 'Added 3 related events to history.', type: 'info' });
  };

  const [ubaProfiles, setUbaProfiles] = useState<{ id: string, user: string, location: string, hours: string, endpoints: string }[]>([
    { id: '1', user: 'admin', location: 'Internal Network', hours: '09:00-17:00 EST', endpoints: 'ALL' },
    { id: '2', user: 'j.doe', location: 'US, UK', hours: '08:00-18:00 PST', endpoints: '/api/v1/data, /portal' },
  ]);

  const [alertSettings, setAlertSettings] = useState({
    inApp: true,
    email: false,
    sms: false,
    voice: true,
    emailAddress: '',
    phoneNumber: ''
  });
  const [toasts, setToasts] = useState<ToastData[]>([]);

  const addToast = (toast: Omit<ToastData, 'id'>) => {
    const id = Date.now().toString();
    setToasts(prev => [...prev, { ...toast, id }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 5000);
  };

  const speakAlert = (message: string) => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance(message);
      utterance.rate = 1.0;
      utterance.pitch = 1.0;
      window.speechSynthesis.speak(utterance);
    }
  };

  const [osintList, setOsintList] = useState<{ id: string, indicator: string, type: string, description: string }[]>([
    { id: '1', indicator: '192.168.1.10', type: 'IP', description: 'Known Brute Force Origin' },
    { id: '2', indicator: '10.0.0.21', type: 'IP', description: 'Public Blocklist - Directory Scanner' },
    { id: '3', indicator: 'malicious-domain.com', type: 'Domain', description: 'Known Phishing Domain' },
  ]);
  const [newOsintIndicator, setNewOsintIndicator] = useState('');
  const [newOsintDescription, setNewOsintDescription] = useState('');
  const [newOsintType, setNewOsintType] = useState('IP');

  const riskData = [
    { name: 'NORMAL', value: history.filter(r => r.risk_level === 'NORMAL').length, color: '#10b981' },
    { name: 'LOW RISK', value: history.filter(r => r.risk_level === 'LOW RISK').length, color: '#3b82f6' },
    { name: 'MEDIUM RISK', value: history.filter(r => r.risk_level === 'MEDIUM RISK').length, color: '#eab308' },
    { name: 'HIGH RISK', value: history.filter(r => r.risk_level === 'HIGH RISK').length, color: '#f97316' },
    { name: 'CRITICAL', value: history.filter(r => r.risk_level === 'CRITICAL ATTACK').length, color: '#ef4444' },
  ].filter(d => d.value > 0);

  const threatData = history.reduce((acc, curr) => {
    const type = curr.attack_type === 'None' || !curr.attack_type ? 'Normal' : curr.attack_type;
    const existing = acc.find(item => item.name === type);
    if (existing) {
      existing.value += 1;
    } else {
      acc.push({ name: type, value: 1 });
    }
    return acc;
  }, [] as { name: string, value: number }[]);

  const handleAnalyze = async () => {
    if (!logInput.trim()) return;
    
    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const osintContext = osintList.length > 0 
        ? `\n\n=== EXTERNAL THREAT INTELLIGENCE (OSINT) ===\nThe following indicators are currently flagged as MALICIOUS in our simulated OSINT feeds. Use this data to cross-reference the logs and enrich your analysis (increase risk levels if matched):\n${osintList.map(o => `- ${o.type}: ${o.indicator} (${o.description})`).join('\n')}`
        : '';

      const ubaContext = ubaProfiles.length > 0
        ? `\n\n=== USER BEHAVIOR ANALYTICS (UBA) CONTEXT ===\nThese are the established baselines for known users. Deviations from these baselines (off-hours, unusual locations/endpoints) indicate potentially compromised accounts or insider threats:\n${ubaProfiles.map(p => `- User: ${p.user} | Location: ${p.location} | Active Hours: ${p.hours} | Typical Endpoints: ${p.endpoints}`).join('\n')}`
        : '';

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash', // Fast and good for structured extraction
        contents: `Please analyze the following log:\n\n${logInput}${osintContext}${ubaContext}`,
        config: {
          systemInstruction: SOC_SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          responseSchema: RESPONSE_SCHEMA,
          temperature: 0.1, // Low temperature for consistent classification
        }
      });

      if (response.text) {
        const parsed = JSON.parse(response.text) as AnalysisResult;
        setResult(parsed);
        setHistory(prev => [{
          ...parsed,
          id: `${Date.now()}-${Math.random()}`,
          timestamp: Date.now()
        }, ...prev]);

        if (parsed.risk_level === 'CRITICAL ATTACK' || parsed.risk_level === 'HIGH RISK') {
          if (alertSettings.inApp) {
            addToast({
              title: `${parsed.risk_level} DETECTED`,
              message: parsed.event_summary,
              type: 'critical'
            });
          }
          if (alertSettings.voice) {
            speakAlert(`Warning. ${parsed.risk_level} detected. Attack type: ${parsed.attack_type}. Immediate action recommended.`);
          }
          if (alertSettings.email && alertSettings.emailAddress) {
            console.log(`[Simulation] Sending Email to ${alertSettings.emailAddress}: CRITICAL THREAT - ${parsed.event_summary}`);
          }
          if (alertSettings.sms && alertSettings.phoneNumber) {
            console.log(`[Simulation] Sending SMS to ${alertSettings.phoneNumber}: CRITICAL THREAT - ${parsed.event_summary}`);
          }
        }
      } else {
        throw new Error("Empty response from AI");
      }
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : "An unknown error occurred during analysis.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 font-sans selection:bg-emerald-500/30">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20">
              <ShieldAlert className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="font-display font-bold text-lg text-slate-100 tracking-tight">AI SOC Analyst</h1>
              <p className="text-xs text-slate-400 font-mono hidden sm:block">Autonomous Threat Detection Engine</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4 bg-slate-950 p-1 rounded-lg border border-slate-800 overflow-x-auto">
            <button 
              onClick={() => setView('analyzer')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'analyzer' ? 'bg-slate-800 text-emerald-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <Terminal className="w-4 h-4" />
              <span className="hidden sm:inline">Analyzer</span>
            </button>
            <button 
              onClick={() => setView('dashboard')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'dashboard' ? 'bg-slate-800 text-emerald-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span className="hidden sm:inline">Dashboard</span>
            </button>
            <button 
              onClick={() => setView('correlation')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'correlation' ? 'bg-slate-800 text-rose-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <Network className="w-4 h-4" />
              <span className="hidden sm:inline">Correlation Engine</span>
            </button>
            <button 
              onClick={() => setView('threat-intel')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'threat-intel' ? 'bg-slate-800 text-purple-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <Globe className="w-4 h-4" />
              <span className="hidden sm:inline">Threat Intel</span>
            </button>
            <button 
              onClick={() => setView('uba')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'uba' ? 'bg-slate-800 text-teal-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <Users className="w-4 h-4" />
              <span className="hidden sm:inline">UBA Profiles</span>
            </button>
            <button 
              onClick={() => setView('settings')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap \${view === 'settings' ? 'bg-slate-800 text-yellow-400' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
            >
              <Settings className="w-4 h-4" />
              <span className="hidden sm:inline">Settings</span>
            </button>
          </div>

          <div className="hidden md:flex items-center gap-2">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-xs font-mono text-emerald-400 font-medium">SYSTEM ONLINE</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 md:px-6 py-8">
        {view === 'dashboard' ? (
          <DashboardView history={history} riskData={riskData} threatData={threatData} />
        ) : view === 'threat-intel' ? (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-display font-semibold text-slate-100 flex items-center gap-2">
                  <Globe className="w-5 h-5 text-purple-400" />
                  External Threat Intelligence
                </h2>
                <p className="text-sm text-slate-400 mt-1">
                  Manage known malicious IPs and domains. These are checked during log analysis to increase detection accuracy.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Add New Indicator */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg h-fit">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Plus className="w-4 h-4 text-emerald-400" />
                  Add Custom Indicator
                </h3>
                <form className="space-y-4" onSubmit={(e) => {
                  e.preventDefault();
                  if (!newOsintIndicator.trim() || !newOsintDescription.trim()) return;
                  setOsintList(prev => [{
                    id: Date.now().toString(),
                    indicator: newOsintIndicator.trim(),
                    type: newOsintType,
                    description: newOsintDescription.trim()
                  }, ...prev]);
                  setNewOsintIndicator('');
                  setNewOsintDescription('');
                }}>
                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Indicator Type</label>
                    <select
                      value={newOsintType}
                      onChange={(e) => setNewOsintType(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50"
                    >
                      <option value="IP">IP Address</option>
                      <option value="Domain">Domain Name</option>
                      <option value="URL">URL</option>
                      <option value="Hash">File Hash</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Value (e.g., 8.8.8.8)</label>
                    <input
                      type="text"
                      required
                      value={newOsintIndicator}
                      onChange={(e) => setNewOsintIndicator(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50"
                      placeholder="Enter indicator value..."
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Description / Source</label>
                    <input
                      type="text"
                      required
                      value={newOsintDescription}
                      onChange={(e) => setNewOsintDescription(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50"
                      placeholder="e.g., Simulated Botnet Feed"
                    />
                  </div>
                  <button
                    type="submit"
                    className="w-full bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 border border-purple-500/30 font-semibold py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-colors focus:ring-2 focus:ring-purple-500/50 focus:outline-none"
                  >
                    <Plus className="w-4 h-4" />
                    Add indicator
                  </button>
                </form>
              </div>

              {/* List of Indicators */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider p-5 border-b border-slate-800 flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-red-400" />
                    Active OSINT Feed
                  </span>
                  <span className="bg-slate-800 px-2 py-1 rounded text-xs font-mono text-slate-400">
                    {osintList.length} Entries
                  </span>
                </h3>
                 <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm whitespace-nowrap">
                    <thead className="text-xs text-slate-500 uppercase bg-slate-800/30 border-b border-slate-800 font-mono">
                      <tr>
                        <th className="px-5 py-3">Type</th>
                        <th className="px-5 py-3">Indicator</th>
                        <th className="px-5 py-3">Description</th>
                        <th className="px-5 py-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {osintList.length > 0 ? (
                        osintList.map((item) => (
                          <tr key={item.id} className="hover:bg-slate-800/20 transition-colors">
                            <td className="px-5 py-4">
                              <span className="px-2 py-1 rounded text-xs font-mono font-medium border border-slate-700 bg-slate-800/50 text-slate-300">
                                {item.type}
                              </span>
                            </td>
                            <td className="px-5 py-4 font-mono text-purple-400 font-medium">
                              {item.indicator}
                            </td>
                            <td className="px-5 py-4 text-slate-400">
                              {item.description}
                            </td>
                            <td className="px-5 py-4 text-right">
                              <button 
                                onClick={() => setOsintList(prev => prev.filter(o => o.id !== item.id))}
                                className="text-slate-500 hover:text-red-400 transition-colors p-1"
                                title="Remove Indicator"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={4} className="px-5 py-8 text-center text-slate-500 font-mono text-sm border-2 border-dashed border-slate-800/50 m-4 rounded-lg">
                            No threat indicators configured.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        ) : view === 'uba' ? (
          <UBAView ubaProfiles={ubaProfiles} setUbaProfiles={setUbaProfiles} />
        ) : view === 'correlation' ? (
          <CorrelationView history={history} addToast={addToast} injectSimulatedAttack={injectSimulatedAttack} speakAlert={speakAlert} alertSettings={alertSettings} />
        ) : view === 'settings' ? (
          <SettingsView alertSettings={alertSettings} setAlertSettings={setAlertSettings} addToast={addToast} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            
            {/* Left Column: Input */}
            <section className="lg:col-span-5 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
            <div className="bg-slate-800/50 border-b border-slate-800 px-4 py-3 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-200 uppercase tracking-wider">
                <Terminal className="w-4 h-4 text-slate-400" />
                Raw Log Intake
              </h2>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex flex-wrap gap-2">
                {PRESET_LOGS.map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => setLogInput(preset.content)}
                    className="text-xs px-3 py-1.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors border border-slate-700 font-medium"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <textarea
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                className="w-full h-64 bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-sm text-emerald-400/90 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500/50 resize-none"
                placeholder="Paste server logs, firewall events, or JSON snippets here..."
                spellCheck={false}
              />
              <button
                onClick={handleAnalyze}
                disabled={isAnalyzing || !logInput.trim()}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 px-4 rounded-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(16,185,129,0.15)] focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 focus:ring-offset-slate-900"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Analyzing Payload...
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5 fill-current" />
                    Process Logs
                  </>
                )}
              </button>
            </div>
          </div>
          
          {error && (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-semibold text-red-400">Analysis Failed</h4>
                <p className="text-xs text-red-300 mt-1">{error}</p>
              </div>
            </div>
          )}
        </section>

        {/* Right Column: Output */}
        <section className="lg:col-span-7">
          <AnimatePresence mode="wait">
            {!result && !isAnalyzing ? (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full min-h-[400px] flex flex-col items-center justify-center text-center p-8 border-2 border-dashed border-slate-800 rounded-xl"
              >
                <div className="w-16 h-16 bg-slate-900 rounded-full flex items-center justify-center mb-4 border border-slate-800">
                  <Activity className="w-8 h-8 text-slate-500" />
                </div>
                <h3 className="font-display font-semibold text-lg text-slate-300 mb-2">Awaiting Input</h3>
                <p className="text-slate-500 text-sm max-w-sm">
                  Paste logs in the intake terminal and run the analysis to generate an autonomous SOC report.
                </p>
              </motion.div>
            ) : isAnalyzing ? (
               <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="h-full min-h-[400px] flex flex-col items-center justify-center p-8 border border-slate-800 bg-slate-900/20 rounded-xl"
                >
                  <div className="relative">
                    <div className="w-24 h-24 border-4 border-slate-800 border-t-emerald-500 rounded-full animate-spin"></div>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <ShieldAlert className="w-8 h-8 text-emerald-500 animate-pulse" />
                    </div>
                  </div>
                  <h3 className="font-mono font-medium text-emerald-400 mt-6 tracking-widest uppercase text-sm">Running ML Detection Engine</h3>
                  <div className="w-48 h-1 bg-slate-800 mt-4 rounded-full overflow-hidden">
                    <div className="h-full bg-emerald-500 animate-[pulse_1s_ease-in-out_infinite] w-full origin-left"></div>
                  </div>
               </motion.div>
            ) : result ? (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-6"
              >
                {/* Risk Banner */}
                <RiskBanner result={result} />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Indicators */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                      <Crosshair className="w-4 h-4 text-purple-400" />
                      Detected Indicators
                    </h3>
                    <ul className="space-y-2">
                      {result.detected_indicators.map((ind, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                          <ChevronRight className="w-4 h-4 text-purple-500 shrink-0 mt-0.5" />
                          <span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Settings / Score */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col">
                     <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                      <Activity className="w-4 h-4 text-blue-400" />
                      Confidence Score
                    </h3>
                    <div className="flex-1 flex flex-col items-center justify-center">
                      <div className="relative w-32 h-32 flex items-center justify-center">
                         <svg className="w-full h-full transform -rotate-90">
                           <circle cx="64" cy="64" r="56" className="stroke-slate-800" strokeWidth="8" fill="none" />
                           <circle 
                            cx="64" cy="64" r="56" 
                            className="stroke-blue-500 transition-all duration-1000 ease-out" 
                            strokeWidth="8" 
                            fill="none" 
                            strokeDasharray="351.85" 
                            strokeDashoffset={351.85 - (351.85 * result.confidence_score)} 
                            strokeLinecap="round" 
                          />
                         </svg>
                         <div className="absolute inset-0 flex flex-col items-center justify-center">
                           <span className="text-3xl font-display font-bold text-white">{(result.confidence_score * 100).toFixed(0)}%</span>
                         </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Explanations */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                   <div className="border-b border-slate-800 p-4 bg-slate-800/20">
                     <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider">
                      <Info className="w-4 h-4 text-emerald-400" />
                      Analysis & Context
                     </h3>
                   </div>
                   <div className="p-5 space-y-6">
                      <div>
                        <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">Human Friendly (Roman Urdu / English)</h4>
                        <div className="bg-emerald-500/5 border border-emerald-500/10 p-3 rounded-lg text-sm text-emerald-100/80 italic border-l-2 border-l-emerald-500">
                          "{result.explanation_simple}"
                        </div>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Technical SOC Explanation</h4>
                        <p className="text-sm text-slate-400 leading-relaxed font-mono">
                          {result.explanation_technical}
                        </p>
                      </div>
                   </div>
                </div>

                {/* Actions */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
                      <ShieldCheck className="w-4 h-4 text-cyan-400" />
                      Recommended Mitigation
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {result.recommended_actions.map((action, i) => (
                        <div key={i} className="flex items-start gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                           <CheckCircle className="w-5 h-5 text-emerald-500 shrink-0" />
                           <span className="text-sm text-slate-300">{action}</span>
                        </div>
                      ))}
                    </div>
                </div>

              </motion.div>
            ) : null}
          </AnimatePresence>
            </section>
          </div>
        )}
      </main>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
        <AnimatePresence>
          {toasts.map(toast => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className={`min-w-[300px] border rounded-lg p-4 shadow-xl flex items-start gap-3 relative overflow-hidden backdrop-blur-md ${
                toast.type === 'critical' 
                  ? 'bg-red-500/10 border-red-500/50 text-red-100 shadow-[0_0_30px_rgba(239,68,68,0.2)]'
                  : 'bg-emerald-500/10 border-emerald-500/50 text-emerald-100'
              }`}
            >
              <div className={`absolute left-0 top-0 bottom-0 w-1 ${toast.type === 'critical' ? 'bg-red-500' : 'bg-emerald-500'}`} />
              {toast.type === 'critical' ? (
                <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
              ) : (
                <Info className="w-5 h-5 text-emerald-500 shrink-0 mt-0.5" />
              )}
              <div className="flex-1">
                <h4 className="text-sm font-bold uppercase tracking-wider mb-1">{toast.title}</h4>
                <p className="text-xs opacity-90">{toast.message}</p>
              </div>
              <button onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))} className="text-white/50 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

    </div>
  );
}

// Dashboard component
function DashboardView({ history, riskData, threatData }: { history: HistoryItem[], riskData: any[], threatData: any[] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [timeFilter, setTimeFilter] = useState('ALL');

  const uniqueAttackTypes = Array.from(new Set(history.map(h => h.attack_type))).filter(Boolean);

  const filteredHistory = history.filter(item => {
    if (searchTerm && !item.event_summary.toLowerCase().includes(searchTerm.toLowerCase()) && !item.attack_type.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    if (riskFilter !== 'ALL' && item.risk_level !== riskFilter) return false;
    if (typeFilter !== 'ALL' && item.attack_type !== typeFilter) return false;
    if (timeFilter !== 'ALL') {
        const now = Date.now();
        if (timeFilter === '1H' && now - item.timestamp > 3600000) return false;
        if (timeFilter === '24H' && now - item.timestamp > 86400000) return false;
        if (timeFilter === '7D' && now - item.timestamp > 604800000) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border border-slate-800 rounded-xl p-5 bg-slate-900">
        <div className="flex flex-col items-center justify-center p-6 border border-slate-800 rounded-xl bg-slate-950/50 shadow-inner">
          <span className="text-5xl font-display font-bold text-emerald-400">{history.length}</span>
          <span className="text-xs text-slate-400 uppercase tracking-widest mt-2 font-mono flex items-center gap-2">
            <Activity className="w-4 h-4" /> Total Events
          </span>
        </div>
        <div className="flex flex-col items-center justify-center p-6 border border-slate-800 rounded-xl bg-slate-950/50 shadow-inner">
          <span className="text-5xl font-display font-bold text-red-500">
            {history.filter(h => h.risk_level === 'CRITICAL ATTACK' || h.risk_level === 'HIGH RISK').length}
          </span>
          <span className="text-xs text-slate-400 uppercase tracking-widest mt-2 font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> High/Critical
          </span>
        </div>
        <div className="flex flex-col items-center justify-center p-6 border border-slate-800 rounded-xl bg-slate-950/50 shadow-inner">
          <span className="text-5xl font-display font-bold text-blue-500">
            {history.filter(h => h.risk_level === 'NORMAL' || h.risk_level === 'LOW RISK').length}
          </span>
          <span className="text-xs text-slate-400 uppercase tracking-widest mt-2 font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" /> Normal/Low
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg min-h-[350px] flex flex-col">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <PieChartIcon className="w-4 h-4 text-slate-400" />
            Risk Distribution
          </h3>
          <div className="flex-1">
            {riskData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie 
                    data={riskData} 
                    dataKey="value" 
                    nameKey="name" 
                    cx="50%" cy="50%" 
                    innerRadius={70} 
                    outerRadius={100} 
                    paddingAngle={3}
                  >
                    {riskData.map((entry, index) => (
                      <Cell key={`cell-\${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#020617', border: '1px solid #1e293b', borderRadius: '0.5rem' }} 
                    itemStyle={{ color: '#cbd5e1' }}
                  />
                  <Legend iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
               <div className="h-full flex items-center justify-center text-slate-500 text-sm font-mono flex-col gap-2">
                 <Terminal className="w-8 h-8 opacity-50" />
                 No events analyzed yet
               </div>
            )}
          </div>
        </div>
        
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg min-h-[350px] flex flex-col">
           <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
             <Crosshair className="w-4 h-4 text-purple-400" />
             Threat Vectors
           </h3>
           <div className="flex-1">
             {threatData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={threatData} layout="vertical" margin={{ top: 5, right: 30, left: 30, bottom: 5 }}>
                   <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                   <XAxis type="number" stroke="#64748b" tick={{fill: '#64748b', fontSize: 12}} />
                   <YAxis dataKey="name" type="category" stroke="#64748b" tick={{fill: '#64748b', fontSize: 12}} width={100} />
                   <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#020617', border: '1px solid #1e293b', borderRadius: '0.5rem' }}
                    cursor={{fill: '#0f172a'}}
                   />
                   <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                     {threatData.map((entry, index) => (
                        <Cell key={`cell-\${index}`} fill={entry.name === 'Normal' ? '#10b981' : '#ef4444'} />
                     ))}
                   </Bar>
                </BarChart>
              </ResponsiveContainer>
             ) : (
                <div className="h-full flex items-center justify-center text-slate-500 text-sm font-mono flex-col gap-2">
                 <ShieldCheck className="w-8 h-8 opacity-50" />
                 System operating normally
               </div>
             )}
           </div>
        </div>
      </div>
      
      {/* Event History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg overflow-hidden">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" />
            Event History Log
          </h3>
          
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <div className="relative flex-1 sm:w-48">
              <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input 
                type="text" 
                placeholder="Search logs..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-sm text-slate-200 focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 outline-none placeholder:text-slate-600"
              />
            </div>
            <select 
              value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:border-blue-500/50 outline-none flex-1 sm:flex-none max-w-[120px]"
            >
              <option value="ALL">All Risks</option>
              <option value="CRITICAL ATTACK">Critical</option>
              <option value="HIGH RISK">High</option>
              <option value="MEDIUM RISK">Medium</option>
              <option value="LOW RISK">Low</option>
              <option value="NORMAL">Normal</option>
            </select>
            <select 
              value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:border-blue-500/50 outline-none flex-1 sm:flex-none max-w-[120px]"
            >
              <option value="ALL">All Types</option>
              {uniqueAttackTypes.map((type, i) => <option key={i} value={type}>{type}</option>)}
            </select>
            <select 
              value={timeFilter} onChange={e => setTimeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:border-blue-500/50 outline-none flex-1 sm:flex-none max-w-[125px]"
            >
              <option value="ALL">All Time</option>
              <option value="1H">Last Hour</option>
              <option value="24H">Last 24h</option>
              <option value="7D">Last 7 Days</option>
            </select>
          </div>
        </div>

        {filteredHistory.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="text-xs text-slate-500 uppercase bg-slate-800/50 border-y border-slate-800 font-mono">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Threat Type</th>
                  <th className="px-4 py-3">Risk Level</th>
                  <th className="px-4 py-3">Summary</th>
                  <th className="px-4 py-3 text-right">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredHistory.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-400 text-xs">
                      {new Date(item.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">{item.attack_type}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-bold border border-current \${
                        item.risk_level === 'CRITICAL ATTACK' ? 'text-red-400 bg-red-400/10' :
                        item.risk_level === 'HIGH RISK' ? 'text-orange-400 bg-orange-400/10' :
                        item.risk_level === 'MEDIUM RISK' ? 'text-yellow-400 bg-yellow-400/10' :
                        item.risk_level === 'LOW RISK' ? 'text-blue-400 bg-blue-400/10' :
                        'text-emerald-400 bg-emerald-400/10'
                      }`}>
                        {item.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 truncate max-w-sm" title={item.event_summary}>
                      {item.event_summary}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-slate-500">
                      {(item.confidence_score * 100).toFixed(0)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-slate-500 text-sm font-mono border border-dashed border-slate-800 rounded-lg flex flex-col items-center justify-center gap-2">
            <Filter className="w-6 h-6 opacity-50 mb-2" />
            {history.length === 0 ? "No events logged" : "No events match the current filters"}
          </div>
        )}
      </div>
    </div>
  );
}

// Helper component for the Risk Banner
function SettingsView({ alertSettings, setAlertSettings, addToast }: { alertSettings: any, setAlertSettings: any, addToast: any }) {
  const [emailInput, setEmailInput] = useState(alertSettings.emailAddress);
  const [phoneInput, setPhoneInput] = useState(alertSettings.phoneNumber);

  const handleSave = () => {
    setAlertSettings({
      ...alertSettings,
      emailAddress: emailInput,
      phoneNumber: phoneInput
    });
    addToast({
      title: 'Settings Saved',
      message: 'Your notification preferences have been updated.',
      type: 'info'
    });
  };

  const handleTest = () => {
    if (alertSettings.inApp) {
      addToast({
        title: 'TEST CRITICAL ALERT',
        message: 'This is a test notification for a critical threat detection.',
        type: 'critical'
      });
    }
    if (alertSettings.voice) {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance("Warning. This is a test of the requested AI Voice Alert System. Immediate action recommended.");
        window.speechSynthesis.speak(utterance);
      }
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-3xl mx-auto">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-slate-100 flex items-center gap-2">
            <Bell className="w-5 h-5 text-yellow-400" />
            Alerts & Notifications
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Configure how you want to be notified when critical security threats are detected.
          </p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-6 space-y-8">
          
          {/* Voice Alerts */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-4 flex-1">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 shrink-0">
                <Volume2 className="w-6 h-6 text-purple-400" />
              </div>
              <div className="flex-1 max-w-md">
                <h3 className="font-semibold text-slate-200">AI Voice Alerts</h3>
                <p className="text-sm text-slate-400 mt-1 mb-3">
                  Uses text-to-speech to announce critical threats out loud in real-time, simulating a physical SOC environment.
                </p>
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer pt-2 shrink-0">
              <input type="checkbox" className="sr-only peer" checked={alertSettings.voice} onChange={e => setAlertSettings({...alertSettings, voice: e.target.checked})} />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-300 after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-500"></div>
            </label>
          </div>

          <hr className="border-slate-800" />

          {/* In-App Alerts */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-4">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 shrink-0">
                <LayoutDashboard className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <h3 className="font-semibold text-slate-200">In-App Notifications</h3>
                <p className="text-sm text-slate-400 mt-1">
                  Receive instant toast notifications across the dashboard when threats are detected.
                </p>
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer pt-2 shrink-0">
              <input type="checkbox" className="sr-only peer" checked={alertSettings.inApp} onChange={e => setAlertSettings({...alertSettings, inApp: e.target.checked})} />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-300 after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500"></div>
            </label>
          </div>

          <hr className="border-slate-800" />

          {/* Email Alerts */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-4 flex-1">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 shrink-0">
                <Mail className="w-6 h-6 text-blue-400" />
              </div>
              <div className="flex-1 max-w-md">
                <h3 className="font-semibold text-slate-200">Email Alerts</h3>
                <p className="text-sm text-slate-400 mt-1 mb-3">
                  Receive immediate critical threat summaries directly to your inbox.
                </p>
                {alertSettings.email && (
                  <input
                    type="email"
                    value={emailInput}
                    onChange={e => setEmailInput(e.target.value)}
                    placeholder="soc-team@company.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50"
                  />
                )}
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer pt-2 shrink-0">
              <input type="checkbox" className="sr-only peer" checked={alertSettings.email} onChange={e => setAlertSettings({...alertSettings, email: e.target.checked})} />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-300 after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-500"></div>
            </label>
          </div>

          <hr className="border-slate-800" />

          {/* SMS Alerts */}
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-4 flex-1">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 shrink-0">
                <Smartphone className="w-6 h-6 text-orange-400" />
              </div>
              <div className="flex-1 max-w-md">
                <h3 className="font-semibold text-slate-200">SMS / Text Message</h3>
                <p className="text-sm text-slate-400 mt-1 mb-3">
                  Critical escalation path. Sends a short SMS for immediate incident response.
                </p>
                {alertSettings.sms && (
                  <input
                    type="tel"
                    value={phoneInput}
                    onChange={e => setPhoneInput(e.target.value)}
                    placeholder="+1 (555) 000-0000"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/50"
                  />
                )}
              </div>
            </div>
            <label className="relative inline-flex items-center cursor-pointer pt-2 shrink-0">
              <input type="checkbox" className="sr-only peer" checked={alertSettings.sms} onChange={e => setAlertSettings({...alertSettings, sms: e.target.checked})} />
              <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-slate-300 after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-500"></div>
            </label>
          </div>
        </div>
        
        <div className="bg-slate-800/30 border-t border-slate-800 p-4 flex items-center justify-between">
          <button
            onClick={handleTest}
            className="px-4 py-2 text-sm font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-2"
          >
            <ShieldAlert className="w-4 h-4 text-red-400" />
            Trigger Test Alert
          </button>
          <button
            onClick={handleSave}
            className="px-6 py-2 text-sm font-medium text-emerald-950 bg-emerald-500 hover:bg-emerald-400 rounded-lg transition-colors shadow-[0_0_15px_rgba(16,185,129,0.2)]"
          >
            Save Preferences
          </button>
        </div>
      </div>
    </div>
  );
}

function UBAView({ ubaProfiles, setUbaProfiles }: { ubaProfiles: any[], setUbaProfiles: any }) {
  const [newUser, setNewUser] = useState('');
  const [newLocation, setNewLocation] = useState('');
  const [newHours, setNewHours] = useState('');
  const [newEndpoints, setNewEndpoints] = useState('');

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-5xl mx-auto">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-slate-100 flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-teal-400" />
            User Behavior Analytics (UBA)
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Establish baseline profiles for users. The AI SOC uses these baselines to detect compromised accounts and insider threats.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Add Profile */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg h-fit">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Plus className="w-4 h-4 text-teal-400" />
            Define New Baseline
          </h3>
          <form className="space-y-4" onSubmit={(e) => {
            e.preventDefault();
            if (!newUser.trim()) return;
            setUbaProfiles((prev: any[]) => [{
              id: Date.now().toString(),
              user: newUser.trim(),
              location: newLocation.trim() || 'Any',
              hours: newHours.trim() || '24/7',
              endpoints: newEndpoints.trim() || 'ALL'
            }, ...prev]);
            setNewUser(''); setNewLocation(''); setNewHours(''); setNewEndpoints('');
          }}>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Username / ID</label>
              <input required value={newUser} onChange={e => setNewUser(e.target.value)} type="text" placeholder="e.g., admin" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50" />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Typical Locations</label>
              <input value={newLocation} onChange={e => setNewLocation(e.target.value)} type="text" placeholder="e.g., US, UK, Office VPN" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50" />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Active Hours</label>
              <input value={newHours} onChange={e => setNewHours(e.target.value)} type="text" placeholder="e.g., 09:00-17:00 EST" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50" />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">Allowed Endpoints/Dirs</label>
              <input value={newEndpoints} onChange={e => setNewEndpoints(e.target.value)} type="text" placeholder="e.g., /api/v1, /dashboard" className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm text-slate-200 outline-none focus:border-teal-500/50 focus:ring-1 focus:ring-teal-500/50" />
            </div>
            <button type="submit" className="w-full bg-teal-600/20 hover:bg-teal-600/30 text-teal-400 border border-teal-500/30 font-semibold py-2 px-4 rounded-lg flex items-center justify-center gap-2 transition-colors focus:ring-2 focus:ring-teal-500/50 focus:outline-none">
              <Plus className="w-4 h-4" /> Save Profile
            </button>
          </form>
        </div>

        {/* List of Profiles */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider p-5 border-b border-slate-800 flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Users className="w-4 h-4 text-emerald-400" /> Active UBA Baselines
            </span>
            <span className="bg-slate-800 px-2 py-1 rounded text-xs font-mono text-slate-400">{ubaProfiles.length} Profiles</span>
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="text-xs text-slate-500 uppercase bg-slate-800/30 border-b border-slate-800 font-mono">
                <tr>
                  <th className="px-5 py-3">User</th>
                  <th className="px-5 py-3">Location</th>
                  <th className="px-5 py-3">Active Hours</th>
                  <th className="px-5 py-3">Endpoints</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {ubaProfiles.length > 0 ? ubaProfiles.map(p => (
                  <tr key={p.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="px-5 py-4 font-mono text-teal-400 font-medium">{p.user}</td>
                    <td className="px-5 py-4 text-slate-300">{p.location}</td>
                    <td className="px-5 py-4 text-slate-300">{p.hours}</td>
                    <td className="px-5 py-4 text-slate-400 max-w-[150px] truncate" title={p.endpoints}>{p.endpoints}</td>
                    <td className="px-5 py-4 text-right">
                      <button onClick={() => setUbaProfiles((prev: any[]) => prev.filter(o => o.id !== p.id))} className="text-slate-500 hover:text-red-400 p-1">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr><td colSpan={5} className="px-5 py-8 text-center text-slate-500 font-mono text-sm border-2 border-dashed border-slate-800/50 m-4 rounded-lg">No UBA profiles defined.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function CorrelationView({ history, addToast, injectSimulatedAttack, speakAlert, alertSettings }: { history: HistoryItem[], addToast: any, injectSimulatedAttack: any, speakAlert: any, alertSettings: any }) {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [isCorrelating, setIsCorrelating] = useState(false);

  const runCorrelation = async () => {
    if (history.length === 0) {
      addToast({ title: 'No Events', message: 'There are no events in history to correlate.', type: 'info' });
      return;
    }
    setIsCorrelating(true);
    try {
      const historyData = history.map(h => ({
        id: h.id,
        summary: h.event_summary,
        risk: h.risk_level,
        type: h.attack_type,
        indicators: h.detected_indicators,
        time: new Date(h.timestamp).toISOString()
      }));

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `Analyze these recent events and find any multi-stage correlated attacks:\n\n${JSON.stringify(historyData, null, 2)}`,
        config: {
          systemInstruction: CORRELATION_SYSTEM_INSTRUCTION,
          responseMimeType: "application/json",
          responseSchema: CORRELATION_SCHEMA,
          temperature: 0.1,
        }
      });

      if (response.text) {
        const parsed = JSON.parse(response.text);
        setIncidents(parsed.incidents || []);
        if (parsed.incidents?.length > 0) {
            addToast({ title: 'Correlation Complete', message: `Identified ${parsed.incidents.length} correlated incidents.`, type: 'critical' });
            if (alertSettings.voice) {
               speakAlert(`Emergency. Correlation engine detected ${parsed.incidents.length} multi-stage attack campaigns.`);
            }
        } else {
            addToast({ title: 'Correlation Complete', message: 'No correlated incidents detected.', type: 'info' });
        }
      }
    } catch (err) {
      console.error(err);
      addToast({ title: 'Correlation Failed', message: 'Failed to run correlation engine.', type: 'critical' });
    } finally {
      setIsCorrelating(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-5xl mx-auto">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-slate-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-rose-400" />
            AI Correlation Engine
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Analyze the event history chronologically to identify complex, multi-stage attack campaigns that span across individual, seemingly low-risk logs.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={injectSimulatedAttack}
            className="px-4 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-2"
          >
            <Flame className="w-4 h-4 text-orange-400" />
            Simulate Attack
          </button>
          <button
            onClick={runCorrelation}
            disabled={isCorrelating || history.length === 0}
            className="px-6 py-2 text-sm font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-all shadow-[0_0_15px_rgba(225,29,72,0.2)] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isCorrelating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {isCorrelating ? "Correlating Events..." : "Run Engine"}
          </button>
        </div>
      </div>

      {!incidents || incidents.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 bg-slate-950 rounded-full flex items-center justify-center mb-4 border border-slate-800 shadow-inner">
            <Network className="w-8 h-8 text-slate-500" />
          </div>
          <h3 className="font-display font-semibold text-lg text-slate-300 mb-2">No theats correlated yet</h3>
          <p className="text-slate-500 text-sm max-w-sm">
            Click 'Run Engine' to analyze your recent event history for complex multi-stage attack patterns.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {incidents.map((incident, i) => (
            <div key={i} className="bg-slate-900 border border-rose-500/30 rounded-xl shadow-[0_0_20px_rgba(225,29,72,0.05)] overflow-hidden">
              <div className="border-b border-rose-500/20 bg-rose-500/5 p-4 flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                <div>
                  <div className="flex items-center gap-3 mb-1">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 uppercase tracking-wider">
                      {incident.severity} SEVERITY
                    </span>
                    <span className="text-sm font-mono text-rose-300 uppercase tracking-widest flex items-center gap-1">
                      <Flame className="w-3 h-3" /> {incident.attack_campaign}
                    </span>
                  </div>
                  <h3 className="text-lg font-semibold text-slate-100">{incident.incident_summary}</h3>
                </div>
                <button
                  onClick={() => window.print()}
                  className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-2 self-start sm:self-center"
                >
                  <FileDown className="w-4 h-4 text-slate-400" />
                  Export PDF Report
                </button>
              </div>
              <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <History className="w-4 h-4 text-blue-400" /> Correlated Events Timeline
                  </h4>
                  <div className="space-y-4 relative border-l border-slate-800 ml-2 pl-4">
                    {incident.correlated_event_ids.map((id: string, idx: number) => {
                      const event = history.find(h => h.id === id);
                      return (
                        <div key={idx} className="relative">
                          <span className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-blue-500 ring-4 ring-slate-900 border border-slate-900"></span>
                          <span className="text-xs font-mono text-slate-500 block mb-0.5">
                             {event ? new Date(event.timestamp).toLocaleTimeString() : 'Unknown Event'}
                          </span>
                          <p className="text-sm text-slate-300 font-medium">
                            {event ? event.event_summary : `Event ID: ${id}`}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div className="space-y-6">
                  <div>
                    <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                      <Crosshair className="w-4 h-4 text-purple-400" /> Analysis Explanation
                    </h4>
                    <p className="text-sm text-slate-400 leading-relaxed">
                      {incident.explanation}
                    </p>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" /> Recommended Action
                    </h4>
                    <ul className="space-y-2">
                      {incident.recommended_actions.map((action: string, j: number) => (
                        <li key={j} className="flex items-start gap-2 text-sm text-emerald-300/80">
                          <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                          <span>{action}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Helper component for the Risk Banner
function RiskBanner({ result }: { result: AnalysisResult }) {
  const getRiskConfig = (level: AnalysisResult['risk_level']) => {
    switch (level) {
      case 'CRITICAL ATTACK':
        return {
          bg: 'bg-red-500/10',
          border: 'border-red-500/30',
          text: 'text-red-400',
          icon: <AlertTriangle className="w-8 h-8 text-red-500" />,
          glow: 'shadow-[0_0_40px_rgba(239,68,68,0.1)]'
        };
      case 'HIGH RISK':
        return {
          bg: 'bg-orange-500/10',
          border: 'border-orange-500/30',
          text: 'text-orange-400',
          icon: <AlertTriangle className="w-8 h-8 text-orange-500" />,
          glow: 'shadow-[0_0_30px_rgba(249,115,22,0.1)]'
        };
      case 'MEDIUM RISK':
        return {
          bg: 'bg-yellow-500/10',
          border: 'border-yellow-500/30',
          text: 'text-yellow-400',
          icon: <AlertTriangle className="w-8 h-8 text-yellow-500" />,
          glow: 'shadow-[0_0_20px_rgba(234,179,8,0.1)]'
        };
      case 'LOW RISK':
        return {
          bg: 'bg-blue-500/10',
          border: 'border-blue-500/30',
          text: 'text-blue-400',
          icon: <Info className="w-8 h-8 text-blue-500" />,
          glow: 'shadow-[0_0_20px_rgba(59,130,246,0.1)]'
        };
      case 'NORMAL':
        return {
          bg: 'bg-emerald-500/10',
          border: 'border-emerald-500/30',
          text: 'text-emerald-400',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-500" />,
          glow: 'shadow-[0_0_20px_rgba(16,185,129,0.1)]'
        };
      default:
        return { bg: 'bg-slate-800', border: 'border-slate-700', text: 'text-slate-400', icon: <Info /> };
    }
  };

  const config = getRiskConfig(result.risk_level);

  return (
    <div className={`rounded-xl border ${config.bg} ${config.border} p-6 flex flex-col sm:flex-row gap-6 items-start sm:items-center ${config.glow}`}>
      <div className="shrink-0 p-3 bg-slate-950/50 rounded-full border border-slate-800/50">
        {config.icon}
      </div>
      <div className="flex-1">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
          <div className="flex flex-wrap items-center gap-3">
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full uppercase tracking-wider border ${config.border} bg-slate-950/50 ${config.text}`}>
              {result.risk_level}
            </span>
            <span className="text-sm font-mono text-slate-400 uppercase tracking-widest border-l border-slate-700 pl-3">
              {result.attack_type.toUpperCase()}
            </span>
          </div>
          <button
            onClick={() => window.print()}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-2"
          >
            <FileDown className="w-4 h-4 text-slate-400" />
            Export PDF Report
          </button>
        </div>
        <h2 className="text-xl font-display font-semibold text-slate-100">
          {result.event_summary}
        </h2>
      </div>
    </div>
  );
}
