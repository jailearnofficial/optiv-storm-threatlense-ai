import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import { BarChart3, PieChart as PieIcon, Activity, Calendar } from 'lucide-react';
import { AIAnalysisVerdict } from '../types/index.js';

interface ChartsPanelProps {
  analysis: AIAnalysisVerdict;
}

export const ChartsPanel: React.FC<ChartsPanelProps> = ({ analysis }) => {
  const chartData = analysis.chart_data;

  // Detections data
  const detections = (chartData?.detections || []).map((d) => ({
    name: d.provider.length > 12 ? d.provider.substring(0, 10) + '..' : d.provider,
    malicious: d.malicious,
    clean: Math.max(0, (d.total || 70) - d.malicious)
  }));

  // Score by provider for radar
  const scores = (chartData?.score_by_provider || []).map((s) => ({
    subject: s.provider,
    score: s.score,
    fullMark: 100
  }));

  // Provider Agreement counts for pie chart
  const stances = (analysis.provider_agreement || []).reduce(
    (acc, curr) => {
      acc[curr.stance] = (acc[curr.stance] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const pieData = [
    { name: 'Malicious', value: stances.malicious || 0, color: '#EF4444' },
    { name: 'Suspicious', value: stances.suspicious || 0, color: '#F59E0B' },
    { name: 'Clean', value: stances.clean || 0, color: '#10B981' },
    { name: 'No Data', value: stances.no_data || 0, color: '#64748B' }
  ].filter((p) => p.value > 0);

  // Timeline
  const timeline = chartData?.timeline || [];

  return (
    <div className="relative z-10 max-w-5xl mx-auto my-6 px-4">
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 md:p-6 backdrop-blur-md">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-6 flex items-center gap-2">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          Threat Intelligence Telemetry & Correlation Visualizations
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart 1: Detections by Provider */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
                Detections by Security Feed
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Malicious vs Clean</span>
            </div>

            <div className="h-56 w-full">
              {detections.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={detections} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                    <XAxis
                      dataKey="name"
                      tick={{ fill: '#94A3B8', fontSize: 10 }}
                      interval={0}
                      angle={-20}
                      textAnchor="end"
                    />
                    <YAxis tick={{ fill: '#94A3B8', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '11px'
                      }}
                    />
                    <Bar dataKey="malicious" stackId="a" fill="#EF4444" name="Malicious" radius={[2, 2, 0, 0]} />
                    <Bar dataKey="clean" stackId="a" fill="#1E293B" name="Clean / Undetected" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-500">
                  No detection metrics available
                </div>
              )}
            </div>
          </div>

          {/* Chart 2: Provider Agreement Distribution */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <PieIcon className="w-3.5 h-3.5 text-violet-400" />
                Provider Consensus & Stance
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Agreement ratio</span>
            </div>

            <div className="h-56 w-full flex items-center justify-center">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={75}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '11px'
                      }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                      formatter={(val) => <span className="text-slate-300">{val}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-500">
                  Consensus pending
                </div>
              )}
            </div>
          </div>

          {/* Chart 3: Radar Score by Provider */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                Threat Contribution Radar (0-100)
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Weighted Risk</span>
            </div>

            <div className="h-56 w-full">
              {scores.length >= 3 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart cx="50%" cy="50%" outerRadius={70} data={scores}>
                    <PolarGrid stroke="#334155" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 9 }} />
                    <Radar name="Risk Score" dataKey="score" stroke="#22D3EE" fill="#22D3EE" fillOpacity={0.4} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '11px'
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-xs text-slate-500 gap-1">
                  <span>Score breakdown requires 3+ feeds</span>
                  <span className="font-mono text-cyan-400">{scores.length} active feeds</span>
                </div>
              )}
            </div>
          </div>

          {/* Chart 4: Timeline / Incident Telemetry */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-amber-400" />
                Indicator Timeline & First Seen
              </span>
              <span className="text-[10px] text-slate-500 font-mono">Chronological</span>
            </div>

            <div className="h-56 w-full overflow-y-auto pr-1 divide-y divide-slate-800/60 space-y-2">
              {timeline.length > 0 ? (
                timeline.map((item, i) => (
                  <div key={i} className="pt-2 flex items-start gap-3 text-xs">
                    <span className="text-[10px] font-mono text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 shrink-0">
                      {item.date}
                    </span>
                    <span className="text-slate-300 font-sans">{item.event}</span>
                  </div>
                ))
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-500">
                  No chronological events recorded
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
