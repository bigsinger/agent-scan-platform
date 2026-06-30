(function () {
  function showBootError(message, detail) {
    const el = document.getElementById('boot-error');
    const msg = document.getElementById('boot-error-message');
    if (msg) msg.textContent = String(message || '') + (detail ? '\n' + String(detail) : '');
    if (el) el.classList.add('show');
  }
  window.addEventListener('error', event => showBootError(event.message, event.error && event.error.stack));
  window.addEventListener('unhandledrejection', event => showBootError('Unhandled Promise Rejection', event.reason && (event.reason.stack || event.reason.message || event.reason)));
  if (!window.Vue) {
    showBootError('Vue 未加载', '请确认 /static/vendor/vue.global.prod.js 存在并可访问。');
    return;
  }
  const seed = window.ASSESSMENT_SEED || {};
  try {
    const { createApp } = Vue;
    const prototypeApp = createApp({
data(){
    const initial = JSON.parse(JSON.stringify(seed));
    initial.form = Object.assign({adapter:'自动识别', targetPath:'', discoveryPaths:'', snapshotContent:''}, initial.form || {});
    initial.quickEstimate = Object.assign({configs:0, mcp_servers:0, skills:0, scan_files:0, agents:0, status:'未检查'}, initial.quickEstimate || {});
    initial.quickBusy = false;
    initial.uploadResult = null;
    initial.discoveryErrors = initial.discoveryErrors || [];
    initial.discoveryLog = initial.discoveryLog || [];
    initial.sqliteStatus = initial.sqliteStatus || {file_bytes:0, mode:'WAL', state:'未知', pragma:{}};
    initial.guardStatus = initial.guardStatus || {state:'NO_BASELINE', watched_files:0, open_recommendations:0, policy:{}};
    initial.quickModes = (initial.quickModes || []).filter(mode => mode.id !== 'fixture');
    initial.backupRecords = initial.backupRecords || [];
    initial.selectedReport = initial.selectedReport || ((initial.reports || [])[0]) || {};
    initial.reportPreviewData = initial.reportPreviewData || null;
    initial.opsBusy = false;
    return initial;
  },
  computed:{
    pageTitle(){
      const all=this.navGroups.flatMap(g=>g.items);
      const found=all.find(x=>x.key===this.current);
      if(found) return found.name;
      const extra={'agent-detail':'Agent 详情','task-detail':'任务详情','skill-detail':'Skill 详情','finding-detail':'风险详情'};
      return extra[this.current]||'Agent 安全测评';
    },
    pendingConsentCount(){
      return this.consents.filter(x=>x.status==='待审批').length;
    },
    p0Count(){
      return this.findings.filter(f=>String(f.severity||'').includes('P0') || String(f.severity||'').includes('严重')).length;
    },
    p1Count(){
      return this.findings.filter(f=>String(f.severity||'').includes('P1') || String(f.severity||'').includes('高危')).length;
    },
    runningTaskCount(){
      return this.tasks.filter(t=>['运行中','等待审批','排队中','RUNNING','WAITING_CONSENT','QUEUED'].includes(t.status) || t.stage==='WAITING_CONSENT').length;
    },
    sqliteMb(){
      const bytes=this.sqliteStatus && this.sqliteStatus.file_bytes || 0;
      return bytes ? (bytes/1024/1024).toFixed(bytes > 10485760 ? 0 : 1) : '0';
    },
    stdioMcpCount(){
      return this.mcpServers.filter(m=>m.transport==='stdio').length;
    },
    remoteMcpCount(){
      return this.mcpServers.filter(m=>m.transport && m.transport!=='stdio').length;
    },
    skillScriptCount(){
      return this.skills.reduce((sum,s)=>sum+(Number(s.scripts)||0),0);
    },
    highSkillCount(){
      return this.skills.filter(s=>['critical','high'].includes(s.riskClass)).length;
    },
    guardLastCheckDisplay(){
      const raw=this.guardStatus && this.guardStatus.last_check_at;
      if(!raw) return '未建立基线';
      const dt=new Date(raw);
      if(Number.isNaN(dt.getTime())) return String(raw).replace('T',' ').replace(/\.\d+Z?$/,'');
      return new Intl.DateTimeFormat('zh-CN', {year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'}).format(dt);
    },
    sqliteWalBusy(){
      const wal=this.sqliteStatus && this.sqliteStatus.wal_checkpoint || [];
      return wal[0] || 0;
    },
    sqliteWalFrames(){
      const wal=this.sqliteStatus && this.sqliteStatus.wal_checkpoint || [];
      return wal[1] || 0;
    },
    sqliteWalCheckpointed(){
      const wal=this.sqliteStatus && this.sqliteStatus.wal_checkpoint || [];
      return wal[2] || 0;
    },
    sqliteIntegrityDisplay(){
      return (this.sqliteStatus && this.sqliteStatus.integrity) || '未检查';
    }
  },
  mounted(){
    this.syncRouteFromLocation();
    window.addEventListener('popstate', this.syncRouteFromLocation);
    this.loadBootstrap();
  },
  beforeUnmount(){
    window.removeEventListener('popstate', this.syncRouteFromLocation);
  },
  methods:{
    routeForKey(key){
      const map={dashboard:'/assessment','quick-scan':'/assessment/quick-scan',create:'/assessment/new',discovery:'/assessment/discovery',agents:'/assessment/agents','agent-detail':'/assessment/agents/'+(this.selectedAsset&&this.selectedAsset.id||'agt_cc_001'),abom:'/assessment/abom',adapters:'/assessment/adapters',profiles:'/assessment/profiles','agent-scan':'/assessment/agent-scan',tasks:'/assessment/tasks','task-detail':'/assessment/tasks/'+(this.selectedTask&&this.selectedTask.id||'asm_v4_001'),mcp:'/assessment/mcp',consents:'/assessment/mcp-consent',skills:'/assessment/skills','skill-detail':'/assessment/skills/'+(this.selectedSkill&&this.selectedSkill.id||'skill_001'),redteam:'/assessment/redteam',cases:'/assessment/redteam-cases',execution:'/assessment/python-exec',sandbox:'/assessment/sandbox',findings:'/assessment/findings','finding-detail':'/assessment/findings/'+(this.selectedFinding&&this.selectedFinding.id||'fnd_001'),evidence:'/assessment/evidence','attack-paths':'/assessment/attack-paths',reports:'/assessment/reports',retests:'/assessment/retests',rules:'/assessment/rules',scanners:'/assessment/scanners',schedules:'/assessment/schedules',integrations:'/assessment/integrations',settings:'/assessment/settings',sqlite:'/assessment/sqlite',licenses:'/assessment/licenses',completeness:'/assessment/completeness'};
      return map[key]||'/assessment';
    },
    keyForPath(path){
      if(!path || path==='/' || path==='/assessment') return 'dashboard';
      const exact={'/assessment/quick-scan':'quick-scan','/assessment/new':'create','/assessment/discovery':'discovery','/assessment/agents':'agents','/assessment/abom':'abom','/assessment/adapters':'adapters','/assessment/profiles':'profiles','/assessment/agent-scan':'agent-scan','/assessment/tasks':'tasks','/assessment/mcp':'mcp','/assessment/mcp-consent':'consents','/assessment/consents':'consents','/assessment/skills':'skills','/assessment/redteam':'redteam','/assessment/redteam-cases':'cases','/assessment/cases':'cases','/assessment/python-exec':'execution','/assessment/execution':'execution','/assessment/sandbox':'sandbox','/assessment/findings':'findings','/assessment/evidence':'evidence','/assessment/attack-paths':'attack-paths','/assessment/reports':'reports','/assessment/retests':'retests','/assessment/rules':'rules','/assessment/scanners':'scanners','/assessment/schedules':'schedules','/assessment/integrations':'integrations','/assessment/settings':'settings','/assessment/sqlite':'sqlite','/assessment/licenses':'licenses','/assessment/completeness':'completeness','/assessment/embed-demo':'integrations','/assessment/api-debug':'completeness'};
      if(exact[path]) return exact[path];
      if(path.startsWith('/assessment/agents/')) return 'agent-detail';
      if(path.startsWith('/assessment/tasks/')) return 'task-detail';
      if(path.startsWith('/assessment/skills/')) return 'skill-detail';
      if(path.startsWith('/assessment/findings/')) return 'finding-detail';
      if(path.startsWith('/assessment/adapters/')) return 'adapters';
      if(path.startsWith('/assessment/agent-scan/issues')) return 'agent-scan';
      if(path.startsWith('/assessment/mcp/')) return 'mcp';
      if(path.startsWith('/assessment/tools/')) return 'mcp';
      if(path.startsWith('/assessment/redteam-cases/')) return 'cases';
      if(path.startsWith('/assessment/reports/')) return 'reports';
      if(path.startsWith('/assessment/profiles/')) return 'profiles';
      if(path.startsWith('/assessment/rules/')) return 'rules';
      if(path.startsWith('/assessment/scanners/')) return 'scanners';
      return 'dashboard';
    },
    pushRoute(key){
      if(location.protocol==='file:') { location.hash=this.routeForKey(key); return; }
      const target=this.routeForKey(key);
      if(location.pathname!==target) history.pushState({key},'',target);
    },
    syncRouteFromLocation(){
      const path=location.protocol==='file:' && location.hash ? location.hash.slice(1) : location.pathname;
      this.current=this.keyForPath(path);
    },
    async loadBootstrap(){
      try {
        const payload=await this.apiGet('/api/v1/bootstrap');
        if(payload && payload.state){
          Object.assign(this, payload.state);
          this.quickModes=(this.quickModes || []).filter(mode => mode.id !== 'fixture');
          if(this.quickMode==='fixture') this.quickMode='machine';
          this.syncRouteFromLocation();
        }
      } catch (err) {
        this.apiError='后端 API 暂不可用，当前显示本地种子数据。';
      }
    },
    async apiGet(path){ return this.apiRequest(path); },
    async apiPost(path, body){ return this.apiRequest(path, {method:'POST', body:JSON.stringify(body||{})}); },
    async apiPatch(path, body){ return this.apiRequest(path, {method:'PATCH', body:JSON.stringify(body||{})}); },
    async apiRequest(path, options){
      const res=await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}}, options||{}));
      const text=await res.text();
      const data=text ? JSON.parse(text) : {};
      if(!res.ok) throw data;
      return data;
    },
    describeError(err){ return err && err.error ? err.error.message+' · '+err.error.correlation_id : String(err && err.message || err || '未知错误'); },

    go(key){this.current=key;this.pushRoute(key);window.scrollTo({top:0,behavior:'smooth'});},
    toastMsg(msg){this.toast=msg;clearTimeout(this._toastTimer);this._toastTimer=setTimeout(()=>this.toast='',2400);},
    formatBytes(bytes){
      const value=Number(bytes)||0;
      if(value>=1024*1024*1024) return (value/1024/1024/1024).toFixed(1)+' GB';
      if(value>=1024*1024) return (value/1024/1024).toFixed(1)+' MB';
      if(value>=1024) return (value/1024).toFixed(1)+' KB';
      return value+' B';
    },
    statusClass(s){
      if(s==='已完成') return 'low';
      if(s==='COMPLETED'||s==='READY'||s==='ACTIVE') return 'low';
      if(s==='运行中'||s==='RENDERING') return 'blue';
      if(s==='RUNNING'||s==='WAITING_CONSENT'||s==='QUEUED') return 'blue';
      if(s==='等待审批'||s==='部分完成') return 'medium';
      if(s==='PENDING'||s==='OPEN') return 'medium';
      if(s==='失败'||s==='FAILED') return 'critical';
      return 'gray';
    },
    mergeRecords(key, items){
      if(!items || !items.length) return;
      const current=this[key]||[];
      const seen=new Set(items.map(x=>String(x.id||x.server||x.name)));
      this[key]=items.concat(current.filter(x=>!seen.has(String(x.id||x.server||x.name))));
    },
    mergeScanResponse(res){
      if(!res) return;
      if(res.discovery){
        this.mergeRecords('discoveryHits', res.discovery.hits);
        this.mergeRecords('agentAssets', res.discovery.agents);
        this.mergeRecords('mcpServers', res.discovery.mcp_servers);
        this.mergeRecords('consents', res.discovery.consents);
        this.mergeRecords('skills', res.discovery.skills);
        this.mergeRecords('discoveryErrors', res.discovery.errors);
      }
      this.mergeRecords('findings', res.findings);
      this.mergeRecords('evidenceItems', res.evidence);
      if(res.report) this.mergeRecords('reports', [res.report]);
      if(res.events && res.events.length) this.taskEvents=res.events.concat(this.taskEvents.filter(e=>!res.events.some(n=>n.seq===e.seq)));
      if(res.findings && res.findings.length) this.selectedFinding=res.findings[0];
      if(res.evidence && res.evidence.length) this.selectedEvidence=res.evidence[0];
      if(res.discovery && res.discovery.agents && res.discovery.agents.length) this.selectedAsset=res.discovery.agents[0];
      if(res.discovery && res.discovery.skills && res.discovery.skills.length) this.selectedSkill=res.discovery.skills[0];
    },
    quickPayload(){
      const payload={mode:this.quickMode, adapter:this.form.adapter || '自动识别'};
      const target=(this.form.targetPath || '').trim();
      if(target) payload.target_path=target;
      return payload;
    },
    quickAgent(a){
      this.form.adapter=a.adapter || a.name || '自动识别';
      const target=a.path || a.config_path || a.root || '';
      if(target){ this.form.targetPath=target; this.quickMode='path'; this.toastMsg('已选择 '+a.name+' 本机资产'); }
      else { this.quickMode='machine'; this.toastMsg('已选择 '+a.name+'，将扫描本机发现资产'); }
      this.current='quick-scan';
    },
    viewAdapter(a){this.toastMsg(a.name+' 适配器覆盖已定位');this.current='adapters';},
    async precheckQuickScan(){
      this.quickBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/quick-scans/precheck', this.quickPayload());
        this.quickEstimate=Object.assign({}, this.quickEstimate, res.precheck || {});
        this.toastMsg('预检完成：'+(this.quickEstimate.status || 'PASS')+'，可扫描文件 '+(this.quickEstimate.scan_files || 0));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.quickBusy=false; }
    },
    async uploadSnapshot(){
      this.quickBusy=true; this.apiError='';
      try {
        const content=(this.form.snapshotContent || '').trim() || JSON.stringify({target_path:this.form.targetPath || '', mode:this.quickMode, created_at:new Date().toISOString()}, null, 2);
        const res=await this.apiPost('/api/v1/uploads', {content, suffix:'json', kind:'quick-scan-snapshot'});
        this.uploadResult=res.artifact; this.toastMsg('快照已保存：'+res.artifact.id);
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.quickBusy=false; }
    },
    async startQuickScan(){
      this.quickBusy=true; this.apiError='';
      try {
        const res = await this.apiPost('/api/v1/quick-scans', this.quickPayload());
        this.mergeScanResponse(res);
        const t = res.assessment || Object.assign({}, this.tasks[0], {id:'asm_quick_'+Date.now(), name:'快速扫描 · '+this.quickMode, target:'本机/显式目标', progress:3, status:'运行中', stage:'PRECHECK', critical:0, high:0});
        this.mergeRecords('tasks', [t]); this.selectedTask=t; this.go('task-detail'); this.toastMsg('快速扫描已完成本地只读分析');
      } catch (err) { this.apiError = this.describeError(err); }
      finally { this.quickBusy=false; }
    },
    async runDiscovery(){
      if(this.discoveryRunning){ this.discoveryRunning=false; this.toastMsg('发现已停止并保留当前命中'); return; }
      this.discoveryRunning=true; this.apiError='';
      this.discoveryLog=['discovery.started scope=current-user'];
      this.toastMsg('本机发现已启动；不会启动 stdio MCP');
      try {
        const extra=(this.form.discoveryPaths || '').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
        const target=(this.form.targetPath || '').trim();
        const payload={scope:'current-user'};
        if(extra.length) payload.paths=extra;
        else if(target) payload.path=target;
        const res=await this.apiPost('/api/v1/discovery-runs', payload);
        this.mergeRecords('discoveryHits', res.hits);
        this.mergeRecords('agentAssets', res.agents);
        this.mergeRecords('mcpServers', res.mcp_servers);
        this.mergeRecords('consents', res.consents);
        this.mergeRecords('skills', res.skills);
        this.mergeRecords('discoveryErrors', res.errors);
        this.discoveryLog=[
          'discovery.completed run='+res.run.id,
          'agents='+(res.agents||[]).length+' hits='+(res.hits||[]).length+' mcp='+(res.mcp_servers||[]).length+' skills='+(res.skills||[]).length,
          ...((res.hits||[]).slice(0,8).map(x=>'hit '+x.type+' '+x.agent+' '+x.path))
        ];
        this.toastMsg('本机发现完成：'+((res.agents||[]).length)+' 个 Agent，'+((res.hits||[]).length)+' 个命中');
      } catch (err) { this.apiError = this.describeError(err); }
      finally { this.discoveryRunning=false; }
    },
    async runGuardCheck(){
      this.quickBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/guard/check', {});
        this.guardStatus=res.guard || this.guardStatus;
        this.mergeRecords('agentAssets', (res.discovery && res.discovery.agents) || []);
        this.mergeRecords('mcpServers', (res.discovery && res.discovery.mcp_servers) || []);
        this.mergeRecords('skills', (res.discovery && res.discovery.skills) || []);
        this.toastMsg('只读 Guard 检查完成：变化 '+((res.event&&res.event.changed)||0)+'，建议 '+((res.event&&res.event.recommendations)||0));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.quickBusy=false; }
    },
    async createRuntimeReport(){
      this.opsBusy=true; this.apiError='';
      try {
        const assessmentId=(this.selectedTask&&this.selectedTask.id) || ((this.tasks||[])[0] && this.tasks[0].id) || '';
        const res=await this.apiPost('/api/v1/reports', {assessment_id:assessmentId, type:'Standard'});
        if(res.report){
          this.mergeRecords('reports', [res.report]);
          await this.openReportPreview(res.report);
          this.toastMsg('本地 HTML/JSON 报告已生成：'+res.report.id);
        }
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async openReportPreview(report){
      if(!report || !report.id) return;
      this.selectedReport=report;
      this.reportPreview=true;
      try {
        const res=await this.apiGet('/api/v1/reports/'+encodeURIComponent(report.id));
        this.selectedReport=Object.assign({}, report, res.item || {});
        this.reportPreviewData=res.preview || null;
      } catch (err) { this.apiError=this.describeError(err); }
    },
    downloadReport(report){
      if(!report || !report.id) return;
      window.open('/api/v1/reports/'+encodeURIComponent(report.id)+'/download', '_blank', 'noopener');
      this.toastMsg('已请求下载本地 HTML 报告');
    },
    async syncReport(report){
      if(!report || !report.id) return;
      this.opsBusy=true; this.apiError='';
      try {
        await this.apiPost('/api/v1/integrations/runtime-platform/sync', {report_id:report.id});
        this.toastMsg('报告回写事件已写入本地审计');
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async acceptFinding(finding){
      if(!finding || !finding.id) return;
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/findings/'+encodeURIComponent(finding.id)+'/accept', {reason:'本地人工确认'});
        if(res.finding){ this.mergeRecords('findings', [res.finding]); this.selectedFinding=res.finding; }
        this.toastMsg('风险状态已写入：已接受风险');
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async retestFinding(finding){
      if(!finding || !finding.id) return;
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/findings/'+encodeURIComponent(finding.id)+'/retest', {scope:'固化输入'});
        if(res.retest){ this.mergeRecords('retests', [res.retest]); }
        this.go('retests');
        this.toastMsg('复测任务已排队：'+(res.retest&&res.retest.id || 'QUEUED'));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async redactEvidence(evidence){
      if(!evidence || !evidence.id) return;
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/evidence/'+encodeURIComponent(evidence.id)+'/redact', {});
        if(res.evidence){ this.mergeRecords('evidenceItems', [res.evidence]); this.selectedEvidence=res.evidence; }
        this.toastMsg('证据脱敏状态已刷新');
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async runSqliteBackup(){
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/sqlite/backup', {});
        if(res.backup){ this.mergeRecords('backupRecords', [res.backup]); }
        await this.refreshSqliteStatus();
        this.toastMsg('在线备份已创建：'+(res.backup&&res.backup.relative_path || '完成'));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async runSqliteIntegrity(){
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/sqlite/integrity-check', {});
        this.sqliteStatus=Object.assign({}, this.sqliteStatus, {integrity:res.integrity && res.integrity.status || 'UNKNOWN'});
        this.toastMsg('完整性检查：'+(res.integrity&&res.integrity.result || 'UNKNOWN'));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async runSqliteCheckpoint(){
      this.opsBusy=true; this.apiError='';
      try {
        await this.apiPost('/api/v1/sqlite/checkpoint', {});
        await this.refreshSqliteStatus();
        this.toastMsg('WAL Checkpoint 已完成');
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    async refreshSqliteStatus(){
      const res=await this.apiGet('/api/v1/sqlite/status');
      this.sqliteStatus=res;
    },
    async runScheduleNow(schedule){
      if(!schedule || !schedule.id) return;
      this.opsBusy=true; this.apiError='';
      try {
        const res=await this.apiPost('/api/v1/schedules/'+encodeURIComponent(schedule.id)+'/run-now', {});
        if(res.run){ this.mergeRecords('tasks', [res.run]); }
        this.toastMsg('计划已立即入队：'+(res.run&&res.run.id || schedule.id));
      } catch (err) { this.apiError=this.describeError(err); }
      finally { this.opsBusy=false; }
    },
    openAgent(a){this.selectedAsset=a;this.agentTab='概览';this.current='agent-detail';window.scrollTo(0,0);},
    openTask(t){this.selectedTask=t;this.taskTab='执行概览';this.current='task-detail';window.scrollTo(0,0);},
    openSkill(s){this.selectedSkill=s;this.skillTab='概览';this.current='skill-detail';window.scrollTo(0,0);},
    openFinding(f){this.selectedFinding=f;this.findingTab='概览';this.current='finding-detail';window.scrollTo(0,0);},
    async submitAssessment(){
      try {
        const res = await this.apiPost('/api/v1/assessments', {target_id:this.selectedAsset.id, target_path:this.form.targetPath, profile_id:'standard-complete@4.0.0'});
        this.mergeScanResponse(res);
        const t = res.assessment || Object.assign({}, this.tasks[0], {id:'asm_v4_'+Date.now(), name:'新建完整测评', progress:1, status:'运行中', stage:'PRECHECK'});
        this.mergeRecords('tasks', [t]);this.selectedTask=t;this.wizard=1;this.planConfirmed=false;this.go('task-detail');this.toastMsg('Assessment Plan 已固化并完成本地扫描');
      } catch (err) { this.apiError = this.describeError(err); }
    },
    async approveConsent(c,scope){
      c.status=scope==='once'?'允许一次':'本任务允许';
      try { await this.apiPost('/api/v1/consents/'+encodeURIComponent(c.id||c.server)+'/decision', {decision:c.status}); } catch (err) { this.apiError = this.describeError(err); }
      this.toastMsg(c.server+' 已批准；配置变化将要求重新审批');
    },
    async denyConsent(c){c.status='已拒绝';try { await this.apiPost('/api/v1/consents/'+encodeURIComponent(c.id||c.server)+'/decision', {decision:'DENIED'}); } catch (err) { this.apiError = this.describeError(err); } this.toastMsg(c.server+' 已拒绝，任务将标记部分完成');},
    async denyAllConsents(){this.consents.forEach(c=>{if(c.status==='待审批')c.status='已拒绝'});try { await this.apiPost('/api/v1/consents/bulk-decision', {decision:'DENIED'}); } catch (err) { this.apiError = this.describeError(err); } this.toastMsg('所有待审批 stdio Server 已拒绝');}
  }
    });
    prototypeApp.config.errorHandler = function(err){ showBootError('Vue 运行时错误', err && (err.stack || err.message || err)); console.error(err); };
    prototypeApp.mount('#app');
    const boot = document.getElementById('boot-status');
    if (boot) boot.remove();
  } catch (err) {
    showBootError('页面启动失败', err && (err.stack || err.message || err));
    console.error(err);
  }
})();
