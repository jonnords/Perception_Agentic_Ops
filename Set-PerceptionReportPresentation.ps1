Set-StrictMode -Version Latest

function Set-PerceptionReportPresentation {
    param([Parameter(Mandatory)][string]$Html)

    if ($Html -notmatch '</head>') { throw 'Report HTML is missing its closing head element.' }
    $presentation = @'
<!-- perception-presentation:start -->
<style id="perception-report-theme">
  :root{color-scheme:light;--ink:#20344b;--muted:#56677d;--line:#dce4ee;--teal:#116f7a;--navy:#20344b;--blue:#1768b2;--paper:#fff;--panel:#fff;--bg:#f2f5fa;--canvas:#f2f5fa;--shadow:0 4px 18px #20344b05}
  html{scroll-behavior:auto;scroll-padding-top:16px}
  body{margin:0;background:radial-gradient(ellipse at 100% 0%,#e7eef9 0,transparent 600px),var(--canvas);color:var(--ink);font:14px/1.65 "Segoe UI",Arial,sans-serif;min-width:0}
  *,*::before,*::after{box-sizing:border-box}
  a{color:var(--teal)}button,input,select,textarea{font:inherit}
  :focus-visible{outline:3px solid #188c98;outline-offset:3px}
  h1,.hero h1{font-size:clamp(27px,2.5vw,36px);line-height:1.2;letter-spacing:-1px;margin:0 0 9px;color:var(--ink)}
  h2{font-size:21px;line-height:1.35;letter-spacing:-.5px;color:var(--ink)}
  h3{font-size:16px;color:var(--ink)}
  body>header,body>header.hero{padding:32px;background:linear-gradient(115deg,#eef4fc,#fff 65%,#eaf6f5);color:var(--ink);border-bottom:1px solid var(--line)}
  body>header>div,.hero-inner{max-width:1440px;margin:auto}
  header p,.hero-subtitle{color:var(--muted);font-size:14px;line-height:1.6}
  .hero-inner{align-items:center;flex-wrap:wrap;gap:16px}
  .environment-label{color:var(--teal)}
  .hero-meta{background:var(--canvas);border:1px solid var(--line);min-width:0;max-width:100%}
  .hero-meta span{color:var(--muted)}.hero-meta code{color:var(--ink)}
  main{width:100%;max-width:1560px;min-width:0;padding:30px 32px 48px;margin:auto}
  main>.top{padding:25px 28px;border:1px solid #d4e1ee;border-radius:16px;background:linear-gradient(110deg,#fff,#f1f7fe 70%,#eaf6f4);box-shadow:var(--shadow)}
  main>.top .muted{max-width:850px;font-size:13px;line-height:1.7}
  .eyebrow{color:#1768a0;font-size:10px;letter-spacing:.15em;font-weight:750}
  .snapshot{padding:15px 2px;font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}
  .perception-report-ready .layout{display:block}
  .perception-report-ready .layout>aside,.perception-report-ready .report-nav{display:none}
  .perception-report-nav{display:flex;flex-wrap:wrap;gap:5px;background:#172a43;border-bottom:1px solid #304863;padding:12px 24px}
  .perception-report-nav a{display:block;padding:8px 11px;border:1px solid transparent;border-radius:8px;color:#c8d7e9;text-decoration:none;font-size:11px}
  .perception-report-nav a:hover{background:#29435f;color:#fff}
  .perception-report-nav a[aria-current=page]{border-color:#4a7897;background:#264a64;color:#fff;font-weight:600;box-shadow:inset 0 -2px #71d7d2}
  .perception-report-nav a[aria-disabled=true]{color:#adbed3;cursor:default}
  .perception-embedded .perception-report-nav{display:none}
  .perception-report-ready .jump-nav a[data-perception-view]{display:none}
  .jump-nav{position:static;box-shadow:none;backdrop-filter:none;background:var(--paper)}
  .jump-nav div{flex-wrap:wrap;padding:8px 18px;max-width:1500px}
  .jump-nav a{color:var(--muted);font-size:12px}
  .panel,main>section,.card,.metric,.agent-card{border:1px solid var(--line);border-radius:14px;background:var(--paper);box-shadow:var(--shadow)}
  .panel,main>section{padding:26px}
  .panel>h2,main>section>h2{margin-bottom:10px}
  .panel>p,main>section>.intro{font-size:12px;line-height:1.8}
  .panel.hero{border-color:#c7dedf;background:linear-gradient(120deg,#eff8f6,#f9fbff);box-shadow:var(--shadow)}
  .cards{gap:14px}.card,.metric{position:relative;padding:20px;min-width:0;border-top:3px solid #729bbf}
  .card::before{display:none}
  .card strong,.card .value,.metric strong{font-size:32px;color:var(--ink);font-variant-numeric:tabular-nums;letter-spacing:-.8px}
  .metric .label,.card>span:first-child{font-size:11px;font-weight:600}
  .card span,.card .label{color:var(--muted)}
  .agent-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
  button,.button{border-radius:8px;transition:background .15s,border-color .15s}
  button:disabled{cursor:not-allowed}
  button:not(.source):not(.link):not(:disabled):hover{border-color:#73a4ca}
  #export{background:#1768b2;border-color:#1768b2;color:#fff;padding:10px 15px;font-size:12px;box-shadow:0 3px 9px #1768b21a}
  #export:hover{background:#12538e}
  input,select,textarea{max-width:100%;min-width:0;border:1px solid #b7c7da;border-radius:8px;background:#fff}
  .controls,.filters{gap:10px;padding:13px 15px;background:#eaf0f7;border:1px solid var(--line);border-radius:12px}.controls>*{min-width:0}
  .controls input,.filters input{min-width:0}
  .controls select{flex:0 1 220px}
  .scroll,.table-wrap,.sankey-wrap{max-width:100%;overflow-x:auto;border-radius:10px}
  th{background:#eef3f9;color:#4c637e;font-size:10px;font-weight:650;letter-spacing:.08em}
  th,td{border-color:var(--line);padding:13px 14px}
  tbody tr:hover{background:#f6f9fe}
  .pill,.chip,.run-tag{border-radius:6px;font-size:11px}
  .advisory,.note{line-height:1.8}
  .agent-card{overflow:hidden}.agent-card>summary{padding:20px}
  .agent-card[open]{border-color:#abc7df}
  .empty{padding:26px;border:1px dashed #b9cadb;border-radius:12px;background:#f7faff}
  dialog{border-radius:16px;box-shadow:0 24px 90px #14294240}
  .reader-head{background:#f5f8fd}.reader-body pre{border:1px solid var(--line);background:#f4f7fc;border-radius:10px}
  .loop-model-track{gap:16px}.loop-model-node{border-radius:12px;border-top-width:3px;background:#f5f8fd}
  .loop-model-node:not(:last-child)::after{right:-13px}
  .loop-coordination{border-radius:10px;border-color:#dcd5ec;background:#f5f2fb}
  .loop-feedback{border-color:#819bb3;color:#3d5873}
  .loop-model-validation{border:1px solid #dde6ef;border-radius:10px;background:#f4f7fc;line-height:1.8}
  .loop-model-change{border-radius:10px;background:#fafcff}
  .loop-playbook-grid{gap:14px;counter-reset:playbook}
  .loop-playbook{counter-increment:playbook;border-color:#d5e2ee;border-radius:13px;background:#fff;box-shadow:0 4px 12px #213b5605}
  .loop-playbook h3{display:flex;align-items:center;gap:10px;padding:18px 16px;background:#eaf2fc;color:#175488;font-size:17px;border-bottom:1px solid #d5e2ee}
  .loop-playbook h3::before{content:counter(playbook,decimal-leading-zero);font-size:10px;font-weight:700;color:#4e759b;letter-spacing:.05em}
  .loop-playbook:nth-child(even) h3{background:#eaf6f4;color:#206d66}.loop-playbook:last-child h3{background:#f1edfa;color:#684b8e}
  .loop-playbook-body{padding:18px}.loop-mapped-agent{box-shadow:0 2px 8px #213b5604}
  figure.loop-demo-sankey{border:1px solid #dfc387;border-top:4px solid #b58625}
  .loop-demo-banner{border-radius:8px;background:#fff4da;color:#745019;letter-spacing:.04em;font-size:11px}
  .loop-demo-scroll{border:1px solid #e1e8ee;border-radius:12px;background:linear-gradient(#fff,#fafcfe)}
  .loop-demo-response{border-radius:10px;background:#f5fafb}
  .session-link,.chip,.run-tag{color:#096a64;border-color:#badbd5;background:#f0f8f6}
  .chip.flag,.run-tag.flag{color:#8b5200;border-color:#e2b56f;background:#fff8e9}
  .pill.expected{color:white;background:var(--good)}
  .pill.review{color:white;background:var(--watch)}
  .pill.high-deviation{color:white;background:var(--bad)}
  .small,.muted,.intro{color:var(--muted)}
  p,li,td,.facts,.agent-summary{overflow-wrap:anywhere}
  @media(max-width:1100px){.agent-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
  @media(max-width:760px){
    body>header,body>header.hero{padding:20px 16px}
    main{padding:18px 16px 28px}h1,.hero h1{font-size:25px}
    main>.top{padding:20px;border-radius:13px}.controls,.filters{padding:11px}
    .perception-report-nav{padding:10px}.perception-report-nav a{padding:6px 8px}
    .agent-grid{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
    .panel,main>section{padding:16px}.card,.metric{padding:13px}
    .agent-stats{grid-template-columns:repeat(2,minmax(0,1fr))}
    .controls input,.controls select{flex:1 1 100%;width:100%}
  }
  @media(max-width:1100px){.loop-model-node:not(:last-child)::after{right:auto}}
  @media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;scroll-behavior:auto!important}}
  @media print{body{background:#fff}.perception-report-nav{display:none}.panel,main>section,.card,.metric{box-shadow:none}}
</style>
<script id="perception-report-navigation">
(() => {
  'use strict';
  if (window.parent !== window) document.documentElement.classList.add('perception-embedded');
  const views = [
    ['environment','Environment explorer','Perception-Live-Environment.html'],
    ['threat-protection','Operational Briefing','Perception-Threat-Protection.html'],
    ['assurance-freshness','Freshness & Run Quality','Perception-Assurance-Freshness.html'],
    ['operational-loops','Operational Loops & Outcomes','Perception-Operational-Loops.html'],
    ['agent-behavior','Agent Behavior Analysis','Perception-Agent-Behavior-Analysis.html'],
    ['systemic-threat-signals','Systemic Threat Signals','Perception-Systemic-Threat-Signals.html'],
    ['defender-investigations','Defender investigations','Perception-Defender-Investigations.html']
  ];
  const availableFiles = __PERCEPTION_AVAILABLE_REPORTS__;
  document.addEventListener('DOMContentLoaded', () => {
    const current = new URL(location.href);
    const offline = current.protocol === 'file:';
    const selected = views.find(([id,,file]) => current.pathname === '/' + id || current.pathname.endsWith('/' + file));
    const navigation = document.createElement('nav');
    navigation.className = 'perception-report-nav';
    navigation.setAttribute('aria-label','Workspace views');
    if (!offline) {
      const home = document.createElement('a');
      home.href = '/#view=overview';home.textContent = 'Workspace overview';home.dataset.perceptionView = 'overview';
      navigation.append(home);
    }
    for (const [id,title,file] of views) {
      const link = document.createElement('a');
      link.textContent = title;link.dataset.perceptionView = id;
      if (offline && !availableFiles.includes(file) && (!selected || selected[0] !== id)) {
        link.setAttribute('role','link');link.setAttribute('aria-disabled','true');
        link.textContent += ' (not generated)';link.title = 'Generate this report, then update saved report presentation.';
      } else link.href = offline ? file : '/#view=' + id;
      if (selected && selected[0] === id) link.setAttribute('aria-current','page');
      navigation.append(link);
    }
    for (const link of document.querySelectorAll('a[href]')) {
      const raw = link.getAttribute('href');
      if (!raw || raw.startsWith('#') || link.hasAttribute('download')) continue;
      const url = new URL(raw,document.baseURI);
      if (url.origin !== current.origin) continue;
      const view = views.find(([id,,file]) => url.pathname === '/' + id || url.pathname.endsWith('/' + file));
      const target = view || (url.pathname === '/' && !url.hash ? views[0] : null);
      if (target) {
        link.dataset.perceptionView = target[0];
        link.href = offline ? target[2] : '/#view=' + target[0];
      }
    }
    document.body.prepend(navigation);
    document.body.classList.add('perception-report-ready');
  });
})();
</script>
<!-- perception-presentation:end -->
'@
    if ($Html -match '<body class="perception-environment">') {
        $environmentTheme = @'
<style id="perception-environment-theme">
  .perception-environment{--ink:#24292f;--navy:#24292f;--muted:#4d5661;--line:#e0e8ee;--blue:#27313a;--cyan:#52b8b4;--canvas:#f6f7f9;--good:#237546;--bad:#aa3535}
  .perception-environment a,.perception-environment code{color:#27313a}
  body.perception-environment>header.hero{padding:38px 32px 32px;border-bottom:1px solid #dce9e8;background:radial-gradient(ellipse at 10% 0%,#dff3ee 0,transparent 55%),linear-gradient(115deg,#f5fbf9,#fff 70%,#f0f4fc)}
  .perception-environment .hero-inner{display:grid;grid-template-columns:minmax(0,1fr) minmax(240px,310px);gap:32px;max-width:1416px;align-items:center}
  .perception-environment .environment-label{padding:5px 10px;margin-bottom:14px;border:1px solid #c7e4db;border-radius:999px;background:#edf8f3;color:#236351;font-size:10px;letter-spacing:.12em}
  .perception-environment .status-dot{width:6px;height:6px;background:#218367;box-shadow:0 0 0 3px #d7eee3}
  .perception-environment .hero h1{max-width:820px;font-size:clamp(28px,3vw,38px);font-weight:700;line-height:1.15;letter-spacing:-1.1px}
  .perception-environment .hero-subtitle{max-width:650px;margin:14px 0 0;color:var(--muted);font-size:14px;line-height:1.75}
  .perception-environment .hero-meta{min-width:0;width:100%;gap:8px;padding:19px 21px;border:1px solid #dce7ea;border-radius:14px;background:#ffffffd9;box-shadow:0 6px 20px #17324606}
  .perception-environment .hero-meta span{font-size:10px;letter-spacing:.12em}
  .perception-environment .hero-meta strong{font-size:14px;font-variant-numeric:tabular-nums}
  .perception-environment .hero-meta code{font-size:11px;line-height:1.65}
  .perception-environment .environment-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}
  .perception-environment .environment-actions .button{display:inline-flex;align-items:center;justify-content:center;min-height:42px;padding:10px 16px;border:1px solid #ccdcd9;border-radius:9px;background:#fff;color:#323a41;font-size:13px;font-weight:600;text-decoration:none}
  .perception-environment .environment-actions .primary{border-color:#0f766e;background:#0f766e;color:#fff;box-shadow:0 3px 8px #0f766e18}
  .perception-environment .environment-actions .button:hover{border-color:#0f766e;background:#edf7f4}
  .perception-environment .environment-actions .primary:hover{background:#0c625c;color:#fff}
  .perception-environment .jump-nav{position:sticky;top:0;z-index:10;background:#fffffff2;border-bottom:1px solid var(--line)}
  .perception-environment .jump-nav div{max-width:1480px;padding:10px 28px;gap:6px;flex-wrap:nowrap;overflow-x:auto}
  .perception-environment .jump-nav a{padding:8px 12px;border-radius:8px;font-size:12px;font-weight:600}
  .perception-environment .jump-nav a:hover{background:#eaf5f2;color:#0f766e}
  .perception-environment main{max-width:1480px;padding:28px 32px 44px}
  .perception-environment .cards{gap:14px;margin-bottom:26px}
  .perception-environment .card{min-height:142px;padding:19px 20px;border:1px solid #e0e7ee;border-radius:14px;background:#fff;box-shadow:0 3px 10px #17324604}
  .perception-environment .card::before{display:block;inset:20px 20px auto auto;width:24px;height:4px;border-radius:999px;background:#8fa2bd}
  .perception-environment .card[data-tone=operations]{border-color:#d4e7e1;background:linear-gradient(135deg,#f0f9f5,#fcfefd)}
  .perception-environment .card[data-tone=operations]::before{background:#198273}
  .perception-environment .card .kicker{padding-right:30px;color:#4d5661;font-size:10px;letter-spacing:.1em}
  .perception-environment .card .value{margin:13px 0 6px;color:#24292f;font-size:34px;font-weight:700;letter-spacing:-1px;font-variant-numeric:tabular-nums}
  .perception-environment .card .label{font-size:13px;line-height:1.5}
  .perception-environment main>section{margin:22px 0;padding:26px;border:1px solid #e0e7ee;border-radius:16px;background:#fff;box-shadow:0 3px 12px #17324604}
  .perception-environment main>section>h2{margin-bottom:9px;font-size:22px;letter-spacing:-.5px}
  .perception-environment .section-intro{max-width:100ch;margin-bottom:20px;font-size:13px;line-height:1.75}
  .perception-environment .efficiency-kpis{gap:12px;margin:20px 0}
  .perception-environment .efficiency-kpi{padding:16px;border-color:#e0e8ee;border-radius:12px;background:#f7f9fc}
  .perception-environment .efficiency-kpi span{font-size:11px;font-weight:500;line-height:1.6}
  .perception-environment .efficiency-kpi strong{margin-top:8px;font-size:clamp(16px,1.8vw,22px);font-weight:650;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
  .perception-environment .efficiency-panel{padding:20px;border-color:#e4ebf0;border-radius:12px;background:#fafcfd}
  .perception-environment .efficiency-panel h3{font-size:15px;letter-spacing:-.15px}
  .perception-environment .funnel{gap:9px}
  .perception-environment .funnel-stage{padding:15px 10px;border:1px solid #dceae8;border-radius:10px;background:#eef6f5}
  .perception-environment .funnel-stage:nth-child(2n){border-color:#e3e3f0;background:#f1f1f9}
  .perception-environment .funnel-stage strong{margin-bottom:4px;font-size:22px;font-variant-numeric:tabular-nums}
  .perception-environment .funnel-stage span{font-size:11px;line-height:1.55}
  .perception-environment .phase-track{height:7px;background:#e5eeef}
  .perception-environment .action-list li{padding:10px 0;font-size:12px;line-height:1.6}
  .perception-environment .action-list strong{font-weight:600}
  .perception-environment .table-scroll{border-color:#e1e9ee;border-radius:12px}
  .perception-environment th{padding:13px 15px;background:#f5f8fa;color:#4d5661;font-size:10px;font-weight:600;letter-spacing:.08em}
  .perception-environment td{padding:13px 15px;font-size:13px;line-height:1.65}
  .perception-environment tbody tr:hover{background:#f4faf8}
  .perception-environment .pill{border:1px solid #d8dde2;font-size:11px;font-weight:600;line-height:1.5}
  .perception-environment .pill:not(.good):not(.bad){background:#f0f2f4;color:#343b43}
  .perception-environment .pill.good{border-color:#cfe5d7;background:#eaf5ee;color:#226540}
  .perception-environment .pill.bad{border-color:#efd6d6;background:#fbeeee;color:#a03333}
  .perception-environment .controls{gap:10px;padding:14px;border-color:#dee9e9;border-radius:12px;background:#f5f9f9}
  .perception-environment .controls input,.perception-environment .controls select,.perception-environment .controls button{min-height:42px;padding:10px 12px;border-radius:9px;font-size:12px}
  .perception-environment .controls input:focus,.perception-environment .controls select:focus{border-color:#148377;outline:3px solid #0f766e1a}
  .perception-environment .controls button.primary{background:#0f766e;border-color:#0f766e;color:#fff}
  .perception-environment .controls button:hover{border-color:#0f766e}
  .perception-environment details.session{margin:12px 0;border-radius:12px;box-shadow:0 2px 5px #17324603}
  .perception-environment details.session:hover{border-color:#a1cfc3;box-shadow:0 4px 14px #17324608}
  .perception-environment details.session>summary{padding:17px 18px}
  .perception-environment details.session[open]>summary{background:#f5faf8}
  .perception-environment .session-title-row strong{color:#293139;font-size:14px;font-weight:600}
  .perception-environment .session-facts{margin-top:4px;font-size:11px;gap:7px 14px}
  .perception-environment .session-facts code{color:#4d5661;font-size:11px}
  .perception-environment .detail-body{padding:12px 16px 16px}
  .perception-environment .metadata{grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));font-size:12px}
  .perception-environment details.run{border-radius:10px;background:#f8fafc}
  .perception-environment .api-flow{grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr))}
  .perception-environment details.rest-step,.perception-environment details.session-rest-calls{border-radius:11px;background:#f8fafc}
  .perception-environment details.rest-step>summary,.perception-environment details.session-rest-calls>summary{padding:14px;font-size:13px}
  .perception-environment .quick-run{padding:20px;border-color:#cbe1db;border-radius:12px;background:#f0f8f5}
  .perception-environment .quick-run-copy strong{font-size:15px}
  .perception-environment .quick-run button:not(:disabled){border-color:#0f766e;background:#0f766e}
  .perception-environment footer{font-size:12px}
  @media(max-width:1000px){
    .perception-environment .hero-inner{grid-template-columns:1fr;gap:24px}
    .perception-environment .hero-meta{max-width:none}
    .perception-environment .efficiency-grid{grid-template-columns:1fr}
  }
  @media(max-width:700px){
    body.perception-environment>header.hero{padding:26px 16px}
    .perception-environment .hero h1{font-size:28px;letter-spacing:-.7px}
    .perception-environment .hero-subtitle{font-size:13px}
    .perception-environment .hero-meta{padding:15px 17px}
    .perception-environment .jump-nav div{padding:8px 12px}
    .perception-environment .jump-nav a{padding:8px 10px}
    .perception-environment main{padding:20px 16px 30px}
    .perception-environment .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
    .perception-environment .card{min-height:132px;padding:16px}
    .perception-environment .card::before{inset:18px 14px auto auto;width:16px}
    .perception-environment .card .value{font-size:30px}
    .perception-environment .card .label{font-size:12px}
    .perception-environment main>section{padding:18px;border-radius:13px}
    .perception-environment main>section>h2{font-size:20px}
    .perception-environment .efficiency-kpis,.perception-environment .funnel{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
    .perception-environment .efficiency-kpi{padding:12px}
    .perception-environment .efficiency-panel{padding:15px}
    .perception-environment details.session>summary{padding:14px}
    .perception-environment .detail-body{padding:10px 12px 14px}
    .perception-environment .quick-run{grid-template-columns:1fr;padding:15px}
  }
</style>
'@
        $presentation = $presentation.Replace('<!-- perception-presentation:end -->', "$environmentTheme`n<!-- perception-presentation:end -->")
    }
    $available = @(
        foreach ($name in @(
            'Perception-Live-Environment.html', 'Perception-Threat-Protection.html',
            'Perception-Assurance-Freshness.html', 'Perception-Agent-Behavior-Analysis.html',
            'Perception-Operational-Loops.html',
            'Perception-Systemic-Threat-Signals.html', 'Perception-Defender-Investigations.html'
        )) {
            if (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf) { $name }
        }
    )
    $presentation = $presentation.Replace('__PERCEPTION_AVAILABLE_REPORTS__', (ConvertTo-Json -InputObject $available -Compress))
    $pattern = '(?s)<!-- perception-presentation:start -->.*?<!-- perception-presentation:end -->\s*'
    $cleanHtml = [regex]::Replace($Html, $pattern, '')
    $cleanHtml.Replace('</head>', "$presentation`n</head>")
}
