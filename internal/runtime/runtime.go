package runtime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/ioc"
)

type TaskContext struct {
	PackageName string
	PackageDir  string
	ScriptName  string
	Script      string
}

type Prepared struct {
	TempDir    string
	EventLog   string
	MonitorJS  string
	WrapperDir string
	Env        []string
	Task       TaskContext
}

type rawEvent struct {
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	Command     string `json:"command"`
	Target      string `json:"target"`
	PackageName string `json:"packageName"`
	PackageDir  string `json:"packageDir"`
	ScriptName  string `json:"scriptName"`
	Script      string `json:"script"`
	Detail      string `json:"detail"`
	Timestamp   string `json:"timestamp"`
}

type wrapperSpec struct {
	Name          string
	Severity      string
	InjectMonitor bool
}

var wrapperSpecs = []wrapperSpec{
	{Name: "node", Severity: "MEDIUM", InjectMonitor: true},
	{Name: "npm", Severity: "LOW"},
	{Name: "npx", Severity: "LOW"},
	{Name: "curl", Severity: "HIGH"},
	{Name: "wget", Severity: "HIGH"},
	{Name: "nc", Severity: "HIGH"},
	{Name: "ncat", Severity: "HIGH"},
	{Name: "netcat", Severity: "HIGH"},
	{Name: "socat", Severity: "HIGH"},
	{Name: "ssh", Severity: "HIGH"},
	{Name: "scp", Severity: "HIGH"},
	{Name: "powershell", Severity: "HIGH"},
	{Name: "pwsh", Severity: "HIGH"},
	{Name: "bash", Severity: "MEDIUM"},
	{Name: "sh", Severity: "MEDIUM"},
	{Name: "python", Severity: "MEDIUM"},
	{Name: "python3", Severity: "MEDIUM"},
	{Name: "perl", Severity: "MEDIUM"},
	{Name: "ruby", Severity: "MEDIUM"},
	{Name: "rm", Severity: "HIGH"},
	{Name: "chmod", Severity: "MEDIUM"},
	{Name: "chown", Severity: "MEDIUM"},
	{Name: "mv", Severity: "MEDIUM"},
	{Name: "cp", Severity: "LOW"},
}

func Prepare(task TaskContext) (*Prepared, error) {
	tempDir, err := os.MkdirTemp("", "phalanx-runtime-*")
	if err != nil {
		return nil, err
	}

	monitorJS := filepath.Join(tempDir, "monitor.js")
	if err := os.WriteFile(monitorJS, []byte(monitorScript), 0600); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	wrapperDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(wrapperDir, 0755); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	eventLog := filepath.Join(tempDir, "events.jsonl")
	if f, err := os.Create(eventLog); err == nil {
		_ = f.Close()
	} else {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}

	for _, spec := range wrapperSpecs {
		if err := writeWrapper(wrapperDir, monitorJS, spec); err != nil {
			_ = os.RemoveAll(tempDir)
			return nil, err
		}
	}

	env := append([]string{}, os.Environ()...)
	env = setEnv(env, "PHALANX_EVENT_LOG", eventLog)
	env = setEnv(env, "PHALANX_MONITOR_JS", monitorJS)
	env = setEnv(env, "PHALANX_PACKAGE_NAME", task.PackageName)
	env = setEnv(env, "PHALANX_PACKAGE_DIR", task.PackageDir)
	env = setEnv(env, "PHALANX_SCRIPT_NAME", task.ScriptName)
	env = setEnv(env, "PHALANX_SCRIPT_COMMAND", task.Script)
	env = prependPath(env, wrapperDir)
	if task.PackageDir != "" {
		env = prependPath(env, filepath.Join(task.PackageDir, "node_modules", ".bin"))
	}

	return &Prepared{
		TempDir:    tempDir,
		EventLog:   eventLog,
		MonitorJS:  monitorJS,
		WrapperDir: wrapperDir,
		Env:        env,
		Task:       task,
	}, nil
}

func (p *Prepared) Cleanup() {
	if p == nil || p.TempDir == "" {
		return
	}
	_ = os.RemoveAll(p.TempDir)
}

func ParseEvents(logPath string, task TaskContext) []analysis.Finding {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []analysis.Finding
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var ev rawEvent
		if strings.HasPrefix(line, "{") {
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				continue
			}
		} else {
			var ok bool
			ev, ok = parsePipeEvent(line, task)
			if !ok {
				continue
			}
		}
		if finding, ok := eventToFinding(ev, task); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func parsePipeEvent(line string, task TaskContext) (rawEvent, bool) {
	parts := strings.SplitN(line, "|", 7)
	if len(parts) < 4 {
		return rawEvent{}, false
	}
	sev := strings.TrimSpace(parts[1])
	if sev == "" {
		sev = "MEDIUM"
	}
	ev := rawEvent{
		Kind:        strings.TrimSpace(parts[0]),
		Severity:    sev,
		Command:     strings.TrimSpace(parts[2]),
		Target:      strings.TrimSpace(parts[3]),
		PackageName: task.PackageName,
		PackageDir:  task.PackageDir,
		ScriptName:  task.ScriptName,
		Script:      task.Script,
		Detail:      "shell wrapper invocation",
		Timestamp:   time.Now().Format(time.RFC3339Nano),
	}
	if len(parts) >= 5 && strings.TrimSpace(parts[4]) != "" {
		ev.PackageName = strings.TrimSpace(parts[4])
	}
	if len(parts) >= 6 && strings.TrimSpace(parts[5]) != "" {
		ev.ScriptName = strings.TrimSpace(parts[5])
	}
	if len(parts) >= 7 && strings.TrimSpace(parts[6]) != "" {
		ev.Detail = strings.TrimSpace(parts[6])
	}
	return ev, true
}

func eventToFinding(ev rawEvent, task TaskContext) (analysis.Finding, bool) {
	kind := strings.ToLower(strings.TrimSpace(ev.Kind))
	severity := strings.ToUpper(strings.TrimSpace(ev.Severity))
	if severity == "" {
		severity = "MEDIUM"
	}

	command := strings.TrimSpace(ev.Command)
	target := strings.TrimSpace(ev.Target)
	detail := strings.TrimSpace(ev.Detail)
	pkgName := choose(ev.PackageName, task.PackageName)
	pkgDir := choose(ev.PackageDir, task.PackageDir)
	scriptName := choose(ev.ScriptName, task.ScriptName)
	location := pkgDir
	if location == "" {
		location = pkgName
	}
	if location == "" {
		location = "runtime"
	}

	ruleID := "RUNTIME-" + strings.ToUpper(strings.ReplaceAll(kind, ".", "-"))
	description := detail
	if description == "" {
		description = "Runtime behavior observed"
	}

	switch {
	case strings.Contains(kind, "network"):
		if ioc.CheckDomain(target) {
			severity = "CRITICAL"
			description = "Known malicious domain contacted: " + target
		} else {
			severity = maxSeverity(severity, "HIGH")
			description = "Network activity toward: " + target
		}
	case strings.Contains(kind, "file") || strings.Contains(kind, "fs"):
		if isSensitivePath(target) {
			severity = "CRITICAL"
			description = "Sensitive file operation against: " + target
		} else {
			severity = maxSeverity(severity, "MEDIUM")
			description = "Filesystem activity against: " + target
		}
	case strings.Contains(kind, "exit"):
		severity = maxSeverity(severity, "HIGH")
		description = "Process exited early"
	default:
		if isSuspiciousCommand(command, target, detail) {
			severity = maxSeverity(severity, commandSeverity(command, target))
			description = fmt.Sprintf("Executed command %q", command)
			if target != "" {
				description += " with target " + target
			}
		} else {
			description = fmt.Sprintf("Executed command %q", command)
			if target != "" {
				description += " with target " + target
			}
		}
	}

	if scriptName != "" {
		description += " [script=" + scriptName + "]"
	}

	return analysis.Finding{
		RuleID:      ruleID,
		Severity:    severity,
		FilePath:    location,
		Line:        0,
		Description: description,
		Origin:      "runtime",
	}, true
}

func writeWrapper(dir, monitorJS string, spec wrapperSpec) error {
	realPath, err := exec.LookPath(spec.Name)
	if err != nil {
		return nil
	}

	if runtime.GOOS == "windows" {
		return writeWindowsWrapper(dir, monitorJS, spec, realPath)
	}
	return writeUnixWrapper(dir, monitorJS, spec, realPath)
}

func writeUnixWrapper(dir, monitorJS string, spec wrapperSpec, realPath string) error {
	path := filepath.Join(dir, spec.Name)
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n")
	b.WriteString("set -eu\n")
	b.WriteString(`LOG="${PHALANX_EVENT_LOG:-}"` + "\n")
	b.WriteString(`PKG="${PHALANX_PACKAGE_NAME:-}"` + "\n")
	b.WriteString(`SCRIPT="${PHALANX_SCRIPT_NAME:-}"` + "\n")
	b.WriteString(`CWD="${PWD:-}"` + "\n")
	b.WriteString(`TARGET="${1:-}"` + "\n")
	b.WriteString(`if [ -n "$LOG" ]; then` + "\n")
	b.WriteString(`  printf 'command|` + spec.Severity + `|` + spec.Name + `|%s|%s|%s|%s\n' "$TARGET" "$PKG" "$SCRIPT" "$CWD" >> "$LOG"` + "\n")
	b.WriteString("fi\n")
	if spec.InjectMonitor {
		b.WriteString("exec ")
		b.WriteString(quoteShell(realPath))
		b.WriteString(" --require ")
		b.WriteString(quoteShell(monitorJS))
		b.WriteString(" \"$@\"\n")
	} else {
		b.WriteString("exec ")
		b.WriteString(quoteShell(realPath))
		b.WriteString(" \"$@\"\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0755); err != nil {
		return err
	}
	return nil
}

func writeWindowsWrapper(dir, monitorJS string, spec wrapperSpec, realPath string) error {
	path := filepath.Join(dir, spec.Name+".cmd")
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("setlocal\r\n")
	b.WriteString(fmt.Sprintf(`if not "%%PHALANX_EVENT_LOG%%"=="" echo command^|%s^|%s^|%%1^|%%PHALANX_PACKAGE_NAME%%^|%%PHALANX_SCRIPT_NAME%%^|%%CD%%>>"%%PHALANX_EVENT_LOG%%"\r\n`, spec.Severity, spec.Name))
	if spec.InjectMonitor {
		b.WriteString(fmt.Sprintf(`"%s" --require "%s" %%*\r\n`, realPath, monitorJS))
	} else {
		b.WriteString(fmt.Sprintf(`"%s" %%*\r\n`, realPath))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return err
	}
	return nil
}

func isSuspiciousCommand(command, target, detail string) bool {
	joined := strings.ToLower(command + " " + target + " " + detail)
	patterns := []string{"curl", "wget", "nc", "ncat", "netcat", "socat", "powershell", "pwsh", "bash", "sh", "rm", "chmod", "chown", "python", "perl", "ruby", "base64", "eval", "exec"}
	for _, p := range patterns {
		if strings.Contains(joined, p) {
			return true
		}
	}
	return false
}

func commandSeverity(command, target string) string {
	cmd := strings.ToLower(command)
	tgt := strings.ToLower(target)
	switch {
	case strings.Contains(cmd, "curl"), strings.Contains(cmd, "wget"), strings.Contains(cmd, "nc"), strings.Contains(cmd, "ncat"), strings.Contains(cmd, "netcat"), strings.Contains(cmd, "socat"), strings.Contains(cmd, "ssh"), strings.Contains(cmd, "scp"), strings.Contains(cmd, "powershell"), strings.Contains(cmd, "pwsh"):
		return "HIGH"
	case strings.Contains(cmd, "rm"):
		if isSensitivePath(tgt) {
			return "CRITICAL"
		}
		return "HIGH"
	case strings.Contains(cmd, "node"):
		if strings.Contains(tgt, "-e") || strings.Contains(tgt, "--eval") {
			return "HIGH"
		}
		return "MEDIUM"
	default:
		return "MEDIUM"
	}
}

func isSensitivePath(p string) bool {
	p = strings.ToLower(filepath.ToSlash(p))
	if p == "" {
		return false
	}
	patterns := []string{"/etc/passwd", "/etc/shadow", "/.ssh/", "/id_rsa", "/.aws/credentials", "/.bashrc", "/.bash_profile", "/.zshrc", "/.npmrc", "/.git/hooks/", "/.config/", "appdata/roaming/microsoft/windows/start menu/programs/startup"}
	for _, needle := range patterns {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

func choose(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return fallback
}

func maxSeverity(a, b string) string {
	order := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	a = strings.ToUpper(a)
	b = strings.ToUpper(b)
	if order[b] > order[a] {
		return b
	}
	return a
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	if value != "" {
		out = append(out, key+"="+value)
	}
	return out
}

func prependPath(env []string, dir string) []string {
	if dir == "" {
		return env
	}
	current := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			current = strings.TrimPrefix(kv, "PATH=")
			break
		}
	}
	if current == "" {
		current = os.Getenv("PATH")
	}
	sep := string(os.PathListSeparator)
	newVal := dir
	if current != "" {
		newVal = dir + sep + current
	}
	return setEnv(env, "PATH", newVal)
}

func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

const monitorScript = `(() => {
  const fs = require('fs');
  const path = require('path');
  const cp = require('child_process');
  const net = require('net');
  const http = require('http');
  const https = require('https');

  const logPath = process.env.PHALANX_EVENT_LOG;
  if (!logPath) return;

  const ctx = {
    packageName: process.env.PHALANX_PACKAGE_NAME || '',
    packageDir: process.env.PHALANX_PACKAGE_DIR || '',
    scriptName: process.env.PHALANX_SCRIPT_NAME || '',
    script: process.env.PHALANX_SCRIPT_COMMAND || '',
  };

  const append = fs.appendFileSync.bind(fs);
  function emit(event) {
    try {
      event.packageName = event.packageName || ctx.packageName;
      event.packageDir = event.packageDir || ctx.packageDir;
      event.scriptName = event.scriptName || ctx.scriptName;
      event.script = event.script || ctx.script;
      event.timestamp = event.timestamp || new Date().toISOString();
      append(logPath, JSON.stringify(event) + '\n');
    } catch (_) {}
  }

  function baseName(v) {
    if (!v) return '';
    try { return path.basename(String(v)).toLowerCase(); } catch (_) { return String(v).toLowerCase(); }
  }

  function isNodeCommand(cmd) {
    const b = baseName(cmd);
    return b === 'node' || b === 'node.exe';
  }

  function firstArg(args) {
    if (Array.isArray(args) && args.length > 0) return String(args[0] || '');
    return '';
  }

  function severityFor(command, target) {
    const joined = (String(command || '') + ' ' + String(target || '')).toLowerCase();
    if (/(curl|wget|nc|ncat|netcat|socat|powershell|pwsh|ssh|scp)/.test(joined)) return 'HIGH';
    if (/\brm\b/.test(joined) || /unlink|rm -rf|del\b/.test(joined)) return 'HIGH';
    if (/\.ssh|\.bashrc|\.npmrc|id_rsa|windows\\start menu\\programs\\startup/.test(joined)) return 'CRITICAL';
    return 'MEDIUM';
  }

  function maybeInjectNodeMonitor(command, args) {
    if (!isNodeCommand(command)) return args;
    const extra = ['--require', __filename];
    if (Array.isArray(args)) return extra.concat(args);
    return extra;
  }

  function emitChild(kind, command, args) {
    const target = firstArg(args) || String(command || '');
    emit({
      kind,
      severity: severityFor(command, target),
      command: String(command || ''),
      target,
      detail: 'child process execution',
    });
    return maybeInjectNodeMonitor(command, args);
  }

  function patchSpawnLike(method, kind) {
    const original = cp[method];
    if (typeof original !== 'function') return;
    cp[method] = function (...args) {
      try {
        if (method === 'exec' || method === 'execSync') {
          const command = args[0];
          emit({ kind, severity: severityFor(command, command), command: String(command || ''), target: String(command || ''), detail: 'shell execution' });
          return original.apply(this, args);
        }
        const command = args[0];
        const argv = Array.isArray(args[1]) ? args[1] : [];
        if (method === 'fork') {
          const forkArgs = Array.isArray(args[1]) ? args[1] : [];
          const forkOptions = args[2] || {};
          emit({ kind, severity: severityFor(command, firstArg(forkArgs) || String(command || '')), command: String(command || ''), target: firstArg(forkArgs) || String(command || ''), detail: 'child process fork' });
          forkOptions.execArgv = Array.isArray(forkOptions.execArgv) ? forkOptions.execArgv.slice() : [];
          if (!forkOptions.execArgv.includes('--require') && !forkOptions.execArgv.some(v => String(v).includes(__filename))) {
            forkOptions.execArgv = ['--require', __filename].concat(forkOptions.execArgv);
          }
          args[2] = forkOptions;
          return original.apply(this, args);
        }
        args[1] = emitChild(kind, command, argv);
        return original.apply(this, args);
      } catch (err) {
        return original.apply(this, args);
      }
    };
  }

  patchSpawnLike('spawn', 'child_process.spawn');
  patchSpawnLike('spawnSync', 'child_process.spawnSync');
  patchSpawnLike('execFile', 'child_process.execFile');
  patchSpawnLike('execFileSync', 'child_process.execFileSync');
  patchSpawnLike('exec', 'child_process.exec');
  patchSpawnLike('execSync', 'child_process.execSync');
  patchSpawnLike('fork', 'child_process.fork');

  function patchFsMethod(name, kind) {
    const original = fs[name];
    if (typeof original !== 'function') return;
    fs[name] = function (...args) {
      try {
        const target = String(args[0] || '');
        emit({ kind, severity: severityFor(name, target), command: name, target, detail: 'filesystem mutation' });
      } catch (_) {}
      return original.apply(this, args);
    };
  }

  ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'rename', 'renameSync', 'truncate', 'truncateSync', 'chmod', 'chmodSync', 'chown', 'chownSync', 'copyFile', 'copyFileSync'].forEach(name => patchFsMethod(name, 'fs.' + name));

  function patchHttpMethod(mod, method) {
    const original = mod[method];
    if (typeof original !== 'function') return;
    mod[method] = function (options, ...rest) {
      try {
        let target = '';
        if (typeof options === 'string') {
          target = options;
        } else if (options && typeof options === 'object') {
          const proto = options.protocol || 'http:';
          const host = options.hostname || options.host || '';
          const port = options.port ? ':' + options.port : '';
          const reqPath = options.path || '';
          target = proto + '//' + host + port + reqPath;
        }
        emit({ kind: 'network.' + method, severity: 'HIGH', command: method, target, detail: 'network request' });
      } catch (_) {}
      return original.call(this, options, ...rest);
    };
  }

  patchHttpMethod(http, 'request');
  patchHttpMethod(http, 'get');
  patchHttpMethod(https, 'request');
  patchHttpMethod(https, 'get');

  const originalConnect = net.connect.bind(net);
  net.connect = function (...args) {
    let target = '';
    if (typeof args[0] === 'object' && args[0]) {
      const o = args[0];
      target = String(o.host || o.hostname || '') + ':' + String(o.port || '');
    } else if (typeof args[0] === 'number') {
      target = 'port:' + String(args[0]);
    } else if (typeof args[0] === 'string') {
      target = args[0];
    }
    emit({ kind: 'network.connect', severity: 'HIGH', command: 'connect', target, detail: 'socket connection' });
    return originalConnect(...args);
  };

  if (typeof global.fetch === 'function') {
    const originalFetch = global.fetch.bind(global);
    global.fetch = async function (resource, init) {
      const target = typeof resource === 'string' ? resource : (resource && resource.url) ? resource.url : String(resource || '');
      emit({ kind: 'network.fetch', severity: severityFor('fetch', target), command: 'fetch', target, detail: 'fetch request' });
      return originalFetch(resource, init);
    };
  }

  const originalExit = process.exit.bind(process);
  process.exit = function (code) {
    emit({ kind: 'process.exit', severity: code && code !== 0 ? 'HIGH' : 'MEDIUM', command: 'exit', target: String(code ?? 0), detail: 'process exit' });
    return originalExit(code);
  };
})();`
