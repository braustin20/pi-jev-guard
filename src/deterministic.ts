import type { Finding, GuardConfig, NormalizedCall } from "./types.js";

function categoryDecision(config: GuardConfig, category: string): "allow" | "prompt" | "block" {
  const hazard = config.hazards[category];
  return hazard?.enabled === false ? "allow" : hazard?.decision ?? "prompt";
}

function add(
  findings: Finding[],
  config: GuardConfig,
  id: string,
  category: string,
  message: string,
): void {
  const decision = categoryDecision(config, category);
  if (decision === "allow") return;
  if (findings.some((finding) => finding.id === id && finding.message === message)) return;
  findings.push({ id, category, message, decision, source: "deterministic" });
}

function destinationIsTrusted(destination: string, trusted: string[]): boolean {
  const host = destination.toLowerCase();
  return trusted.some((entry) => {
    const normalized = entry.toLowerCase();
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}

export function detectDeterministic(call: Omit<NormalizedCall, "deterministicFindings">, config: GuardConfig): Finding[] {
  const findings: Finding[] = [];
  const shell = call.shell;
  const shellReadsFiles = shell?.commands.some((command) => ["cat", "grep", "head", "less", "more", "tail"].includes(command)) ?? false;
  const isRead = ["read", "grep", "find", "ls"].includes(call.toolName) || shellReadsFiles;
  const isWrite = ["write", "edit"].includes(call.toolName);

  for (const path of call.paths) {
    if (path.dynamic) {
      add(findings, config, "dynamic-path", "outside_project_or_system_change", `Path could not be resolved safely: ${path.input}`);
    } else if (path.withinProject === false) {
      add(findings, config, "outside-project", "outside_project_or_system_change", `Path is outside the project: ${path.canonical ?? path.input}`);
    }
    if (path.protected) {
      add(
        findings,
        config,
        "protected-path",
        "outside_project_or_system_change",
        `Protected path matched ${path.matchedPattern ?? "policy"}: ${path.canonical ?? path.input}`,
      );
    }
    if (isRead && path.sensitive) {
      add(findings, config, "sensitive-read", "sensitive_information_access", `Sensitive file may be read: ${path.canonical ?? path.input}`);
    }
  }

  if (isWrite) {
    for (const overwritten of call.recoverability?.overwrittenPaths ?? []) {
      if (!overwritten.exists) continue;
      if (overwritten.untracked) {
        add(findings, config, "overwrite-untracked", "irreversible_edit", `Existing untracked file would be overwritten: ${overwritten.path}`);
      } else if (overwritten.dirty || !overwritten.tracked) {
        add(findings, config, "overwrite-unrecoverable", "irreversible_edit", `Dirty or unrecoverable file would be overwritten: ${overwritten.path}`);
      }
    }
  }

  if (!shell) return findings;
  const command = shell.command;

  if (/\brm\b[^\n;&|]*(?:\s--recursive\b|\s-[^\s]*r)|\b(?:mkfs(?:\.[\w-]+)?|shred|wipefs)\b|\bdd\b[^\n;&|]*\bof=|\bfind\b[^\n;&|]*\s-delete\b/i.test(command)) {
    add(findings, config, "destructive-filesystem", "destructive_filesystem", "Command contains a known destructive filesystem operation");
  }

  if (/\bgit\s+(?:reset\s+--hard|clean\s+-[^\s]*f|push\b[^\n]*(?:--force(?:-with-lease)?|-f\b)|branch\s+-[dD]|stash\s+(?:clear|drop)|reflog\s+expire)|\bgit\s+checkout\s+--\s/i.test(command)) {
    add(findings, config, "destructive-git", "destructive_version_control", "Command contains a destructive Git operation");
  }

  if (/\b(?:chmod|chown|chgrp|setfacl)\b|\bsudo\b|\b(?:aws\s+iam|gcloud\s+(?:projects\s+)?(?:add-iam-policy-binding|set-iam-policy)|az\s+role\s+(?:assignment|definition)|kubectl\s+(?:apply|create|delete|patch)\b[^\n]*(?:role|clusterrole|rolebinding|clusterrolebinding))\b/i.test(command)) {
    add(findings, config, "permissions-iam", "permissions_or_iam_change", "Command may change permissions, ownership, or IAM policy");
  }

  if (/(?:\bcurl\b|\bwget\b)[^\n]*(?:\||&&|;)\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b|\bwget\b[^\n]*&&[^\n]*chmod\s+\+x[^\n]*&&[^\n]*(?:\.\/|\/tmp\/)/i.test(command)) {
    add(findings, config, "download-execute", "download_and_execute", "Command downloads content and executes it");
  }

  const untrustedDestinations = shell.destinations.filter(
    (destination) => !destinationIsTrusted(destination, config.trustedDestinations),
  );
  if (
    untrustedDestinations.length > 0 &&
    (/\bcurl\b[^\n]*(?:--data(?:-binary)?|-d|--form|-F|--upload-file|-T)\s+@|\b(?:scp|rsync|nc|netcat)\b/i.test(command) ||
      call.paths.some((path) => path.sensitive))
  ) {
    add(
      findings,
      config,
      "possible-exfiltration",
      "sensitive_data_exfiltration",
      `Command may send local data to ${untrustedDestinations.join(", ")}`,
    );
  }

  if (shell.complex) {
    add(findings, config, "complex-shell", "complex_shell_composition", `Shell composition requires review (${shell.operators.join(" ") || "nested shell"})`);
  }
  if (shell.unknown) {
    add(findings, config, "unparsed-shell", "complex_shell_composition", "One or more shell commands could not be classified locally");
  }
  return findings;
}
