import * as vscode from "vscode";
import * as constants from "./constants";

export function getSeverityFromConfig(){
    let severity = vscode.workspace.getConfiguration().get("vls.severity") as string;
    return severity.toLowerCase();
}


export function applySeverityFilter(vulnerabilities: []) {
    const config = vscode.workspace.getConfiguration();
    let configSeverity = config.get("vls.severity", "Moderate");
    configSeverity = configSeverity.toLowerCase();
  
    let minimumSeverityScore = mapSeverityScore(configSeverity);
  
    let response: any[] = vulnerabilities.filter((vuln) => {
      return mapSeverityScore(vuln["severity"]) >= minimumSeverityScore;
    });
  
    return response;
  };
  
  const mapSeverityScore = (severity: string) => {
    return constants.vulnerabilityScore[
      severity.toLowerCase() as keyof typeof constants.vulnerabilityScore
    ];
  };
  