/* eslint-disable @typescript-eslint/naming-convention */
import * as vscode from "vscode";

export class VulnerabilitesTreeProvider implements vscode.TreeDataProvider<Vulnerability> {
  static refresh(): any {
    throw new Error("Method not implemented.");
  }
  private _onDidChangeTreeData: vscode.EventEmitter<Vulnerability | undefined | void> = new vscode.EventEmitter<
    Vulnerability | undefined | void
  >();
  readonly onDidChangeTreeData: vscode.Event<Vulnerability | undefined | void> = this._onDidChangeTreeData.event;
  resultdata: any;

  constructor(constdata: string) {
    this.resultdata = constdata;

  }
  refresh(): void {
    this.resultdata = null;
    this._onDidChangeTreeData.fire();
  }
  clearResults(): void {
    this.resultdata = null;
    this.refresh();
  }
  

  getTreeItem(element: Vulnerability): vscode.TreeItem {
    element.label = element.not_scanned && element.label !== "Scanning..."
      ? `${element.label} (Package cannot be scanned)`
      : element.overallSeverity === ""
      ? `${element.label}`
      : `${element.label}  (${element.overallSeverity})`;
    element.tooltip = element.details;
    return element;
  }

  getChildren(element?: Vulnerability): Thenable<Vulnerability[]> {

    const vulnerabilities = this.getVulnerabilityInformation(
      element?.packagename,
      element?.version,
      element?.not_scanned
    );

    vulnerabilities.sort((a, b) => this.compareVersions(b.version, a.version));

    return Promise.resolve(vulnerabilities.filter((v) => !!v.label));
  }

  compareVersions(versionA: string, versionB: string): number {
    const componentsA = versionA.split(".").map(Number);
    const componentsB = versionB.split(".").map(Number);

    for (let i = 0; i < Math.max(componentsA.length, componentsB.length); i++) {
      const componentA = componentsA[i] || 0;
      const componentB = componentsB[i] || 0;

      if (componentA > componentB) {
        return 1;
      } else if (componentA < componentB) {
        return -1;
      }
    }
    return 0;
  }

  private getVulnerabilityInformation(packagename?: string, version?: string, not_scanned?: boolean): Vulnerability[] {
    let vulnInformation: Vulnerability[] = [];

    if (packagename === undefined || packagename === null || packagename === "") {
      this.resultdata.scan_results.forEach(
        (result: { package_name: string; vulnerable_versions?: any; not_scanned?: boolean }) => {
          if (result.vulnerable_versions && Object.keys(result.vulnerable_versions).length > 0) {
            vulnInformation.push(
              new Vulnerability(
                result.package_name,
                result.package_name,
                "",
                vscode.TreeItemCollapsibleState.Collapsed,
                "",
                "",
                false
              )
            );
          } else if (result.vulnerable_versions 
            && Object.keys(result.vulnerable_versions).length === 0 && 
            vscode.workspace.getConfiguration().get("vls.showAllPackages") as boolean && !result.not_scanned) {
            vulnInformation.push(
              new Vulnerability(
                result.package_name + " ( No Vulnerabilities Found )",
                result.package_name + " ( No Vulnerabilities Found )",
                "",
                vscode.TreeItemCollapsibleState.None,
                "",
                "",
                false
              )
            );
          } else if (result.not_scanned) {
            vulnInformation.push(
              new Vulnerability(
                result.package_name,
                result.package_name,
                "",
                vscode.TreeItemCollapsibleState.None,
                "",
                "",
                true
              )
            );
          }
        }
      );

      if (vulnInformation.length === 0) {
        return [
          new Vulnerability("No vulnerabilities found.", "", "", vscode.TreeItemCollapsibleState.None, "", "", false),
        ];
      }

      
    } else {
      if (version === undefined || version === null || version === "") {
        let object = this.resultdata?.scan_results.find(
          (result: { package_name: string; vulnerable_versions?: any; severity: any }) => {
            return (
              result?.package_name === packagename &&
              result.vulnerable_versions &&
              Object.keys(result.vulnerable_versions).length > 0
            );
          }
        );

        if (object === undefined) {
          return [
            new Vulnerability(
              "No vulnerabilities found for this package.",
              "",
              "",
              vscode.TreeItemCollapsibleState.None,
              "",
              "",
              false
            ),
          ];
        }
        if (not_scanned) {
          return [
            new Vulnerability(
              "This Package was not scanned.",
              "",
              "",
              vscode.TreeItemCollapsibleState.None,
              "",
              "",
              false
            ),
          ];
        }

        let versions = Object.keys(object.vulnerable_versions);

        return versions.map((version) => {
          const versionData = object.vulnerable_versions[version];

          return new Vulnerability(
            version,
            packagename,
            version,
            vscode.TreeItemCollapsibleState.Collapsed,
            "",
            versionData?.overall_severity || "",
            false
          );
        });
      } else {
        let vulnerabilityArray: any[] = this.resultdata.scan_results.find(
          (result: { package_name: string; vulnerable_versions?: any }) => result?.package_name === packagename
        )?.vulnerable_versions[version].vulnerabilities;

        if (vulnerabilityArray !== undefined && vulnerabilityArray.length > 0) {
          return vulnerabilityArray.map((vuln) => {
            return new Vulnerability(
              vuln.summary,
              packagename,
              version,
              vscode.TreeItemCollapsibleState.None,
              vuln.details,
              vuln.severity,
              false
            );
          });
        } else {
          return [
            new Vulnerability(
              "No vulnerabilities found for this package and version.",
              "",
              "",
              vscode.TreeItemCollapsibleState.None,
              "",
              "",
              false
            ),
          ];
        }
      }
    }
    vulnInformation = vulnInformation.filter((vulnerability) => vulnerability.label !== "" || vulnerability.version !== "");
    return vulnInformation;
    
  }

}
class Vulnerability extends vscode.TreeItem {
  constructor(
    public label: string,
    public packagename: string,
    public version: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public details: string,
    public overallSeverity: string,
    public not_scanned: boolean
  ) {
    super(label, collapsibleState);
  }
}
