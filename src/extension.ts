/* eslint-disable @typescript-eslint/naming-convention */
import * as toml from "@iarna/toml";
import axios from "axios";
import * as fs from "fs";
import * as vscode from "vscode";
import * as constants from "./constants";
import { scan_request, scan_request_list } from "./model";
import { VulnerabilitesTreeProvider } from "./treeview";
import { PyPIFileParser, PyPIPackageParser } from "./parsers/python";
import {
  NodeFileParserPackageJson,
  NodeFileParserPackageLockJson,
  NodePackageParserPackageJson,
  NodePackageParserPackageLockJson,
} from "./parsers/node";
import { GolangFileParser, GolangPackageParser } from "./parsers/golang";
import { RustLockFileParser, RustLockPackageParser, RustTomlFileParser, RustTomlPackageParser } from "./parsers/rust";
import { GradleFileParser, GradlePackageParser, PomXMLFileParser, PomXMLPackageParser } from "./parsers/java";
import { applySeverityFilter } from "./utils";
import { VLSError } from "./error";

export function activate(context: vscode.ExtensionContext) {
  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Running Vulnerabilty Scan Extension....",
      cancellable: false,
    },
    async function sendPostRequest() {}
  );

  let severity = vscode.workspace.getConfiguration().get("vls.severity") as string;
  severity = severity.toLowerCase();

  let scanTextViaVLS = vscode.commands.registerCommand("vls.scanTextViaVLS", () => {
    let excludedPackages: any[] = [];
    var scanRequest: scan_request[] = [];

    vscode.commands.executeCommand("workbench.output.action.clearOutput");
    vscode.commands.executeCommand("vulnerabilitiesTreeView.focus");

    let editor = vscode.window.activeTextEditor;
    if (!editor || editor === undefined) {
      vscode.window.showErrorMessage("Unable to scan!");
      return;
    }

    let selection = editor?.selection;
    if (selection && !selection.isEmpty) {
      const selectionRange = new vscode.Range(
        selection.start.line,
        selection?.start.character,
        selection?.end.line,
        selection?.end.character
      );
      let highlightedText = editor?.document.getText(selectionRange) ? editor.document.getText(selectionRange) : "";
      let fileName = editor.document.fileName
        .split(/[\\\/]/)
        .pop()
        ?.toLowerCase();

      if (fileName === undefined) {
        return;
      }
      let languageId = editor.document.languageId.toLowerCase();

      if (
        constants.languageIdKeyMap.python.includes(languageId) ||
        constants.dependencyStandardFileNames.python.includes(fileName)
      ) {
        [scanRequest, excludedPackages] = PyPIPackageParser(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.nodejs.includes(fileName) ||
        constants.languageIdKeyMap.nodejs.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = NodePackageParserPackageJson(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.nodejslock.includes(fileName) ||
        constants.languageIdKeyMap.nodejs.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = NodePackageParserPackageLockJson(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.golang.includes(fileName) ||
        constants.languageIdKeyMap.golang.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = GolangPackageParser(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.rust.includes(fileName) ||
        constants.languageIdKeyMap.rust.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = RustTomlPackageParser(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.rustlock.includes(fileName) ||
        constants.languageIdKeyMap.rust.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = RustLockPackageParser(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.mavenxml.includes(fileName) ||
        constants.languageIdKeyMap.maven.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = PomXMLPackageParser(highlightedText);
      } else if (
        constants.dependencyStandardFileNames.mavengradle.includes(fileName) ||
        constants.languageIdKeyMap.maven.includes(languageId)
      ) {
        [scanRequest, excludedPackages] = GradlePackageParser(highlightedText);
      }
    }
    makeAPIRequest(scanRequest, excludedPackages);
    context.subscriptions.push(scanTextViaVLS);
  });

  let scanFileViaVLS = vscode.commands.registerCommand("vls.scanFileViaVLS", (fileUri) => {
    vscode.commands.executeCommand("workbench.output.action.clearOutput");
    vscode.commands.executeCommand("vulnerabilitiesTreeView.focus");

    let excludedPackages: any[] = [];
    var scanRequest: scan_request[] = [];

    let filePath = fileUri.fsPath;
    let fileName = fileUri.fsPath.split("/").pop()?.toLowerCase();
    let fileContents = fs.readFileSync(filePath, "utf8");

    if (!fs.existsSync(filePath)) {
      vscode.window.showErrorMessage("Unable to read file for scanning, Please try again.");
      return;
    }

    if (constants.dependencyStandardFileNames.python.includes(fileName)) {
      [scanRequest, excludedPackages] = PyPIFileParser(fileContents);
    } else if (constants.dependencyStandardFileNames.nodejs.includes(fileName)) {
      [scanRequest, excludedPackages] = NodeFileParserPackageJson(fileContents);
    } else if (constants.dependencyStandardFileNames.nodejslock.includes(fileName)) {
      [scanRequest, excludedPackages] = NodeFileParserPackageLockJson(fileContents);
    } else if (constants.dependencyStandardFileNames.golang.includes(fileName)) {
      [scanRequest, excludedPackages] = GolangFileParser(fileContents);
    } else if (constants.dependencyStandardFileNames.rust.includes(fileName)) {
      [scanRequest, excludedPackages] = RustTomlFileParser(fileContents);
    } else if (constants.dependencyStandardFileNames.rustlock.includes(fileName)) {
      [scanRequest, excludedPackages] = RustLockFileParser(fileContents);
    } else if (constants.dependencyStandardFileNames.mavenxml.includes(fileName)) {
      [scanRequest, excludedPackages] = PomXMLFileParser(fileContents);
    } else if (constants.dependencyStandardFileNames.mavengradle.includes(fileName)) {
      [scanRequest, excludedPackages] = GradleFileParser(fileContents);
    }
    makeAPIRequest(scanRequest, excludedPackages);
    context.subscriptions.push(scanFileViaVLS);
  });
}

const makeAPIRequest = (scanRequest: scan_request[], excludedPackages: any[]): Promise<any> => {
  let emptyTreeView: any = {
    scan_results: [
      {
        package_name: "Scanning...",
        not_scanned: true,
        vulnerable_versions: {},
      },
    ],
  };
  vscode.window.createTreeView("vulnerabilitiesTreeView", {
    treeDataProvider: new VulnerabilitesTreeProvider(emptyTreeView),
  });

  return new Promise(async (resolve, reject) => {
    var data: any;

    try {
      scanRequest = scanRequest?.filter((req) => req.name !== "");
      let scanRequestList: scan_request_list = {
        scan_request: scanRequest,
      };

      if (scanRequestList.scan_request.length > 0) {
        let endpoint = "/scan";
        let apiUrl = vscode.workspace.getConfiguration().get("vls.apiUrl") + endpoint;
        let response: any;
        try {
          response = await axios.post(apiUrl, scanRequestList);
        } catch (err) {
          throw new VLSError("Unable to connect to API, please try again!");
        }
        console.log(response.status);

        if (response.status === 200) {
          data = response.data;
        } else {
          throw new VLSError(`API request failed with status code ${response.status}`);
        }

        if (!data["scan_results"] || data["scan_results"].length === 0) {
          data["scan_results"] = [];
        }

        data["scan_results"].forEach((object: any) => {
          let versions = Object.keys(object["vulnerable_versions"]);
          versions.map((version) => {
            object["vulnerable_versions"][version]["vulnerabilities"] = applySeverityFilter(
              object["vulnerable_versions"][version]["vulnerabilities"]
            );
          });
        });
      }

      if (data === undefined || data["scan_results"] === undefined) {
        data = {};
        data["scan_results"] = [];
      }

      data["scan_results"] = excludedPackages.concat(data["scan_results"]);
      vscode.window.createTreeView("vulnerabilitiesTreeView", {
        treeDataProvider: new VulnerabilitesTreeProvider(data),
      });

      resolve(data);
    } catch (err: any) {
      if (err instanceof VLSError) {
        vscode.window.showInformationMessage(err.message);
      } else {
        vscode.window.showInformationMessage("Something went wrong. Please try again!");
      }
      reject(err);
    }
  });
};
