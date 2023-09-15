/* eslint-disable @typescript-eslint/naming-convention */
import * as constants from "../constants";
import {scan_request } from "../model";
import { getSeverityFromConfig } from "../utils";

export function NodeFileParserPackageJson(fileContents: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];
  let json = JSON.parse(fileContents);
  let devDependencies = json.devDependencies || {};
  let dependencies = json.dependencies || {};
  let allPackages = { ...devDependencies, ...dependencies };

  for (let packageName in allPackages) {
    let version = allPackages[packageName];
    if (version && /^\d/.test(version)) {
      let payload: scan_request = {
        version: version.replace(/\s/g, "==") ? version.replace(/\s/g, "==") : "",
        name: packageName,
        ecosystem: "npm",
        severity: getSeverityFromConfig(),
      };
      scanRequest.push(payload);
    } else {
      excludedPackages.push({
        package_name: packageName,
        not_scanned: true,
        vulnerable_versions: {},
      });
    }
  }
  return [scanRequest, excludedPackages];
}

export function NodeFileParserPackageLockJson(fileContents: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];
  let json = JSON.parse(fileContents);
  let devDependencies = json.devDependencies || {};
  let dependencies = json.dependencies || {};
  let allPackages = { ...devDependencies, ...dependencies };

  for (let packageName in allPackages) {
    let packageVersion = allPackages[packageName].version;
    if (constants.delimiters.node_excluded.test(packageVersion)) {
      excludedPackages.push({
        package_name: packageVersion.trim(),
        not_scanned: true,
        vulnerable_versions: {},
      });
    } else {
      scanRequest.push({
        version: packageVersion,
        name: packageName,
        ecosystem: "npm",
        severity: getSeverityFromConfig(),
      });
    }
  }
  return [scanRequest, excludedPackages];
}

export function NodePackageParserPackageJson(highlightedText: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];
  var highlightedTextArray = highlightedText.split("\n");
  highlightedTextArray.forEach((element) => {
    if (constants.delimiters.node_excluded.test(element)) {
      excludedPackages.push({
        package_name: element.trim(),
        not_scanned: true,
        vulnerable_versions: {},
      });
    } else {
      let packageNameSplit = element.split(constants.delimiters.nodes_included);
      if (packageNameSplit.length >= 2) {
        let payload = {
          version: packageNameSplit[1] ? packageNameSplit[1] : "",
          name: packageNameSplit[0],
          ecosystem: "npm",
          severity: getSeverityFromConfig(),
        };
        scanRequest.push(payload);
        console.log("scanRequest22222", payload);
      }
    }
  });
  return [scanRequest, excludedPackages];
}

export function NodePackageParserPackageLockJson(highlightedText: any) {
  
  var excludedPackages: any = [];
  var scanRequest: any = [];
  highlightedText.split(",\r\n    ").forEach((element: string) => {
    let matches = element.match(constants.delimiters.node_match);
    if (matches && matches[1]) {
      let version = matches[1];
      let packageNameWithNodeModules = element.split('"')[1];
      let payload: scan_request = {
        name: packageNameWithNodeModules,
        ecosystem: "npm",
        severity: getSeverityFromConfig(),
        version: version ? version : "",
      };
      scanRequest.push(payload);
      console.log("scanRequest33333", payload);
    } else {
      excludedPackages.push({
        package_name: matches,
        not_scanned: true,
        vulnerable_versions: {},
      });
    }
  });
  console.log("scanRequest4444", scanRequest);
  return [scanRequest, excludedPackages];
}
