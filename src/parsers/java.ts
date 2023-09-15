/* eslint-disable @typescript-eslint/naming-convention */
import * as constants from "../constants";
import { getSeverityFromConfig } from "../utils";

export function GradleFileParser(fileContents: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];

  var temp = fileContents.split("\n");
  let dependencies: string[] = [];
  for (var i = 0; i < temp.length; i += 1) {
    let line: string = temp[i].trim();
    if (line.startsWith("implementation")) {
      dependencies.push(line);
    }
  }
  for (let i = 0; i < dependencies.length; i++) {
    let line = dependencies[i];
    let parts = line.split("'");
    if (parts.length >= 1) {
      let packageNameWithVersion = parts[1];
      let packageName = packageNameWithVersion;
      let version = "";
      let colonIndex = packageNameWithVersion.indexOf(":");
      while (colonIndex !== -1) {
        let nextChar = packageNameWithVersion.charAt(colonIndex + 1);
        if (!isNaN(Number(nextChar))) {
          packageName = packageNameWithVersion.substring(0, colonIndex).trim();
          version = packageNameWithVersion.substring(colonIndex + 1).trim();
          break;
        } else {
          colonIndex = packageNameWithVersion.indexOf(":", colonIndex + 1);
        }
      }

      if (constants.delimiters.maven_excluded.test(version)) {
        excludedPackages.push({
          package_name: version.trim(),
          not_scanned: true,
          vulnerable_versions: {},
        });
      } else {
        scanRequest.push({
          version: version ? version : "",
          name: packageName.trim(),
          ecosystem: "Maven",
          severity: getSeverityFromConfig(),
        });
      }
    }
  }
  return [scanRequest, excludedPackages];
}

export function PomXMLFileParser(fileContents: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];

  extractData(fileContents, "groupId").map((group, index) => {
    let packagename =
      group + "." + extractData(fileContents, "artifactId")[index];
    let version = extractData(fileContents, "version")[index] || "";
    scanRequest.push({
      version: version ? version : "",
      name: packagename,
      ecosystem: "Maven",
      severity: getSeverityFromConfig(),
    });
  });
  console.log("scanRequest", scanRequest);
  return [scanRequest, excludedPackages];
}


function extractData(xml: string, tag: string) {
  let regex = new RegExp(`<${tag}>(.*?)<\/${tag}>`, "g");
  let matches = xml.match(regex);
  if (!matches) {
    return [];
  }
  return matches.map((match) =>
    match.replace(`<${tag}>`, "").replace(`</${tag}>`, "")
  );
}


export function GradlePackageParser(highlightedText:any){

  var excludedPackages: any = [];
  var scanRequest: any = [];
  var temp = highlightedText.split("\n");
            for (var i = 0; i < temp.length; i += 1) {
              let delim = /'/;
              var newarr = temp[i].split(delim);
              if (newarr.length >= 3 && newarr[0].trim() === "implementation") {
                let packageNameWithVersion = newarr[1].trim().substring(0);
                let packageName = packageNameWithVersion;
                let version = "";
                let colonIndex = packageNameWithVersion.indexOf(":");
                while (colonIndex !== -1) {
                  let nextChar = packageNameWithVersion.charAt(colonIndex + 1);
                  if (!isNaN(Number(nextChar))) {
                    packageName = packageNameWithVersion
                      .substring(0, colonIndex)
                      .trim();
                    version = packageNameWithVersion
                      .substring(colonIndex + 1)
                      .trim();
                    break;
                  } else {
                    colonIndex = packageNameWithVersion.indexOf(
                      ":",
                      colonIndex + 1
                    );
                  }
                }
                if (constants.delimiters.crates_excluded.test(version)) {
                  excludedPackages.push({
                    package_name: version.trim(),
                    not_scanned: true,
                    vulnerable_versions: {},
                  });
                } else {
                  scanRequest.push({
                    version: version,
                    name: packageName.trim(),
                    ecosystem: "Maven",
                    severity: getSeverityFromConfig(),
                  });
                }
              }
            }
            return [scanRequest, excludedPackages];
}


export function PomXMLPackageParser(highlightedText:any){

  var excludedPackages: any = [];
  var scanRequest: any = [];

  extractData(highlightedText, "groupId").map((group, index) => {
    let packagename =
      group + "." + extractData(highlightedText, "artifactId")[index];
    let version = extractData(highlightedText, "version")[index] || "";
    scanRequest.push({
      version: version ? version : "",
      name: packagename,
      ecosystem: "Maven",
      severity: getSeverityFromConfig(),
    });
  });
  console.log("scanRequest", scanRequest);
  return [scanRequest, excludedPackages];
}
