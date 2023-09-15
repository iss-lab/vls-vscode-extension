/* eslint-disable @typescript-eslint/naming-convention */
import * as toml from "@iarna/toml";
import * as constants from "../constants";
import { TomlObject} from "../model";
import { getSeverityFromConfig } from "../utils";

export function RustLockFileParser(fileContents: any) {
  var excludedPackages: any = [];
  var scanRequest: any = [];

  let tomlObject = toml.parse(fileContents) as TomlObject;
  if (tomlObject && Array.isArray(tomlObject.package)) {
    tomlObject.package.forEach((pkg: any) => {
      if (pkg && pkg.name && pkg.version) {
        let packageName = pkg.name;
        let packageVersion = pkg.version;
        scanRequest.push({
          version: packageVersion ? packageVersion : "",
          name: packageName,
          ecosystem: "crates.io",
          severity: getSeverityFromConfig(),
        });
      }
    });
  }
  return [scanRequest, excludedPackages];
}

export function RustTomlFileParser(fileContents: any) {

  var excludedPackages: any = [];
  var scanRequest: any = [];

  var temp = fileContents.split("\n");
  var isPackageSection = false;
  var packageInfo: { name?: string; version?: string } = {};

  for (var i = 0; i < temp.length; i += 1) {
    let line = temp[i];

    if (constants.delimiters.crates_excluded.test(line)) {
      excludedPackages.push({
        package_name: line.trim(),
        not_scanned: true,
        vulnerable_versions: {},
      });
    } else if (line.trim() === "[package]") {
      isPackageSection = true;
    } else if (line.trim() === "" && isPackageSection) {
      isPackageSection = false;
    } else if (!isPackageSection) {
      let parts = line.split("=").map((part: string) => part.trim());
      if (parts.length === 2) {
        const packageName = parts[0];
        let version = parts[1].replace(/"/g, "").trim();

        if (!packageName.includes(" ")) {
          scanRequest.push({
            name: packageName,
            version: version ? version : "",
            ecosystem: "crates.io",
            severity: getSeverityFromConfig(),
          });
        }
      }
    } else {
      let parts = line.split("=").map((part: string) => part.trim());
      if (parts.length === 2) {
        const packageField = parts[0];
        let packageValue = parts[1].replace(/"/g, "").trim();

        if (packageField === "name" || packageField === "version") {
          packageInfo[packageField] = packageValue;
        }
      }
    }
  }
  if (packageInfo.name && packageInfo.version) {
    scanRequest.push({
      name: packageInfo.name,
      version: packageInfo.version,
      ecosystem: "crates.io",
      severity: getSeverityFromConfig(),
    });
  }
  return [scanRequest, excludedPackages];
}

export function RustLockPackageParser(highlightedText: any){

  var excludedPackages: any = [];
  var scanRequest: any = [];

  let tomlObject = toml.parse(highlightedText) as TomlObject;
  if (tomlObject && Array.isArray(tomlObject.package)) {
    tomlObject.package.forEach((pkg: any) => {
      if (pkg && pkg.name && pkg.version) {
        let packageName = pkg.name;
        let packageVersion = pkg.version;
        scanRequest.push({
          version: packageVersion ? packageVersion : "",
          name: packageName,
          ecosystem: "crates.io",
          severity: getSeverityFromConfig(),
        });
      } else {
        excludedPackages.push({
          package_name: pkg.name,
          not_scanned: true,
          vulnerable_versions: {},
        });
      }
    });
  }
  return [scanRequest, excludedPackages];

}

export function RustTomlPackageParser(highlightedText: any){

  var excludedPackages: any = [];
  var scanRequest: any = [];
  var temp = highlightedText.split("\n");
            var packageInfo: { name?: string; version?: string } = {};
            var packageSection = false;

            for (var i = 0; i < temp.length; i += 1) {
              let line = temp[i];

              if (line.trim() === "[package]") {
                packageSection = true;
                continue;
              } else if (line.trim() === "" && packageSection) {
                packageSection = false;
                continue;
              }

              if (packageSection) {
                let parts = line.split("=").map((part) => part.trim());
                if (parts.length === 2) {
                  let packageName = parts[0];
                  let version = parts[1].replace(/"/g, "").trim();

                  if (packageName === "name" || packageName === "version") {
                    packageInfo[packageName] = version;
                  }
                }
              } else {
                let parts = line.split("=").map((part) => part.trim());
                if (parts.length === 2) {
                  let packageName = parts[0];
                  let version = parts[1].replace(/"/g, "").trim();

                  if (packageName.includes(" ")) {
                    excludedPackages.push({
                      package_name: packageName,
                      not_scanned: true,
                      vulnerable_versions: {},
                    });
                  } else {
                    scanRequest.push({
                      name: packageName === "name" ? version : packageName,
                      version: packageName === "name" ? "" : version,
                      ecosystem: "crates.io",
                      severity: getSeverityFromConfig(),
                    });
                  }
                }
              }
            }
            if (packageInfo.name) {
              scanRequest.push({
                name: packageInfo.name,
                version: packageInfo.version ? packageInfo.version : "",
                ecosystem: "crates.io",
                severity: getSeverityFromConfig(),
              });
            }
  return [scanRequest, excludedPackages];
}