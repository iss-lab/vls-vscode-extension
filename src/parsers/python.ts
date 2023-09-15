/* eslint-disable @typescript-eslint/naming-convention */
import * as constants from "../constants";
import { getSeverityFromConfig } from "../utils";

export function PyPIFileParser(fileContents: any){

    var excludedPackages: any = [];
    var scanRequest: any = [];

    var highlightedTextArray = fileContents.split("\n");
      highlightedTextArray.forEach((element: string) => {
        if (constants.delimiters.python_excluded.test(element)) {
          excludedPackages.push({
            package_name: element.trim(),
            not_scanned: true,
            vulnerable_versions: {},
          });
        } else {
          let packageNameSplit = element.split(constants.delimiters.python_included);
          scanRequest.push({
            version: packageNameSplit[1] ? packageNameSplit[1] : "",
            name: packageNameSplit[0],
            ecosystem: "PyPI",
            severity: getSeverityFromConfig(),
          });
        }
      });

      return [scanRequest, excludedPackages];
}

export function PyPIPackageParser(highlightedText: any){

  var excludedPackages: any = [];
  var scanRequest: any = [];

  var highlightedTextArray = highlightedText.split("\n");
          highlightedTextArray.forEach((element) => {
            if (constants.delimiters.python_excluded.test(element)) {
              excludedPackages.push({
                package_name: element.trim(),
                not_scanned: true,
                vulnerable_versions: {},
              });
            } else {
              let packageNameSplit = element.split(
                constants.delimiters.python_included
              );
              scanRequest.push({
                version: packageNameSplit[1] ? packageNameSplit[1] : "",
                name: packageNameSplit[0],
                ecosystem: "PyPI",
                severity: getSeverityFromConfig(),
              });
            }
          });
        return [scanRequest, excludedPackages];
}