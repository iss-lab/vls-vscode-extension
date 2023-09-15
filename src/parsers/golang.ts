/* eslint-disable @typescript-eslint/naming-convention */
import * as toml from "@iarna/toml";
import axios from "axios";
import * as fs from "fs";
import * as vscode from "vscode";
import { getSeverityFromConfig } from "../utils";


export function GolangFileParser(fileContents: string) {
  
  var excludedPackages: any = [];
  var scanRequest: any = [];
  var lines = fileContents.split("\n");

  for (let line of lines) {
    line = line.trim();
    if (line === '') {
      continue;
    }
    if (line.startsWith("module ") || line.startsWith("go ") || line.startsWith("require (") || line === ")") {
      continue;
    }
    if (line.includes("// indirect")) {
      line = line.replace(/\/\/ indirect/g, '').trim();
    }
    let lastSpaceIndex = line.lastIndexOf(" ");
    if (lastSpaceIndex > 0) {
      let packageName = line.substring(0, lastSpaceIndex).trim();
      let version = line.substring(lastSpaceIndex + 1).trim();
      scanRequest.push({
        version: version,
        name: packageName,
        ecosystem: "Go",
        severity: getSeverityFromConfig(),
      });
    } else {
      scanRequest.push({
        version: "",
        name: line,
        ecosystem: "Go",
        severity: getSeverityFromConfig(),
      });
    }
  }
  return [scanRequest, excludedPackages];
}


export function GolangPackageParser(highlightedText: any){  

  var excludedPackages: any = [];
  var scanRequest: any = [];
  var lines = highlightedText.split("\n");

  for (let line of lines) {
    line = line.trim();
    if (line === '') {
      continue;
    }
    if (line.startsWith("module ") || line.startsWith("go ") || line.startsWith("require (") || line === ")") {
      continue;
    }
    if (line.includes("// indirect")) {
      line = line.replace(/\/\/ indirect/g, '').trim();
    }
    let lastSpaceIndex = line.lastIndexOf(" ");
    if (lastSpaceIndex > 0) {
      let packageName = line.substring(0, lastSpaceIndex).trim();
      let version = line.substring(lastSpaceIndex + 1).trim();
      scanRequest.push({
        version: version,
        name: packageName,
        ecosystem: "Go",
        severity: getSeverityFromConfig(),
      });
    } else {
      scanRequest.push({
        version: "",
        name: line,
        ecosystem: "Go",
        severity: getSeverityFromConfig(),
      });
    }
  }
  return [scanRequest, excludedPackages];
}