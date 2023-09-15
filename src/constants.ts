/* eslint-disable @typescript-eslint/naming-convention */
export const languageIdKeyMap = {
    "golang": ["go"],
    "python": ["python", "pip-requirements"],
    "nodejs": ["javascript","typescript","javascriptreact","typescriptreact"],
    "rust": ["rust"],
    "maven" : ["java", "Groovy", "XML"]
};

export const dependencyStandardFileNames = {
      "golang": ["go.mod"],
      "nodejs": ["package.json"],
      "nodejslock": ["package-lock.json"],
      "rust": ["cargo.toml"],
      "rustlock": ["cargo.lock"],
      "python": ["requirements.txt"],
      "mavenxml": ["pom.xml"],
      "mavengradle": ["build.gradle"]
};

export const ecosystemSupported = {
    "Golang": "Go",
    "Python": "PyPI",
    "Rust": "crates.io",
    "Node/Typescript/Javascript/JS Frameworks": "npm",
    "Java": "Maven"
};

export const vulnerabilityScore = {
    "none": 1,
    "low": 2,
    "moderate": 3,
    "high": 4,
    "critical": 5
};

export const delimiters = {
    "python_excluded": /!=|<|>|<=|>=|\*|\^/,
    "python_included": /==|\r|\n/,
    "node_excluded": /!=|<|>|<=|>=|\*|\^/,
    "nodes_included": /==|\r|\n/,
    "node_match": /"version": "(.*?)"/,
    "crates_excluded": /!=|<|>|<=|>=|\*|\^/,
    "maven_excluded": /[()\[\],|+-]/
};