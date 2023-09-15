# Vulnerability Lookup Service (VLS)

Vulnerability Lookup Service is a tool to identify potential security vulnerabilities in external packages. This service will provide information of known vulnerabilities available on the internet.

The primary use of the VLS is to help organizations and individuals stay informed about the latest security threats and security posture of the application.
By regularly scanning dependency file/s that contains packages used in a particular project against a vulnerability database, users can identify any known vulnerabilities that may be exploited by malicious actors.

## Features
1. Multiple Package Ecosystem scan support:
VLS can scan external packages for vulnerabilities across multiple ecosystems. Currently supported ecosystems are NPM/Javascript, PyPI/Python, Maven/Java, Crates.io/Rust, Go/Golang with support for other ecosystems underway. 

2. Single Package & Full File Scan support
Using VLS, a user can scan for selected packages in the dependency file or the full file via actions available in right-click options.

3. Configurable Severity filter: 
User can configure minimum severity of vulnerabilities that is to be flagged.

## Installation

VLS VSCODE extension also requires the VLS-API to run in your environment.

**Build and Run VLS API**

VLS API is available as a docker container. To build and run the VLS-API, follow these steps

1. Clone VLS-API from [here](https://github.com/iss-lab/vls-api.git)

2. Build VLS docker image using
    ```docker
    docker build -t iss-lab/vls-api .
    ```
3. Run the docker container
    ```docker
    docker run -d -p 3000:3000 iss-lab/vls-api
    ```
4. VLS-API will now be accessible via `http://localhost:3000/`

<br/>

**Install VLS Extension**

The Extension is packaged as a VSIX file available in the build/ folder of this repository which can be installed using either of the following ways:

1. Using "Install from VSIX" option available in the extensions sidebar in VSCODE. The option will be available on clicking the three dots ("Views and more actions") in the extensions sidebar on the top.
2. Using the below command to install the extension from the specified .vsix file.

```bash 
code --install-extension path/to/extension.vsix
```

 

## Configuration

VLS can be configured via options that are available in the "User Settings" in VSCODE under the VLS heading. Configuration options are documented below:

1. VLS: API URL - The HTTP/HTTPS URL of your VLS-API (Default - http://localhost:3000)
2. VLS: Severity - Dropdown to configure minimum severity of vulnerabilities to show.
3. VLS: Show all packages - Checkbox to show all packages including the non-vulnerable ones.

## Usage

VLS can scan packages from known dependency files like package.json/package-lock.json/requirements.txt/go.mod/build.gradle/pom.xml/cargo.toml/cargo.lock. 

For single package:
Select the name of the package, right-click and select **Lookup Vulnerability for Package** option.

For file:
Right-click on the file and select **Lookup Vulnerability in File** option.

You can view the Vulnerable packages in a tab called **VULNERABLE PACKAGES** which is next to terminal in the bottom panel on VSCODE. 

## Note

Currently VLS only supports direct version scans and does not infer versions. 

For Example in Python/requirements.txt file, only packages with no version or with ==version can be scanned. Packages with versions like >=version etc. will not be scanned and will be shown as (Package cannot be scanned) in the result panel. 

For packages with no version being specified, results of all versions will be displayed.