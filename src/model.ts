/* eslint-disable @typescript-eslint/naming-convention */
export interface scan_request{
    version: string
    name: string;
    ecosystem: string;
    severity: string;

}

export interface scan_request_list{
    scan_request: scan_request[];
}

export interface TomlObject {
    package?: {
      name?: string;
      version?:string
    };
    dependencies?: Record<string, string | Record<string, any>>;
    
  }