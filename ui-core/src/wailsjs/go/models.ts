export namespace main {
	
	export class BulkUpdateRequest {
	    username: string;
	    password: string;
	    targetPlextrac: string;
	    clientId: string;
	    reportId: string;
	    findingIds: string[];
	    updateType: string;
	    tags?: string[];
	    status?: string;
	
	    static createFrom(source: any = {}) {
	        return new BulkUpdateRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.clientId = source["clientId"];
	        this.reportId = source["reportId"];
	        this.findingIds = source["findingIds"];
	        this.updateType = source["updateType"];
	        this.tags = source["tags"];
	        this.status = source["status"];
	    }
	}
	export class ClientDetailedConfig {
	    username: string;
	    password: string;
	    targetPlextrac: string;
	    clientName: string;
	    snPsCode: string;
	    stateCode: string;
	
	    static createFrom(source: any = {}) {
	        return new ClientDetailedConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.clientName = source["clientName"];
	        this.snPsCode = source["snPsCode"];
	        this.stateCode = source["stateCode"];
	    }
	}
	export class FieldValue {
	    key: string;
	    label: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new FieldValue(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.label = source["label"];
	        this.value = source["value"];
	    }
	}
	export class Finding {
	    flaw_id: string;
	    title: string;
	    severity: string;
	    status: string;
	    description: string;
	    recommendations: string;
	    tags: string[];
	    fields: FieldValue[];
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.flaw_id = source["flaw_id"];
	        this.title = source["title"];
	        this.severity = source["severity"];
	        this.status = source["status"];
	        this.description = source["description"];
	        this.recommendations = source["recommendations"];
	        this.tags = source["tags"];
	        this.fields = this.convertValues(source["fields"], FieldValue);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FindingsRequest {
	    username: string;
	    password: string;
	    targetPlextrac: string;
	    clientId: string;
	    reportId: string;
	
	    static createFrom(source: any = {}) {
	        return new FindingsRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.clientId = source["clientId"];
	        this.reportId = source["reportId"];
	    }
	}
	export class FindingsResponse {
	    success: boolean;
	    findings?: Finding[];
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new FindingsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class N2PConfig {
	    username: string;
	    password: string;
	    clientId: string;
	    reportId: string;
	    scope: string;
	    directory: string;
	    targetPlextrac: string;
	    screenshotDir: string;
	    nonCore: boolean;
	    clientConfig: string;
	    overwrite: boolean;
	
	    static createFrom(source: any = {}) {
	        return new N2PConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.clientId = source["clientId"];
	        this.reportId = source["reportId"];
	        this.scope = source["scope"];
	        this.directory = source["directory"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.screenshotDir = source["screenshotDir"];
	        this.nonCore = source["nonCore"];
	        this.clientConfig = source["clientConfig"];
	        this.overwrite = source["overwrite"];
	    }
	}
	export class ReportDetailedConfig {
	    username: string;
	    password: string;
	    targetPlextrac: string;
	    clientId: string;
	    reportName: string;
	    reportTemplate: string;
	    customFieldTemplate: string;
	
	    static createFrom(source: any = {}) {
	        return new ReportDetailedConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.clientId = source["clientId"];
	        this.reportName = source["reportName"];
	        this.reportTemplate = source["reportTemplate"];
	        this.customFieldTemplate = source["customFieldTemplate"];
	    }
	}
	export class UpdateFindingRequest {
	    username: string;
	    password: string;
	    targetPlextrac: string;
	    clientId: string;
	    reportId: string;
	    findingId: string;
	    updateType: string;
	    severity?: string;
	    status?: string;
	    customFields?: FieldValue;
	
	    static createFrom(source: any = {}) {
	        return new UpdateFindingRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.password = source["password"];
	        this.targetPlextrac = source["targetPlextrac"];
	        this.clientId = source["clientId"];
	        this.reportId = source["reportId"];
	        this.findingId = source["findingId"];
	        this.updateType = source["updateType"];
	        this.severity = source["severity"];
	        this.status = source["status"];
	        this.customFields = this.convertValues(source["customFields"], FieldValue);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class UpdateResponse {
	    success: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.error = source["error"];
	    }
	}

}

export namespace plugin {
	
	export class PluginInfo {
	    id: string;
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new PluginInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	    }
	}
	export class CategoryInfo {
	    name: string;
	    writeup_db_id: string;
	    writeup_name: string;
	    plugin_count: number;
	    plugins?: PluginInfo[];
	
	    static createFrom(source: any = {}) {
	        return new CategoryInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.writeup_db_id = source["writeup_db_id"];
	        this.writeup_name = source["writeup_name"];
	        this.plugin_count = source["plugin_count"];
	        this.plugins = this.convertValues(source["plugins"], PluginInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

