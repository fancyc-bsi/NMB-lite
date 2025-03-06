export namespace main {
	
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

