package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/beevik/etree"
	"github.com/sirupsen/logrus"
)

type GenConfig struct {
	regen bool
}

var log = logrus.New()

func main() {
	// Initialize with regen as false
	genConfig := &GenConfig{regen: false}
	genConfig.Run()
}

func (gc *GenConfig) Run() {
	nessusFilePath := "creator/plugins-2023-10-02.xml"
	outputFilePath := "config.json"
	nessus7zFile := "plugins-2023-10-02.7z"

	if !fileExists(nessusFilePath) {
		err := extract7z(nessus7zFile, ".")
		if err != nil {
			log.Fatalf("Error extracting 7z file: %v", err)
		}
		log.Infof("Extracted %s to current directory", nessus7zFile)
	}

	gc.checkRegen(outputFilePath)

	parsedResults := gc.parseNessusPolicyFile(nessusFilePath)
	gc.saveResultsToJSON(parsedResults, outputFilePath)

	destPath := "internal/config/config.json"
	err := moveFile(outputFilePath, destPath)
	if err != nil {
		log.Fatalf("Error moving file to %s: %v", destPath, err)
	}
	log.Infof("Moved %s to %s", outputFilePath, destPath)
	log.Info("Done")
}

func (gc *GenConfig) checkRegen(outputFilePath string) {
	if gc.regen {
		err := os.Remove(outputFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warnf("%s not found, nothing to remove.", outputFilePath)
			} else {
				log.Errorf("Error removing %s: %v", outputFilePath, err)
			}
		} else {
			log.Info("Config will be regenerated - please wait ...")
		}
	}
}

func (gc *GenConfig) categorizePlugins(results map[string]map[string][]string) map[string]map[string]interface{} {
	// Base commands
	nmap := "nmap -T4 --host-timeout 300s"
	msf := "sudo msfconsole"
	redisBase := "redis-cli"
	sudoNmap := "sudo nmap -T4 --host-timeout 300s"

	// Metasploit
	metasploitIPMI := "-q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts {host} ; set rport {port} ; run; exit'"
	metasploitIKE := "-q -x 'use auxiliary/scanner/ike/cisco_ike_benigncertain; set rhosts {host} ; set rport {port} ; run; exit'"
	metasploitNLA := "-q -x 'use auxiliary/scanner/rdp/rdp_scanner; set rhosts {host} ; set rport {port} ; run; exit'"
	metasploitSQLsa := "-q -x 'use auxiliary/scanner/mssql/mssql_login; set rhosts {host} ; set rport {port} ; run; exit'"

	// Nmap
	serviceVersion := "-sC -sV {host} -p {port}"
	sslCert := "--script ssl-cert {host} -p {port}"
	sshEnumCiphers := "--script ssh2-enum-algos {host} -p {port}"
	enumTLSCiphers := "--script ssl-enum-ciphers {host} -p {port}"
	redisInfo := "-h {host} info && sleep 1 && echo -e 'quit\n'"
	snmpPublic := "-v 2c -c public -w {host}"
	smbSigning := "--script smb2-security-mode {host} -p {port}"
	osVersion := "-sC -sV -O {host}"
	nfsShowmount := "--script nfs-showmount {host} -p {port}"
	nfsLs := "--script nfs-ls {host} -p {port}"
	//httpEnum := "--script http-enum {host} -p {port}"
	anonFTP := "--script ftp-anon {host} -p {port}"
	logjamTest := "--script ssl-dh-params {host} -p {port}"
	apacheCassandra := "--script cassandra-brute {host} -p {port}"
	ipForwarding := "{host} --script ip-forwarding --script-args='target=google.com'"
	rdpEnumEncryption := "--script rdp-enum-encryption {host} -p {port}"
	testHeaders := "--script http-security-headers {host} -p {port}"

	// Curl
	//curlHeaders := "curl --silent -I -L -k https://{host}:{port} || curl --silent -I -L http://{host}:{port}"
	jqueryCurlCheck := "curl --silent -L -i http://{host}:{port} | grep -i jquery || (echo '_' && curl --silent -k -L -i https://{host}:{port} | grep -i jquery || echo '_')"
	puppetCurlCheck := "curl --silent -L -i http://{host}:{port} | grep -i puppet || (echo '_' && curl --silent -k -L -i https://{host}:{port} | grep -i puppet || echo '_')"
	hashicorpCurlCheck := "curl --silent -L -i http://{host}:{port} | grep -i Hashicorp || (echo '_' && curl --silent -k -L -i https://{host}:{port} | grep -i Hashicorp || echo '_')"
	webServerAutoComplete := "curl --silent -L -i http://{host}:{port} | grep -i autocomplete || (echo '_' && curl --silent -k -L -i https://{host}:{port} | grep -i autocomplete || echo '_')"

	categorizedResults := make(map[string]map[string]interface{})
	categorizedIDs := make(map[string]bool)

	categories := map[string]map[string]interface{}{
		"Default_MSSQL_Checks": {
			"primary_keywords": []string{"Microsoft SQL Server sa Account Default Blank Password"},
			"scan_type":        msf,
			"parameters":       metasploitSQLsa,
			"verify_words":     []string{"Login Successful:"},
		},
		"ArubaOS_OOD_Checks": {
			"primary_keywords": []string{"ArubaOS-Switch Ripple20 Multiple Vulnerabilities (ARUBA-PSA-2020-006)"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"up"},
		},
		"Java_RMI_Checks": {
			"primary_keywords": []string{"Java JMX Agent Insecure Configuration"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"up", "Java RMI"},
		},
		"OOD_MSSQL_Checks": {
			"primary_keywords": []string{"Microsoft SQL Server Unsupported Version Detection (remote check)"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"version"},
		},
		"Web_Server_Auto_Complete_Checks": {
			"primary_keywords": []string{"Web Server Allows Password Auto-Completion"},
			"scan_type":        "",
			"parameters":       webServerAutoComplete,
			"verify_words":     []string{"autocomplete"},
		},
		"jQuery_Checks": {
			"primary_keywords": []string{"JQuery"},
			"scan_type":        "",
			"parameters":       jqueryCurlCheck,
			"verify_words":     []string{"jquery"},
		},
		"Puppet_enterprise_Checks": {
			"primary_keywords": []string{"Puppet Enterprise"},
			"scan_type":        "",
			"parameters":       puppetCurlCheck,
			"verify_words":     []string{"Puppet"},
		},
		"Logjam_Checks": {
			"primary_keywords": []string{"SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)"},
			"scan_type":        nmap,
			"parameters":       logjamTest,
			"verify_words":     []string{"VULNERABLE"},
		},
		"Hashicorp_API_Checks": {
			"primary_keywords": []string{"Hashicorp Consul Web UI and API access"},
			"scan_type":        "",
			"parameters":       hashicorpCurlCheck,
			"verify_words":     []string{"HashiCorp"},
		},
		"Insecure_NLA_Checks": {
			"primary_keywords": []string{"Terminal Services Doesn't Use Network Level Authentication (NLA) Only"},
			"scan_type":        msf,
			"parameters":       metasploitNLA,
			"verify_words":     []string{"Requires NLA: No"},
		},
		"Anon_FTP_Checks": {
			"primary_keywords": []string{"Anonymous FTP Enabled"},
			"scan_type":        nmap,
			"parameters":       anonFTP,
			"verify_words":     []string{"ftp-anon", "allowed"},
		},
		"Redis_Passwordless_Checks": {
			"primary_keywords": []string{"Redis Server Unprotected by Password Authentication"},
			"scan_type":        redisBase,
			"parameters":       redisInfo,
			"verify_words":     []string{"redis_version"},
		},
		"NFS_Mount_List_Checks": {
			"primary_keywords": []string{"NFS Share User Mountable"},
			"scan_type":        nmap,
			"parameters":       nfsLs,
			"verify_words":     []string{"nfs-ls:", "up"},
		},
		"NFS_Mount_Checks": {
			"primary_keywords": []string{"NFS Exported Share Information Disclosure", "NFS Shares World Readable"},
			"scan_type":        nmap,
			"parameters":       nfsShowmount,
			"verify_words":     []string{"nfs-showmount:", "up"},
		},
		"SSL_cert_Checks": {
			"primary_keywords": []string{"ssl"},
			"scan_type":        nmap,
			"parameters":       sslCert,
			"verify_words":     []string{"ssl-cert", "subject", "up"},
		},
		"Tomcat_Checks": {
			"primary_keywords": []string{"tomcat"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"tomcat", "up"},
		},
		"Esxi_Checks": {
			"primary_keywords": []string{"esxi"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"up"},
		},
		"Nginx_Checks": {
			"primary_keywords": []string{"nginx"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"nginx", "up"},
		},
		"vCenter_Checks": {
			"primary_keywords": []string{"vcenter"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"vcenter", "up"},
		},
		"PHP_Checks": {
			"primary_keywords": []string{"php"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"php", "up"},
		},
		"SNMP_Public_Checks": {
			"primary_keywords": []string{"snmp agent"},
			"scan_type":        "snmp-check",
			"parameters":       snmpPublic,
			"verify_words":     []string{"system information", "hostname"},
		},
		"SMB_Signing_Checks": {
			"primary_keywords": []string{"SMB", "Microsoft Windows SMB Guest Account Local User Access"},
			"scan_type":        nmap,
			"parameters":       smbSigning,
			"verify_words":     []string{"up", "smb", "signing"},
		},
		"TLS_Version_Checks": {
			"primary_keywords": []string{"TLS", "SSL"},
			"scan_type":        nmap,
			"parameters":       enumTLSCiphers,
			"verify_words":     []string{"ciphers", "up"},
		},
		"SSH_Cipher_Checks": {
			"primary_keywords": []string{"ssh"},
			"scan_type":        nmap,
			"parameters":       sshEnumCiphers,
			"verify_words":     []string{"ssh2-enum-algos", "up"},
		},
		"Dell_iDRAC_Checks": {
			"primary_keywords": []string{"idrac", "dell"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"idrac", "up"},
		},
		"Apache_HTTP_Checks": {
			"primary_keywords": []string{"apache"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"up"},
		},
		"Python_Unsupported_Checks": {
			"primary_keywords": []string{"python"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"python", "up"},
		},
		"Unsupported_Unix_OS_Checks": {
			"primary_keywords": []string{"Unix"},
			"scan_type":        sudoNmap,
			"parameters":       osVersion,
			"verify_words":     []string{"OS details", "up"},
		},
		"NTP_Mode6_Checks": {
			"primary_keywords": []string{"Network Time Protocol (NTP) Mode 6 Scanner"},
			"scan_type":        "ntpq",
			"parameters":       "-c rv {host}",
			"verify_words":     []string{"host", "ntpd", "ntp", "system", "clock="},
		},
		"OpenSSL_Version_Checks": {
			"primary_keywords": []string{"openssl"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"openssl", "up"},
		},
		"Splunk_Version_Checks": {
			"primary_keywords": []string{"splunk"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"splunk"},
		},
		"Clickjacking_Checks": {
			"primary_keywords": []string{"Web Application Potentially Vulnerable to Clickjacking"},
			"scan_type":        nmap,
			"parameters":       testHeaders,
			"verify_words":     []string{"HTTP/1.1 200 OK"},
		},
		"IPMI_Metasploit_Checks": {
			"primary_keywords": []string{"ipmi v2.0 password hash disclosure"},
			"scan_type":        msf,
			"parameters":       metasploitIPMI,
			"verify_words":     []string{"hash found"},
		},
		"IKE_Metasploit_Checks": {
			"primary_keywords": []string{"Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key"},
			"scan_type":        msf,
			"parameters":       metasploitIKE,
			"verify_words":     []string{"leak", "ike"},
		},
		"HP_iLO_Version_Checks": {
			"primary_keywords": []string{"ilo"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"ilo", "up"},
		},
		"AMQP_Info_Checks": {
			"primary_keywords": []string{"AMQP Cleartext Authentication"},
			"scan_type":        nmap,
			"parameters":       "--script amqp-info {host} -p {port}",
			"verify_words":     []string{"up", "amqp"},
		},
		"Cleartext_Comms_Checks": {
			"primary_keywords": []string{"Web Server Uses Basic Authentication Without HTTPS", "Web Server Transmits Cleartext Credentials", "Unencrypted Telnet Server", "FTP Supports Cleartext Authentication"},
			"scan_type":        nmap,
			"parameters":       serviceVersion,
			"verify_words":     []string{"version", "up"},
		},
		"Rdp_Encryption_Checks": {
			"primary_keywords": []string{"Remote Desktop Protocol Server Man-in-the-Middle Weakness", "Unsecured Terminal Services Configuration", "Terminal Services Encryption Level is not FIPS-140 Compliant", "Terminal Services Encryption Level is Medium or Low"},
			"scan_type":        nmap,
			"parameters":       rdpEnumEncryption,
			"verify_words":     []string{"RDP", "up"},
		},
		"IP_Forwarding_Checks": {
			"primary_keywords": []string{"IP Forwarding Enabled"},
			"scan_type":        nmap,
			"parameters":       ipForwarding,
			"verify_words":     []string{"enabled", "up"},
		},
		"Apache_Cassandra_Checks": {
			"primary_keywords": []string{"Apache Cassandra Default Credentials"},
			"scan_type":        sudoNmap,
			"parameters":       apacheCassandra,
			"verify_words":     []string{"cassandra", "up"},
		},
	}

	for scriptName, pluginData := range results {
		pluginIDs := pluginData["ids"]

		for category, categoryData := range categories {
			primaryKeywords := categoryData["primary_keywords"].([]string)
			scanType := categoryData["scan_type"].(string)
			parameters := categoryData["parameters"].(string)
			verifyWords := categoryData["verify_words"].([]string)

			for _, primaryKeyword := range primaryKeywords {
				if strings.Contains(strings.ToLower(scriptName), strings.ToLower(primaryKeyword)) {
					if _, exists := categorizedResults[category]; !exists {
						categorizedResults[category] = map[string]interface{}{
							"ids":          []string{},
							"scan_type":    scanType,
							"parameters":   parameters,
							"verify_words": verifyWords,
						}
					}

					for _, pluginID := range pluginIDs {
						if !categorizedIDs[pluginID] {
							categorizedResults[category]["ids"] = append(categorizedResults[category]["ids"].([]string), pluginID)
							categorizedIDs[pluginID] = true
						}
					}
					break
				}
			}
		}
	}

	return categorizedResults
}

func (gc *GenConfig) parseNessusPolicyFile(filePath string) map[string]map[string]interface{} {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(filePath); err != nil {
		log.Fatalf("Error reading Nessus policy file: %v", err)
	}

	results := make(map[string]map[string][]string)

	allowedScriptFamilies := []string{
		"Backdoors", "Brute force attacks", "CGI abuses", "CGI abuses : XSS", "CISCO", "Databases",
		"Default Unix Accounts", "DNS", "Firewalls", "FTP", "Gain a shell remotely", "General",
		"Misc.", "Netware", "Peer-To-Peer File Sharing", "RPC", "SCADA", "Service detection",
		"Settings", "SMTP problems", "SNMP", "Tenable.ot", "Web Servers", "Windows",
	}

	for _, naslElement := range doc.FindElements("//nasl") {
		scriptNameElement := naslElement.FindElement("script_name")
		if scriptNameElement != nil {
			scriptName := strings.TrimSpace(scriptNameElement.Text())

			scriptIDElement := naslElement.FindElement("script_id")
			if scriptIDElement != nil {
				scriptID := strings.TrimSpace(scriptIDElement.Text())

				riskFactorElement := naslElement.FindElement(".//attribute[@name='risk_factor']/value")
				if riskFactorElement != nil && strings.ToLower(strings.TrimSpace(riskFactorElement.Text())) == "none" {
					continue
				}

				scriptFamilyElement := naslElement.FindElement("script_family")
				if scriptFamilyElement != nil {
					scriptFamily := strings.TrimSpace(scriptFamilyElement.Text())
					if contains(allowedScriptFamilies, scriptFamily) {
						if _, exists := results[scriptName]; !exists {
							results[scriptName] = map[string][]string{"ids": {}}
						}
						if !contains(results[scriptName]["ids"], scriptID) {
							results[scriptName]["ids"] = append(results[scriptName]["ids"], scriptID)
						}
					}
				}
			}
		}
	}

	return gc.categorizePlugins(results)
}

func (gc *GenConfig) saveResultsToJSON(results map[string]map[string]interface{}, outputFile string) {
	jsonData := map[string]interface{}{"plugins": results}
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(jsonData); err != nil {
		log.Fatalf("Error encoding JSON data: %v", err)
	}
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func extract7z(archivePath, extractPath string) error {
	cmd := exec.Command("7z", "x", archivePath, "-o"+extractPath)
	return cmd.Run()
}

func moveFile(sourcePath, destPath string) error {
	err := os.MkdirAll(filepath.Dir(destPath), os.ModePerm)
	if err != nil {
		return fmt.Errorf("error creating directories: %w", err)
	}
	return os.Rename(sourcePath, destPath)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}
