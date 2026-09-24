/**
 * Phase 3 — Seed ~200 Software nodes, 20 Sector nodes, and link ThreatActor→Sector (TARGETS).
 * Also links the curated flagship AFFECTS edges. Idempotent (MERGE).
 */
const { getDriver } = require('../../config/neo4j');
const { linkTargets } = require('../services/ingest/attack-stix');

// vendor/product lists — commonly attacked software (hand-curated, per plan)
const PRODUCTS = [
  // Apache
  ['apache', 'http_server'], ['apache', 'tomcat'], ['apache', 'log4j'], ['apache', 'struts'],
  ['apache', 'ofbiz'], ['apache', 'kafka'], ['apache', 'spark'], ['apache', 'hadoop'],
  ['apache', 'cassandra'], ['apache', 'druid'], ['apache', 'flink'], ['apache', 'solr'],
  ['apache', 'commons_text'], ['apache', 'shiro'], ['apache', 'activemq'], ['apache', 'velocity'],
  // Microsoft
  ['microsoft', 'windows_10'], ['microsoft', 'windows_11'], ['microsoft', 'windows_server'], ['microsoft', 'exchange_server'],
  ['microsoft', 'office'], ['microsoft', 'outlook'], ['microsoft', 'sharepoint_server'], ['microsoft', 'iis'],
  ['microsoft', 'azure_ad'], ['microsoft', 'power_bi'], ['microsoft', 'visual_studio'], ['microsoft', 'sql_server'],
  ['microsoft', 'edge'], ['microsoft', 'onedrive'], ['microsoft', 'teams'], ['microsoft', 'hyper-v'],
  ['microsoft', 'remote_desktop'], ['microsoft', 'entra_id'],
  // Google
  ['google', 'chrome'], ['google', 'android'], ['google', 'cloud_platform'],
  // Adobe
  ['adobe', 'acrobat_reader'], ['adobe', 'acrobat'], ['adobe', 'flash_player'], ['adobe', 'coldfusion'],
  ['adobe', 'experience_manager'],
  // Oracle
  ['oracle', 'weblogic_server'], ['oracle', 'java_se'], ['oracle', 'mysql'], ['oracle', 'database_server'],
  ['oracle', 'peoplesoft'], ['oracle', 'fusion_middleware'], ['oracle', 'siebel_crm'], ['oracle', 'ebs'],
  // Cisco
  ['cisco', 'ios'], ['cisco', 'ios_xe'], ['cisco', 'asa'], ['cisco', 'firepower'], ['cisco', 'webex'],
  ['cisco', 'small_business_rv'], ['cisco', 'adaptive_security_appliance'], ['cisco', 'telepresence'],
  // Fortinet
  ['fortinet', 'fortios'], ['fortinet', 'fortigate'], ['fortinet', 'fortiproxy'], ['fortinet', 'fortiweb'],
  // VMware
  ['vmware', 'vsphere'], ['vmware', 'esxi'], ['vmware', 'vcenter'], ['vmware', 'workspace_one'],
  ['vmware', 'horizon'], ['vmware', 'cloud_foundation'],
  // Atlassian
  ['atlassian', 'confluence'], ['atlassian', 'jira'], ['atlassian', 'bamboo'], ['atlassian', 'crowd'],
  ['atlassian', 'bitbucket'],
  // DevOps / infra
  ['jenkins', 'jenkins'], ['gitlab', 'gitlab'], ['github', 'enterprise_server'], ['docker', 'docker'],
  ['kubernetes', 'kubernetes'], ['nginx', 'nginx'], ['haproxy', 'haproxy'], ['redis', 'redis'],
  ['elastic', 'elasticsearch'], ['elastic', 'kibana'], ['elastic', 'logstash'], ['mongodb', 'mongodb'],
  ['mysql', 'mysql'], ['mariadb', 'mariadb'], ['postgresql', 'postgresql'], ['sqlite', 'sqlite'],
  ['nodejs', 'node'], ['openjsf', 'lodash'], ['python', 'python'], ['php', 'php'], ['ruby', 'ruby_on_rails'],
  ['jetbrains', 'teamcity'], ['puppet', 'puppet_enterprise'], ['hashicorp', 'terraform'], ['hashicorp', 'vault'],
  ['grafana', 'grafana'], ['prometheus', 'prometheus'], ['ansible', 'ansible'], ['apache', 'airflow'],
  // Security appliances
  ['paloaltonetworks', 'pan-os'], ['paloaltonetworks', 'expedition'], ['citrix', 'netscaler_adc'],
  ['citrix', 'workspace'], ['citrix', 'sharefile'], ['ivanti', 'connect_secure'], ['ivanti', 'endpoint_manager'],
  ['ivanti', 'avalanche'], ['pulse_secure', 'connect_secure'], ['sonicwall', 'sma_100'], ['sonicwall', 'nsv'],
  ['zscaler', 'client_connector'], ['barracuda', 'email_security_gateway'], ['f5', 'big-ip'],
  ['f5', 'nginx_ingress_controller'], ['watchguard', 'firebox'], ['marvell', 'panoptis'], ['sophos', 'xg_firewall'],
  ['checkpoint', 'quantum_security_gateway'], ['fortra', 'goanywhere_mft'], ['progress', 'moveit_transfer'],
  ['progress', 'whatsup_gold'], ['papercut', 'print_management_software'], ['zimbra', 'zimbra_collaboration_suite'],
  // Databases & data
  ['snowflake', 'snowflake'], ['sap', 'netweaver'], ['sap', 'business_objects'], ['couchbase', 'couchbase_server'],
  ['cassandra', 'cassandra'], ['couchdb', 'couchdb'], ['apache', 'hive'], ['apache', 'hbase'], ['apache', 'zookeeper'],
  ['clickhouse', 'clickhouse'], ['timescale', 'timescaledb'], ['influxdata', 'influxdb'], ['neo4j', 'neo4j'],
  // OS / platform
  ['linux', 'linux_kernel'], ['canonical', 'ubuntu'], ['redhat', 'enterprise_linux'], ['debian', 'debian_linux'],
  ['suse', 'linux_enterprise_server'], ['oracle', 'linux'], ['apple', 'macos'], ['apple', 'ios'], ['apple', 'ipados'],
  ['apple', 'tvos'], ['apple', 'watchos'], ['apple', 'safari'], ['apple', 'webkit'], ['mozilla', 'firefox'],
  ['mozilla', 'thunderbird'], ['opera', 'opera'], ['google', 'chrome_os'], ['microsoft', 'windows_vista'],
  ['microsoft', 'windows_7'], ['microsoft', 'windows_8.1'], ['microsoft', 'windows_rt'],
  // Network equipment / IoT
  ['netgear', 'routers'], ['tp-link', 'routers'], ['d-link', 'routers'], ['honeywell', 'experion_pks'],
  ['siemens', 'simatic'], ['schneider_electric', 'ecostruxure'], ['rockwell', 'control_logix'], ['advantech', 'hmi'],
  ['mitsubishi', 'melsec'], ['omron', 'sysmac'], ['wago', 'pfc200'], ['phoenix_contact', 'plcnext'],
  // Cloud / SaaS
  ['aws', 's3'], ['aws', 'iam'], ['amazon', 'ec2'], ['microsoft', 'azure'], ['google', 'gke'], ['cloudflare', 'waf'],
  ['github', 'actions'], ['slack', 'slack'], ['zoom', 'zoom'], ['microsoft', 'mshtml'], ['microsoft', 'word'],
  ['microsoft', 'excel'], ['microsoft', 'powerpoint'], ['libreoffice', 'libreoffice'], ['apache', 'openoffice'],
  // VPN / remote access
  ['openssh', 'openssh'], ['openvpn', 'openvpn'], ['wireguard', 'wireguard'], ['cisco', 'anyconnect'],
  ['paloaltonetworks', 'globalprotect'], ['ivanti', 'zero_trust'], ['citrix', 'gateway'],
  // Web frameworks / libraries
  ['jquery', 'jquery'], ['facebook', 'react'], ['vuejs', 'vue'], ['angular', 'angular'], ['laravel', 'laravel'],
  ['spring', 'spring_framework'], ['spring', 'spring_boot'], ['apache', 'camel'], ['hibernate', 'hibernate'],
  ['drupal', 'drupal'], ['joomla', 'joomla'], ['wordpress', 'wordpress'], ['typo3', 'typo3'], ['moodle', 'moodle'],
  ['openxchange', 'ox_app_suite'], ['roundcube', 'roundcube'], ['horde', 'horde'], ['nextcloud', 'server'],
  ['owncloud', 'owncloud'], ['simple_machines', 'smf'], ['phpmyadmin', 'phpmyadmin'], ['grafana', 'loki'],
  ['datadog', 'agent'], ['newrelic', 'agent'], ['splunk', 'enterprise'], ['splunk', 'universal_forwarder'],
  ['elastic', 'beats'], ['opensearch', 'opensearch'], ['varnish', 'varnish_cache'], ['squid', 'squid'],
  ['apache', 'mod_jk'], ['apache', 'xerces'], ['apache', 'poi'], ['apache', 'pdfbox'], ['openjsf', 'jquery_ui'],
  ['moment', 'moment'], ['guzzlehttp', 'guzzle'], ['lcms', 'limesurvey'], ['greenbone', 'gsa'],
  ['tivoli', 'storage_manager'], ['ibm', 'aspera'], ['ibm', 'websphere'], ['ibm', 'mq'], ['ibm', 'cognos'],
  ['delmia', 'apriso_service'], ['ge', 'proficy'], ['netapp', 'ontap'], ['dell', 'openmanage'], ['hp', 'ilo'],
  ['lenovo', 'xclarity'], ['supermicro', 'ipmi'], ['avaya', 'aura'], ['unify', 'openscape'], ['asterisk', 'asterisk'],
  ['freeswitch', 'freeswitch'], ['kamailio', 'kamailio'],
];

const SECTORS = [
  'Aerospace', 'Agriculture', 'Automotive', 'Communications', 'Construction',
  'Critical Manufacturing', 'Defense', 'Education', 'Energy', 'Financial Services',
  'Food & Beverage', 'Government', 'Healthcare', 'Hospitality', 'Information Technology',
  'Media', 'Mining', 'Nuclear', 'Retail', 'Telecommunications', 'Transportation', 'Utilities', 'Water',
];

function cpe2(vendor, product, version) {
  return `cpe:2.3:a:${vendor}:${product}:${version || '*'}:*:*:*:*:*:*:*`;
}

async function seedSoftware() {
  const driver = getDriver();
  const session = driver.session();
  try {
    // Software nodes
    const rows = PRODUCTS.map(([vendor, product]) => ({
      cpeName: cpe2(vendor, product, '*'),
      vendor,
      product,
      version: '*',
    }));
    for (let i = 0; i < rows.length; i += 200) {
      const chunk = rows.slice(i, i + 200);
      await session.run(
        `
        UNWIND $rows AS row
        MERGE (s:Software {cpeName: row.cpeName})
        SET s.vendor = row.vendor, s.product = row.product, s.version = row.version
        RETURN count(*) AS c
        `,
        { rows: chunk }
      );
      console.log(`  [software] batch ${i / 200 + 1}: ${chunk.length} nodes`);
    }

    // Sector nodes
    for (let i = 0; i < SECTORS.length; i += 20) {
      const chunk = SECTORS.slice(i, i + 20);
      await session.run(
        `
        UNWIND $sectors AS s
        MERGE (n:Sector {sectorName: s})
        RETURN count(*) AS c
        `,
        { sectors: chunk }
      );
    }
    console.log(`  [sectors] ${SECTORS.length} nodes`);
  } finally {
    await session.close();
  }

  // Link ThreatActor → Sector (TARGETS)
  await linkTargets();

  const s = getDriver().session();
  try {
    const sw = await s.run('MATCH (n:Software) RETURN count(n) AS c');
    const se = await s.run('MATCH (n:Sector) RETURN count(n) AS c');
    const tg = await s.run('MATCH ()-[r:TARGETS]->() RETURN count(r) AS c');
    console.log(`\n  Software nodes: ${sw.records[0].get('c').toNumber()}`);
    console.log(`  Sector nodes: ${se.records[0].get('c').toNumber()}`);
    console.log(`  TARGETS edges: ${tg.records[0].get('c').toNumber()}`);
  } finally {
    await s.close();
  }
}

module.exports = { seedSoftware };

if (require.main === module) {
  seedSoftware()
    .then(() => process.exit(0))
    .catch((e) => {
      console.error('seedSoftware failed:', e);
      process.exit(1);
    });
}