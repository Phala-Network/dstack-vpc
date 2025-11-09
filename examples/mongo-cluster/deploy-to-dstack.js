#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { log, ensureDir, readJsonFile, writeJsonFile, renderCompose } = require('./utils');

// Load Dstack configuration from .env file
function loadDstackEnv() {
  const envFile = path.join(__dirname, '.dstack', 'dstack.env');
  if (!fs.existsSync(envFile)) {
    log.error('Dstack environment file not found: .dstack/dstack.env');
    log.error('');
    log.error('Please create configuration files from examples:');
    log.error('  cp .dstack/dstack.env.example .dstack/dstack.env');
    log.error('  cp .dstack/config.json.example .dstack/config.json');
    log.error('');
    log.error('Then edit .dstack/dstack.env with your API URL and credentials.');
    process.exit(1);
  }

  const envContent = fs.readFileSync(envFile, 'utf8');
  const env = {};

  envContent.split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...valueParts] = trimmed.split('=');
      if (key && valueParts.length > 0) {
        env[key.trim()] = valueParts.join('=').trim();
      }
    }
  });

  if (!env.DSTACK_API_URL) {
    log.error('DSTACK_API_URL must be set in .dstack/dstack.env');
    process.exit(1);
  }

  // DSTACK_AUTH is optional - if not set, no authentication will be used
  if (!env.DSTACK_AUTH) {
    env.DSTACK_AUTH = '';
  }

  return env;
}

class DstackDeployer {
  constructor() {
    this.scriptDir = __dirname;
    this.dstackDir = path.join(this.scriptDir, '.dstack');
    this.configFile = path.join(this.dstackDir, 'config.json');
    this.deploymentsDir = path.join(this.dstackDir, 'deployments');
    this.config = null;

    // Load Dstack API configuration
    ensureDir(this.dstackDir);
    const dstackEnv = loadDstackEnv();
    this.apiUrl = dstackEnv.DSTACK_API_URL;
    this.apiAuth = dstackEnv.DSTACK_AUTH;

    ensureDir(this.deploymentsDir);
  }

  async dstackApiCall(method, data = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(`/prpc/${method}?json`, this.apiUrl);
      const postData = JSON.stringify(data);

      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      };

      // Only add Authorization header if apiAuth is set
      if (this.apiAuth) {
        headers['Authorization'] = this.apiAuth;
      }

      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: headers,
        rejectUnauthorized: false
      };

      log.debug(`API Call: ${method}`);
      log.debug(`Data: ${postData}`);

      const req = https.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk) => {
          responseData += chunk;
        });

        res.on('end', () => {
          try {
            log.debug(`Raw response (${res.statusCode}): ${responseData.substring(0, 500)}${responseData.length > 500 ? '...' : ''}`);

            // Check HTTP status code first
            if (res.statusCode < 200 || res.statusCode >= 300) {
              let errorMessage = `HTTP ${res.statusCode}`;
              if (responseData) {
                try {
                  const parsed = JSON.parse(responseData);
                  if (parsed.error) {
                    errorMessage += `: ${parsed.error}`;
                  } else {
                    // If no error field, show truncated response body
                    const truncatedBody = responseData.length > 200 ? responseData.substring(0, 200) + '...' : responseData;
                    errorMessage += `: ${truncatedBody}`;
                  }
                } catch (parseError) {
                  // If response is not JSON, show truncated raw response
                  const truncatedBody = responseData.length > 200 ? responseData.substring(0, 200) + '...' : responseData;
                  errorMessage += `: ${truncatedBody}`;
                }
              }
              reject(new Error(errorMessage));
              return;
            }

            const parsed = JSON.parse(responseData);
            log.debug(`Response: ${JSON.stringify(parsed, null, 2)}`);

            // Check for API-level error in successful HTTP responses
            if (parsed && parsed.error) {
              reject(new Error(`API Error: ${parsed.error}`));
              return;
            }

            resolve(parsed);
          } catch (error) {
            reject(new Error(`Failed to parse response: ${error.message}\nResponse: ${responseData.substring(0, 500)}${responseData.length > 500 ? '...' : ''}`));
          }
        });
      });

      req.on('error', (error) => {
        reject(new Error(`API request failed: ${error.message}`));
      });

      req.setTimeout(30000, () => {
        req.destroy();
        reject(new Error('API request timeout'));
      });

      req.write(postData);
      req.end();
    });
  }

  getDeploymentState(name) {
    const stateFile = path.join(this.deploymentsDir, name, 'deployment-info.json');
    return readJsonFile(stateFile);
  }

  saveDeploymentState(name, state) {
    ensureDir(path.join(this.deploymentsDir, name));
    const stateFile = path.join(this.deploymentsDir, name, 'deployment-info.json');
    writeJsonFile(stateFile, state);
    log.debug(`Saved state for ${name}`);
  }

  loadConfig() {
    this.config = readJsonFile(this.configFile);
    if (!this.config) {
      log.error(`Configuration file not found: ${this.configFile}`);
      log.error('');
      log.error('Please create configuration files from examples:');
      log.error('  cp .dstack/dstack.env.example .dstack/dstack.env');
      log.error('  cp .dstack/config.json.example .dstack/config.json');
      log.error('');
      log.error('Then edit both files with your deployment configuration.');
      process.exit(1);
    }
    log.info(`Loaded configuration from: ${this.configFile}`);
  }

  async checkAuth() {
    log.info('Checking Dstack API connection...');
    try {
      const response = await this.dstackApiCall('Version', {});
      log.success(`Connected to Dstack VMM version: ${response.version || 'unknown'}`);
    } catch (error) {
      log.error(`Failed to connect to Dstack API: ${error.message}`);
      throw error;
    }
  }

  async listVMs(keyword = '', brief = true, vmIds = null) {
    const request = {
      keyword: keyword,
      brief: brief,
      page: 1,
      page_size: 100
    };

    // If vmIds provided, filter by specific VM IDs
    if (vmIds && vmIds.length > 0) {
      request.ids = vmIds;
    }

    return await this.dstackApiCall('Status', request);
  }

  async getVMInfo(vmId) {
    const response = await this.dstackApiCall('GetInfo', { id: vmId });
    if (response.found && response.info) {
      return response.info;
    }
    return null;
  }

  async listContainers(vmId) {
    // Use guest API to get container status
    return new Promise((resolve, reject) => {
      const url = new URL(`/guest/ListContainers?id=${vmId}`, this.apiUrl);

      const headers = {};
      // Only add Authorization header if apiAuth is set
      if (this.apiAuth) {
        headers['Authorization'] = this.apiAuth;
      }

      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'GET',
        headers: headers,
        rejectUnauthorized: false
      };

      const req = https.request(options, (res) => {
        let responseData = '';
        res.on('data', (chunk) => { responseData += chunk; });
        res.on('end', () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              log.debug(`ListContainers failed for ${vmId}: HTTP ${res.statusCode}`);
              resolve({ containers: [] });
              return;
            }

            const parsed = JSON.parse(responseData);
            resolve(parsed);
          } catch (error) {
            log.debug(`Failed to parse ListContainers response: ${error.message}`);
            resolve({ containers: [] });
          }
        });
      });

      req.on('error', (error) => {
        log.debug(`ListContainers request failed: ${error.message}`);
        resolve({ containers: [] });
      });

      req.setTimeout(10000, () => {
        req.destroy();
        resolve({ containers: [] });
      });

      req.end();
    });
  }

  parseMemory(memoryStr) {
    // Parse memory string like "2G", "4096M", "8G" to MB
    if (typeof memoryStr === 'number') {
      return memoryStr * 1024; // Assume GB if number
    }

    const str = memoryStr.toString().toUpperCase();
    const match = str.match(/^(\d+(?:\.\d+)?)\s*([GMK]?)$/);

    if (!match) {
      throw new Error(`Invalid memory format: ${memoryStr}. Use format like "2G", "4096M", or "8G"`);
    }

    const value = parseFloat(match[1]);
    const unit = match[2] || 'G'; // Default to GB

    switch (unit) {
      case 'G':
        return Math.floor(value * 1024); // GB to MB
      case 'M':
        return Math.floor(value); // Already in MB
      case 'K':
        return Math.floor(value / 1024); // KB to MB
      default:
        throw new Error(`Unknown memory unit: ${unit}`);
    }
  }

  parseStorage(storageStr) {
    // Parse storage string like "20G", "100G" to GB number
    if (typeof storageStr === 'number') {
      return storageStr;
    }

    const str = storageStr.toString().toUpperCase();
    const match = str.match(/^(\d+(?:\.\d+)?)\s*([GT]?)$/);

    if (!match) {
      throw new Error(`Invalid storage format: ${storageStr}. Use format like "20G", "100G"`);
    }

    const value = parseFloat(match[1]);
    const unit = match[2] || 'G'; // Default to GB

    switch (unit) {
      case 'G':
        return Math.floor(value);
      case 'T':
        return Math.floor(value * 1024); // TB to GB
      default:
        throw new Error(`Unknown storage unit: ${unit}`);
    }
  }

  createDstackManifest(name, dockerComposeYaml) {
    // Dstack expects a JSON manifest, not raw YAML
    const manifest = {
      manifest_version: 2,
      name: name,
      runner: 'docker-compose',
      docker_compose_file: dockerComposeYaml,
      kms_enabled: true,
      gateway_enabled: true,
      public_logs: true,
      public_sysinfo: true,
      public_tcbinfo: true,
      local_key_provider_enabled: false,
      key_provider_id: '',
      allowed_envs: [],
      no_instance_id: false,
      secure_time: false
    };

    return JSON.stringify(manifest);
  }

  async createVM(config) {
    const composeYaml = fs.readFileSync(config.composeFile, 'utf8');
    const composeManifest = this.createDstackManifest(config.name, composeYaml);

    const vmConfig = {
      name: config.name,
      image: config.image,
      compose_file: composeManifest,
      vcpu: config.cpu,
      memory: this.parseMemory(config.memory),
      disk_size: this.parseStorage(config.storage),
      ports: [],
      encrypted_env: config.encryptedEnv || '',
      user_config: config.userConfig || '',
      hugepages: false,
      pin_numa: false,
      gpus: { gpus: [], attach_mode: 'listed' },
      kms_urls: config.kmsUrls || [],
      gateway_urls: config.gatewayUrls || [],
      stopped: false
    };

    if (config.appId) {
      vmConfig.app_id = config.appId;
    }

    const response = await this.dstackApiCall('CreateVm', vmConfig);
    log.debug(`CreateVm response: ${JSON.stringify(response)}`);

    // The response should have an 'id' field according to the proto definition
    if (!response || !response.id) {
      throw new Error(`CreateVm returned invalid response: ${JSON.stringify(response)}`);
    }

    return response.id;
  }

  async startVM(vmId) {
    await this.dstackApiCall('StartVm', { id: vmId });
  }

  async stopVM(vmId) {
    await this.dstackApiCall('StopVm', { id: vmId });
  }

  async removeVM(vmId) {
    await this.dstackApiCall('RemoveVm', { id: vmId });
  }

  async waitForVMStatus(vmId, targetStatus, maxWaitSeconds = 60) {
    const startTime = Date.now();
    const pollInterval = 2000; // 2 seconds

    while (true) {
      const elapsed = (Date.now() - startTime) / 1000;

      if (elapsed > maxWaitSeconds) {
        throw new Error(`Timeout waiting for VM ${vmId} to reach status ${targetStatus}`);
      }

      try {
        const vmInfo = await this.getVMInfo(vmId);

        if (!vmInfo) {
          log.debug(`VM ${vmId} not found, may already be removed`);
          return;
        }

        log.debug(`VM ${vmId} status: ${vmInfo.status} (waiting for ${targetStatus})`);

        if (vmInfo.status === targetStatus) {
          return vmInfo;
        }

        // If target is 'stopped' and VM is already in a terminal state, that's ok
        if (targetStatus === 'stopped' && (vmInfo.status === 'exited' || vmInfo.status === 'stopped')) {
          return vmInfo;
        }

      } catch (error) {
        log.debug(`Error checking VM status: ${error.message}`);
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
  }

  async deployWithConfig(config) {
    // Check if already deployed (idempotent)
    const existingState = this.getDeploymentState(config.name);
    if (existingState && existingState.vm_id) {
      log.info(`${config.name} already deployed with VM ID: ${existingState.vm_id}`);
      return { vmId: existingState.vm_id, appId: existingState.app_id };
    }

    const deploymentDir = path.join(this.deploymentsDir, config.name);
    ensureDir(deploymentDir);

    if (!this.config.os_image) {
      throw new Error('OS image is not configured');
    }

    log.debug('Deployment parameters:');
    log.debug(`  Name: ${config.name}, vCPU: ${config.cpu}, Memory: ${config.memory}GB`);
    log.debug(`  Disk: ${config.storage}GB, Image: ${this.config.os_image}`);
    if (config.appId) {
      log.debug(`  App ID: ${config.appId}`);
    }

    if (!config.composeFile.startsWith('/')) {
      config.composeFile = path.join(this.scriptDir, config.composeFile);
    }

    const staticEnvs = config.staticEnvs || {};
    const renderedComposeFile = renderCompose(config.composeFile, deploymentDir, staticEnvs);

    // Save "deploying" state BEFORE calling API
    this.saveDeploymentState(config.name, {
      name: config.name,
      status: 'deploying',
      vm_id: null,
      started_at: new Date().toISOString()
    });

    try {
      const vmId = await this.createVM({
        name: config.name,
        image: this.config.os_image,
        composeFile: renderedComposeFile,
        cpu: config.cpu,
        memory: config.memory,
        storage: config.storage,
        kmsUrls: config.kmsUrls || [],
        gatewayUrls: config.gatewayUrls || [],
        appId: config.appId
      });

      if (!vmId) {
        throw new Error('Failed to get VM ID from CreateVm response');
      }

      log.success(`Created VM ${config.name} with ID: ${vmId}`);

      // Start the VM
      await this.startVM(vmId);
      log.success(`Started VM ${config.name}`);

      // Get VM info
      const vmInfo = await this.getVMInfo(vmId);
      const appUrl = vmInfo?.app_url || 'N/A';
      const appId = vmInfo?.app_id || config.appId || null;

      log.info(`Dashboard: ${appUrl}`);
      if (appId) {
        log.debug(`App ID: ${appId}`);
      }

      this.saveDeploymentState(config.name, {
        name: config.name,
        status: 'deployed',
        vm_id: vmId,
        app_id: appId,
        app_url: appUrl,
        deployed_at: new Date().toISOString()
      });

      return { vmId, appId };
    } catch (error) {
      // Save failed state so we can recover
      this.saveDeploymentState(config.name, {
        name: config.name,
        status: 'failed',
        vm_id: null,
        error: error.message,
        failed_at: new Date().toISOString()
      });
      log.error(`Deployment failed: ${error.message}`);
      throw error;
    }
  }

  async deployNode(nodeConfig, vpcServerAppId) {
    log.info(`Deploying node: ${nodeConfig.name}...`);

    // Extract index from name (e.g., mongodb-0 -> 0, test-app-0 -> 0)
    const match = nodeConfig.name.match(/-(\d+)$/);
    const nodeInd = match ? match[1] : '0';

    return await this.deployWithConfig({
      ...nodeConfig,
      staticEnvs: {
        VPC_SERVER_APP_ID: vpcServerAppId,
        NODE_IND: nodeInd,
      }
    });
  }

  async deployCluster() {
    await this.checkAuth();
    this.loadConfig();

    log.info('Starting MongoDB cluster deployment...');
    log.info('Deploying VPC server and nodes with pre-configured app IDs\n');

    // Validate configuration
    if (!this.config.vpc_server || !this.config.vpc_server.appId) {
      log.error('vpc_server.appId must be configured in config.json');
      process.exit(1);
    }

    if (!this.config.nodes || this.config.nodes.length === 0) {
      log.error('At least one node must be configured in config.json');
      process.exit(1);
    }

    for (const node of this.config.nodes) {
      if (!node.appId) {
        log.error(`Node ${node.name} must have appId configured`);
        process.exit(1);
      }
    }

    const vpcServerAppId = this.config.vpc_server.appId;
    const nodeAppIds = this.config.nodes.map(n => n.appId);
    // Deduplicate app IDs and join with commas
    const uniqueAppIds = [...new Set(nodeAppIds)];
    const allowedApps = uniqueAppIds.join(',');

    log.info(`VPC Server App ID: ${vpcServerAppId}`);
    log.info(`Node App IDs: ${nodeAppIds.join(', ')}`);
    if (uniqueAppIds.length < nodeAppIds.length) {
      log.info(`Deduplicated App IDs: ${uniqueAppIds.join(', ')}`);
    }
    log.info(`VPC_ALLOWED_APPS: ${allowedApps}\n`);

    // Deploy VPC server with correct VPC_ALLOWED_APPS
    log.info('Deploying VPC server...');
    const vpcResult = await this.deployWithConfig({
      ...this.config.vpc_server,
      staticEnvs: {
        VPC_ALLOWED_APPS: allowedApps,
      }
    });
    log.success(`VPC server deployed: ${vpcResult.vmId}\n`);

    // Deploy all MongoDB nodes
    log.info('Deploying MongoDB nodes...');
    const nodeResults = [];
    for (const nodeConfig of this.config.nodes) {
      const result = await this.deployNode(nodeConfig, vpcServerAppId);
      nodeResults.push(result);
      log.success(`Node ${nodeConfig.name} deployed: ${result.vmId}`);
    }

    console.log('\n' + '═'.repeat(80));
    log.success('🎉 MongoDB cluster deployment finished!');
    console.log('═'.repeat(80));
    console.log(`\nVPC Server VM ID: ${vpcResult.vmId}`);
    console.log(`MongoDB Nodes: ${nodeResults.length} deployed`);
  }

  async showStatus(watch = false, interval = 5000) {
    await this.checkAuth();

    const showStatusOnce = async () => {
      if (!watch) {
        log.info('Fetching VM status from Dstack...');
      }

      // Get list of our deployed VM IDs
      const ourVmIds = [];
      if (fs.existsSync(this.deploymentsDir)) {
        const deployments = fs.readdirSync(this.deploymentsDir).filter(name => !name.startsWith('.'));
        for (const deploymentName of deployments) {
          const state = this.getDeploymentState(deploymentName);
          if (state && state.vm_id) {
            ourVmIds.push(state.vm_id);
          }
        }
      }

      // Only query our VMs if we have any deployed
      if (ourVmIds.length === 0) {
        if (!watch) {
          console.log('\n📊 Dstack VM Status\n');
          console.log('═'.repeat(80));
          console.log('No deployed VMs found. Use "cluster" command to create VMs.');
        }
        return;
      }

      const statusResponse = await this.listVMs('', false, ourVmIds);

      if (watch) {
        console.clear();
        const now = new Date().toLocaleTimeString();
        console.log(`🔄 Auto-refreshing every ${interval / 1000}s | Last update: ${now}`);
        console.log('   Press Ctrl+C to stop\n');
      }

      console.log('\n📊 Dstack VM Status\n');
      console.log('═'.repeat(80));

      if (!statusResponse.vms || statusResponse.vms.length === 0) {
        console.log('No VMs found');
        return;
      }

      for (const vm of statusResponse.vms) {
        const statusIcon = vm.status === 'running' ? '✅' :
          vm.status === 'stopped' ? '🔴' : '⚠️';

        console.log(`${statusIcon} ${vm.name.padEnd(25)} │ ${vm.status.padEnd(10)} │ ${vm.uptime || 'N/A'}`);
        console.log(`   └─ ID: ${vm.id}`);
        if (vm.app_url) {
          console.log(`   └─ 📊 Dashboard: ${vm.app_url}`);
        }

        // Fetch container status if VM is running
        if (vm.status === 'running') {
          const containerInfo = await this.listContainers(vm.id);
          if (containerInfo.containers && containerInfo.containers.length > 0) {
            console.log(`   └─ 📦 Containers: ${containerInfo.containers.length}`);
            for (const container of containerInfo.containers) {
              // Use same icon logic as deploy.js for consistency
              let statusIcon = '🔴'; // Default: red circle for other states

              if (container.status.includes('Up')) {
                if (container.status.includes('(healthy)')) {
                  statusIcon = '💚'; // Green heart for healthy running
                } else {
                  statusIcon = '🟡'; // Yellow circle for running but not healthy
                }
              } else if (container.status.includes('Exited (0)')) {
                statusIcon = '✅'; // Green check for clean exit
              }

              const containerName = container.names[0]?.replace(/^\//, '') || container.id.substring(0, 12);
              console.log(`      ${statusIcon} ${containerName.padEnd(30)} │ ${container.state.padEnd(10)} │ ${container.status}`);
            }
          }
        }

        console.log('');
      }

      console.log('═'.repeat(80));
      console.log(`📈 Total: ${statusResponse.vms.length} VMs`);
    };

    await showStatusOnce();
    if (watch) {
      process.on('SIGINT', () => {
        process.exit(0);
      });
      while (true) {
        await new Promise(resolve => setTimeout(resolve, interval));
        await showStatusOnce();
      }
    }
  }

  async teardown() {
    await this.checkAuth();

    console.log('\n⚠️  WARNING: This will delete all deployed VMs for this cluster');
    console.log('═'.repeat(80));

    log.info('Scanning deployment configurations...');

    const deploymentConfigs = [];
    if (fs.existsSync(this.deploymentsDir)) {
      const deployments = fs.readdirSync(this.deploymentsDir).filter(name =>
        !name.startsWith('.')
      );

      for (const deploymentName of deployments) {
        const deploymentDir = path.join(this.deploymentsDir, deploymentName);
        const state = this.getDeploymentState(deploymentName);

        if (state && state.vm_id) {
          deploymentConfigs.push({
            name: deploymentName,
            vm_id: state.vm_id,
            deploymentDir
          });
        }
      }
    }

    if (deploymentConfigs.length === 0) {
      log.info('No deployed VMs found. Everything is already clean!');
      return;
    }

    console.log(`\nFound ${deploymentConfigs.length} deployments to remove:`);
    deploymentConfigs.forEach(config => {
      console.log(`  • ${config.name} (VM ID: ${config.vm_id.substring(0, 12)}...)`);
    });

    console.log('\n🗑️  Starting teardown...\n');

    let successCount = 0;
    let failCount = 0;

    for (const config of deploymentConfigs) {
      try {
        log.info(`Stopping ${config.name}...`);

        // Stop the VM
        try {
          await this.stopVM(config.vm_id);
          log.info(`  Sent stop command to ${config.name}`);
        } catch (error) {
          log.debug(`Stop VM failed (may already be stopped): ${error.message}`);
        }

        // Wait for VM to be stopped
        try {
          log.info(`  Waiting for ${config.name} to stop...`);
          await this.waitForVMStatus(config.vm_id, 'stopped', 60);
          log.info(`  ${config.name} stopped successfully`);
        } catch (error) {
          log.warn(`  Timeout waiting for ${config.name} to stop: ${error.message}`);
          log.warn(`  Proceeding with removal anyway...`);
        }

        // Remove the VM
        log.info(`  Removing ${config.name}...`);
        await this.removeVM(config.vm_id);
        log.success(`✓ Deleted ${config.name}`);

        successCount++;
        fs.rmSync(config.deploymentDir, { recursive: true, force: true });

      } catch (error) {
        log.error(`✗ Failed to delete ${config.name}: ${error.message}`);
        failCount++;
      }
    }

    if (fs.existsSync(this.deploymentsDir)) {
      try {
        const remainingDirs = fs.readdirSync(this.deploymentsDir);
        if (remainingDirs.length === 0) {
          fs.rmSync(this.deploymentsDir, { recursive: true, force: true });
          log.debug('Removed deployments directory');
        }
      } catch (error) {
        log.warn(`Failed to remove deployments directory: ${error.message}`);
      }
    }

    console.log('\n' + '═'.repeat(80));
    console.log(`📊 Teardown Summary:`);
    console.log(`   ✅ Successfully deleted: ${successCount}`);
    if (failCount > 0) {
      console.log(`   ❌ Failed to delete: ${failCount}`);
    }
    console.log(`   🗑️  Removed deployment directories`);

    if (successCount === deploymentConfigs.length) {
      console.log('\n✨ All VMs successfully removed!');
    } else if (failCount > 0) {
      console.log('\n⚠️  Some VMs could not be removed. Check logs for details.');
    }
  }
}

async function main() {
  const deployer = new DstackDeployer();
  const command = process.argv[2];
  const args = process.argv.slice(3);

  switch (command) {
    case 'cluster':
      await deployer.deployCluster();
      break;
    case 'status':
      const watchMode = args.includes('--watch') || args.includes('-w');
      let interval = 5000;

      const intervalIndex = args.findIndex(arg => arg === '--interval' || arg === '-i');
      if (intervalIndex !== -1 && args[intervalIndex + 1]) {
        const customInterval = parseInt(args[intervalIndex + 1]) * 1000;
        if (!isNaN(customInterval) && customInterval >= 1000) {
          interval = customInterval;
        }
      }

      await deployer.showStatus(watchMode, interval);
      break;
    case 'down':
      await deployer.teardown();
      break;
    default:
      console.log('Usage: node deployDstack.js {cluster|status|down} [options]');
      console.log('\nCommands:');
      console.log('  cluster       Deploy MongoDB cluster (VPC server + nodes + test apps)');
      console.log('  status [options]     Show status of deployed VMs');
      console.log('    --watch, -w        Auto-refresh status in a loop');
      console.log('    --interval, -i <s> Set refresh interval in seconds (default: 5)');
      console.log('  down          Remove all deployed VMs and clean up directories');
      console.log('\nExamples:');
      console.log('  node deployDstack.js cluster            # Deploy the cluster');
      console.log('  node deployDstack.js status --watch     # Monitor VM status');
      console.log('  node deployDstack.js down               # Teardown cluster');
      console.log('\nConfiguration:');
      console.log('  .dstack/dstack.env                  API URL and authentication (optional)');
      console.log('  .dstack/config.json      Cluster configuration with app IDs');
      console.log('\nEnvironment variables:');
      console.log('  DEBUG=1              Enable debug output');
      process.exit(1);
  }
}

main().catch(error => {
  log.error(`Unexpected error: ${error.message}`);
  if (process.env.DEBUG) {
    console.error(error.stack);
  }
  process.exit(1);
});
