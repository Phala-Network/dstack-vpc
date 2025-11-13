import fs from 'node:fs';
import url from 'node:url';
import path from 'node:path';
import { createClient, encryptEnvVars, watchCvmState } from "@phala/cloud";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function readDockerCompose(filename) {
  const filepath = path.join(__dirname, filename);
  if (fs.existsSync(filepath)) {
    return fs.readFileSync(filepath, 'utf-8');
  }
  throw new Error(`File not exists: ${filepath}`);
}


async function deployCvm(client, { name, instanceType, node_id, app_id, nonce, dockerCompose, envs }) {
  console.log(`[${name}] Begin deploy`)

  const env_keys = envs.map(i => i.key)

  //
  // #1: provisioning CVM with compose file & instance type.
  //
  // That's the minimum requirement, and all resources will be automatically allocated.
  // In this example, we skip the contract-owned dstack app and use the default KMS instead,
  // which will return app_id and app_env_encrypt_pubkey if provisioning succeeds.
  //
  const provision = await client.provisionCvm({
    name: name,
    instance_type: instanceType,
    compose_file: {
      docker_compose_file: dockerCompose,
      allowed_envs: env_keys,
    },
    env_keys: env_keys,
    image: 'dstack-dev-0.5.4.1',
    app_id,
    node_id,
    nonce,
  });
  if (!provision.app_id || !provision.app_env_encrypt_pubkey) {
    throw new Error(`[${name} Unxpected provisioning result: app_id or app_env_encrypt_pubkey not found.`);
  }
  console.log(`[${name}] APP ID to use: ${provision.app_id}`);

  //
  // #2: Encrypt environment variables locally.
  //
  const encrypted = await encryptEnvVars(envs, provision.app_env_encrypt_pubkey);

  //
  // #3: Commit the CVM provisioning.
  //
  const result = await client.commitCvmProvision({
    app_id: provision.app_id,
    compose_hash: provision.compose_hash,
    encrypted_env: encrypted,
    env_keys: env_keys,
  });
  if (!result.vm_uuid || result.vm_uuid === null) {
    throw new Error(`[${name}] VM Create failed: vm_uuid is missing`);
  }
  console.log(`[${name}] CVM Created: ${result.vm_uuid}`);

  //
  // #4: (Optional) - watch the boot progress until it reaches the target state.
  //
  let last_progress = undefined;
  await watchCvmState(
    client,
    {
      id: result.vm_uuid,
      target: "running",
    },
    {
      onEvent: (state) => {
        if (state.type === "state" && state.data.boot_progress !== last_progress) {
          last_progress = state.data.boot_progress;
          console.log(`[${name}] [${state.data.uptime}] ${last_progress}`);
        }
        if (state.type === "complete") {
          console.log(`[${name}] CVM booted successfully.`);
        }
      },
    },
  );
  return { ...result, app_id: provision.app_id, app_env_encrypt_pubkey: provision.app_env_encrypt_pubkey }
}

/**
 * 
 */
async function main() {
  const client = createClient();

  const { app_ids } = await client.nextAppIds({ counts: 4 });
  console.log(app_ids);

  //
  // Step 1: Deploy VPC Server
  //
  const { app_id: vpcServerAppId } = await deployCvm(client, {
    name: 'vpc-server',
    instanceType: 'tdx.small',
    app_id: app_ids[0].app_id,
    nonce: app_ids[0].nonce,
    node_id: 18,
    dockerCompose: readDockerCompose('vpc-server.yaml'),
    envs: [
      { key: 'VPC_ALLOWED_APPS', value: 'any' },
    ]
  })

  //
  // Step 2: Deploy MongoDB Cluster
  //
  const { app_id: mongodb0 } = await deployCvm(client, {
    name: 'mongodb-0',
    instanceType: 'tdx.small',
    app_id: app_ids[1].app_id,
    nonce: app_ids[1].nonce,
    node_id: 18,
    dockerCompose: readDockerCompose('mongodb.yaml'),
    envs: [
      { key: 'NODE_IND', value: '0'},
      { key: 'VPC_SERVER_APP_ID', value: vpcServerAppId },
    ]
  })
  const { app_id: mongodb1 } = await deployCvm(client, {
    name: 'mongodb-1',
    instanceType: 'tdx.small',
    app_id: app_ids[2].app_id,
    nonce: app_ids[2].nonce,
    node_id: 18,
    dockerCompose: readDockerCompose('mongodb.yaml'),
    envs: [
      { key: 'NODE_IND', value: '1'},
      { key: 'VPC_SERVER_APP_ID', value: vpcServerAppId },
    ]
  })
  const { app_id: mongodb2 } = await deployCvm(client, {
    name: 'mongodb-2',
    instanceType: 'tdx.small',
    app_id: app_ids[3].app_id,
    nonce: app_ids[3].nonce,
    node_id: 18,
    dockerCompose: readDockerCompose('mongodb.yaml'),
    envs: [
      { key: 'NODE_IND', value: '2'},
      { key: 'VPC_SERVER_APP_ID', value: vpcServerAppId },
    ]
  })

  // Step 3: 
}

main()
  .then(() => {})
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });