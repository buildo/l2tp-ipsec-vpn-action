const core = require('@actions/core');
const github = require('@actions/github');
const { exec } = require('@actions/exec');
const fs = require('fs').promises;

async function createFileWithSudo(path, content) {
  const tempFile = `/tmp/${path.split('/').pop()}`;
  await fs.writeFile(tempFile, content);

  const dirname = path.substring(0, path.lastIndexOf('/'));
  if (dirname) {
    await exec('sudo', ['mkdir', '-p', dirname]);
  }

  await exec('sudo', ['mv', tempFile, path]);
  await exec('sudo', ['chmod', '600', path]);
}

async function createSymlinkWithSudo(target, source) {
  try {
    await exec('sudo', ['ln', '-fs', source, target]);
  } catch (error) {
    core.warning(`Failed to create symlink from ${source} to ${target}: ${error.message}`);
  }
}

async function createConfigFiles(server, username, password, psk) {
  // See https://wiki.strongswan.org/projects/strongswan/wiki/connsection
  await createFileWithSudo('/etc/ipsec.conf', `
config setup

conn L2TP-PSK
    # Use IKEv1 for key exchange (IKEv2 is typically used in IPsec only setups, without L2TP)
    keyexchange=ikev1

    # Use these ciphers (see full list here https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites):
    # - aes128-sha256-modp2048: the most widely supported
    # - aes256-sha256-modp2048: a stronger alternative, not as widely supported
    # - aes256-sha512-modp4096: the strongest, but unlikely to be supported
    ike=aes128-sha256-modp2048,aes256-sha256-modp2048,aes256-sha512-modp4096

    # Start the connection when the IPsec service starts
    auto=start

    # Authenticate using a pre-shared key
    authby=psk

    # Use IPsec only as a transport mode and not a tunnel on its own
    type=transport

    # IP address of the VPN server
    right=${server}
`);

  await createFileWithSudo('/etc/ipsec.secrets', `${server} : PSK "${psk}"`);

  // See https://linux.die.net/man/8/pppd
  await createFileWithSudo('/etc/ppp/options.l2tpd.client', `
# L2TP cannot use EAP authentication so disable it
refuse-eap
# L2TP requires MS-CHAPv2 for authentication
require-mschap-v2
# Disable compression, since most of the traffic is already compressed
# and compression can cause issues with some protocols
noccp
# Disable ppp authentication, since we are using L2TP/IPsec authentication
noauth

logfile /var/log/xl2tpd.log
mtu 1410
mru 1410
defaultroute
usepeerdns
debug
name ${username}
password ${password}
`);

  // See https://linux.die.net/man/5/xl2tpd.conf
  await createFileWithSudo('/etc/xl2tpd/xl2tpd.conf', `
[lac vpn]
lns = ${server}
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
autodial = yes
`);

  await createFileWithSudo('/etc/resolv-vpn.conf', `
nameserver 1.1.1.1
nameserver 8.8.8.8
`);
  await createSymlinkWithSudo('/etc/resolv.conf', '/etc/resolv-vpn.conf');

  core.info('All configuration files created successfully.');
}

async function waitForVpnConnection(timeout = 30_000, interval = 1000) {
  const start = Date.now();

  while (Date.now() - start < timeout) {
    let ipsecOk = false;
    let pppOk = false;

    try {
      // Check if IPsec connection is up
      let ipsecOutput = '';
      await exec('sudo ipsec status', [], {

        listeners: {
          stdout: (data) => { ipsecOutput += data.toString(); }
        }
      });

      ipsecOk = /L2TP-PSK.*ESTABLISHED/.test(ipsecOutput);

      // Check if PPP interface exists
      let ifaceOutput = '';
      await exec('ip a s ppp0', [], {

        listeners: {
          stdout: (data) => { ifaceOutput += data.toString(); }
        }
      });

      pppOk = ifaceOutput.split('\n').some(line => line.trim().startsWith('inet '));

      if (ipsecOk && pppOk) {
        return true;
      }

    } catch (err) {
      // Suppress errors temporarily
    }

    await new Promise((resolve) => setTimeout(resolve, interval));
  }

  throw new Error('VPN connection timeout: IPsec or PPP interface not ready. Content of /var/log/xl2tpd.log:\n' +
    await fs.readFile('/var/log/xl2tpd.log', 'utf8'));
}

async function startVPN(server) {
  core.info('Starting the VPN connection...');

  await exec('sudo ipsec start');
  await exec('sudo xl2tpd -C /tmp/l2tp-control');

  // Wait for the xl2tpd service to start
  core.info('Waiting for the VPN connection to start...');
  await waitForVpnConnection();
  core.info('VPN connection established!');

  core.info('Settings routes...');
  // Get gateway for the VPN server
  let gateway = '';
  await exec(`ip route get ${server}`, [], {
    listeners: {
      stdout: (data) => {
        const match = data.toString().match(/via (\d+\.\d+\.\d+\.\d+)/);
        if (match) gateway = match[1];
      }
    }
  });
  if (!gateway) throw new Error('Could not determine gateway to VPN server');

  await exec(`ip route add ${server} via ${gateway} dev eth0`);
  await exec(`ip route replace default dev ppp0`);
};

async function installTools() {
  await exec('sudo', ['apt-get', 'update']);
  await exec('sudo', ['apt-get', 'install', '-y', 'strongswan', 'xl2tpd']);
};

async function run() {
  try {
    const server = core.getInput('server', { required: true });
    const username = core.getInput('username', { required: true });
    const password = core.getInput('password', { required: true });
    const psk = core.getInput('psk', { required: true });

    core.info(`Installing necessary tools...`);
    await installTools();

    await createConfigFiles(server, username, password, psk);
    await startVPN(server);

    const payload = JSON.stringify(github.context.payload, undefined, 2)
    console.log(`The event payload: ${payload}`);

  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
